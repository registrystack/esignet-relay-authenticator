package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"time"
)

// maxTrackedSenders bounds the cooldown and budget state held in memory.
const maxTrackedSenders = 10_000

var e164 = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)

// messagingVerifier sends one-time codes through Registry Messaging to the
// contact held in BREG for the person who asked. Pending challenges are held
// in process memory, so run one replica (or sticky routing) and expect a
// restart to drop them.
type messagingVerifier struct {
	*challengeStore
	p      *Provider
	config MessagingConfig
	tokens tokenSource
	limits *sendLimiter
}

func newMessagingVerifier(p *Provider, c MessagingConfig) *messagingVerifier {
	v := &messagingVerifier{
		challengeStore: newChallengeStore(time.Duration(c.CodeTTLSeconds) * time.Second),
		p:              p,
		config:         c,
		tokens:         newTokenSource(p, c.TokenResource, c.TokenScopes),
	}
	v.limits = newSendLimiter(func() time.Time { return v.now() }, time.Duration(c.ResendCooldownSeconds)*time.Second, c.MaxSendsPerHour)
	return v
}

func (v *messagingVerifier) channels() []string {
	out := make([]string, 0, len(v.config.Channels))
	for name := range v.config.Channels {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// SendOTP gives the same outward result whether or not a message is sent for an
// unknown, ineligible or contactless person, or when a resend limit applies.
// Only an unreachable BREG or Messaging, or a malformed request, is an error.
func (v *messagingVerifier) SendOTP(ctx context.Context, r OTPRequest) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !validBinding(r.Binding) || !validText(r.Identifier) || !validText(r.IdentifierType) {
		return ErrInvalidRequest
	}
	channel := ""
	for _, name := range r.Channels {
		if _, ok := v.config.Channels[name]; ok {
			channel = name
			break
		}
	}
	if channel == "" {
		return ErrInvalidRequest
	}
	key := challengeKey{r.Identifier, r.IdentifierType, r.Binding}
	admitted, err := v.limits.admit(key)
	if err != nil || !admitted {
		return err
	}
	contact, err := v.contact(ctx, r.Identifier, channel)
	if err != nil {
		v.limits.release(key)
		return err
	}
	if contact == "" {
		return nil
	}
	release, err := v.begin()
	if err != nil {
		v.limits.release(key)
		return err
	}
	defer release()
	code, c, err := v.generate()
	if err != nil {
		v.limits.release(key)
		return err
	}
	// The challenge exists before the call so that a code delivered after an
	// ambiguous transport failure still verifies.
	v.put(key, c)
	if definite, err := v.send(ctx, channel, contact, code, c.expires); err != nil {
		if definite {
			v.discard(key)
		}
		v.limits.release(key)
		return err
	}
	return nil
}

func (v *messagingVerifier) Verify(ctx context.Context, r ChallengeRequest) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return v.check(challengeKey{r.Identifier, r.IdentifierType, r.Binding}, r.Challenge)
}

// contact returns the person's contact for the channel, or "" when the person
// is unknown, not eligible for sign-in, or has no usable contact.
func (v *messagingVerifier) contact(ctx context.Context, identifier, channel string) (string, error) {
	field := v.config.ContactFields[channel]
	fields := append(append([]string(nil), v.p.config.BREG.AccountCheckFields...), field)
	values, err := v.p.lookup(ctx, identifier, fields)
	if err == ErrSubjectDenied {
		return "", nil
	}
	if err != nil {
		return "", ErrUnavailable
	}
	if !v.p.accountOK(values, identifier) {
		return "", nil
	}
	contact, _ := values[field].(string)
	if (channel == "email" && !validMailAddress(contact)) || (channel == "phone" && !e164.MatchString(contact)) {
		return "", nil
	}
	return contact, nil
}

// send submits one message. definite reports that Messaging refused it, so no
// message can reach the recipient. Transport failures and server errors leave
// the outcome unknown. A send is never retried.
func (v *messagingVerifier) send(ctx context.Context, channel, contact, code string, expires time.Time) (definite bool, err error) {
	token, err := v.tokens.accessToken(ctx)
	if err != nil {
		return true, ErrUnavailable
	}
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return true, ErrUnavailable
	}
	ch := v.config.Channels[channel]
	minutes := int((v.ttl + time.Minute - 1) / time.Minute)
	body, _ := json.Marshal(map[string]any{
		"senderProfile": ch.SenderProfile,
		"to":            map[string]string{channel: contact},
		"template":      map[string]string{"id": ch.TemplateID, "version": ch.TemplateVersion},
		"locale":        ch.Locale,
		"data":          map[string]any{"code": code, "minutes": minutes},
		"expiresAt":     expires.UTC().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trimSlash(v.config.BaseURL)+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return true, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", hex.EncodeToString(key[:]))
	status, raw, err := v.p.request(req)
	if err != nil {
		return false, ErrUnavailable
	}
	if status >= 200 && status < 300 {
		return false, nil
	}
	var problem struct {
		Code string `json:"code"`
	}
	if status == http.StatusUnauthorized || (decodeJSON(raw, &problem) == nil && problem.Code == "authentication.refused") {
		v.tokens.invalidate(token)
	}
	return status >= 400 && status < 500, ErrUnavailable
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// sendLimiter spaces resends per person and binding and caps sends per person
// per hour. It counts every admitted request, so a caller cannot tell a known
// person from an unknown one by the limits.
type sendLimiter struct {
	now      func() time.Time
	cooldown time.Duration
	perHour  int
	mu       sync.Mutex
	next     map[challengeKey]time.Time
	sends    map[[2]string][]time.Time
}

func newSendLimiter(now func() time.Time, cooldown time.Duration, perHour int) *sendLimiter {
	return &sendLimiter{now: now, cooldown: cooldown, perHour: perHour, next: map[challengeKey]time.Time{}, sends: map[[2]string][]time.Time{}}
}

// admit reports whether a send may proceed and records it when it may.
func (l *sendLimiter) admit(k challengeKey) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	person := [2]string{k.identifier, k.identifierType}
	if len(l.next)+len(l.sends) >= maxTrackedSenders {
		l.prune(now)
		if len(l.next)+len(l.sends) >= maxTrackedSenders {
			return false, ErrUnavailable
		}
	}
	if until, ok := l.next[k]; ok && now.Before(until) {
		return false, nil
	}
	recent := l.sends[person][:0:0]
	for _, t := range l.sends[person] {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.perHour {
		l.sends[person] = recent
		return false, nil
	}
	l.sends[person] = append(recent, now)
	l.next[k] = now.Add(l.cooldown)
	return true, nil
}

// release frees the resend cooldown after a send that failed. The hourly budget stays spent.
func (l *sendLimiter) release(k challengeKey) {
	l.mu.Lock()
	delete(l.next, k)
	l.mu.Unlock()
}

func (l *sendLimiter) prune(now time.Time) {
	for k, until := range l.next {
		if !now.Before(until) {
			delete(l.next, k)
		}
	}
	for person, times := range l.sends {
		if len(times) == 0 || now.Sub(times[len(times)-1]) >= time.Hour {
			delete(l.sends, person)
		}
	}
}
