package provider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxTrackedPeople = 100_000
	// maxInFlightSends caps the Messaging calls running at once. A send past the
	// cap is dropped and reported to the operator signal.
	maxInFlightSends = 64
	// failureLockThreshold is the failed verifications per person, within one
	// window, after which codes stop being issued and accepted for that person.
	failureLockThreshold = 10
	limiterWindow        = time.Hour
	maxMessagingEmail    = 254
)

var e164 = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)

// validMessagingEmail applies Registry Messaging's recipient rule: one
// local@domain address of visible ASCII with a dotted domain and none of < > , ;.
func validMessagingEmail(s string) bool {
	local, domain, ok := strings.Cut(s, "@")
	if !ok || len(s) > maxMessagingEmail || local == "" || !strings.Contains(domain, ".") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "@") {
		return false
	}
	for _, b := range []byte(s) {
		if b < 0x21 || b > 0x7e || strings.IndexByte("<>,;", b) >= 0 {
			return false
		}
	}
	return true
}

// messagingVerifier sends one-time codes through Registry Messaging to the
// contact held in BREG for the person who asked. Pending challenges and limits
// are held in process memory, so run one replica (or sticky routing) and expect
// a restart to drop them.
type messagingVerifier struct {
	*challengeStore
	p      *Provider
	config MessagingConfig
	tokens tokenSource
	limits *personLimiter
	slots  chan struct{}
	sends  sync.WaitGroup
}

func newMessagingVerifier(p *Provider, c MessagingConfig) *messagingVerifier {
	v := &messagingVerifier{
		challengeStore: newChallengeStore(time.Duration(c.CodeTTLSeconds)*time.Second, c.MaxPendingCodes),
		p:              p,
		config:         c,
		tokens:         newTokenSource(p, c.TokenResource, c.TokenScopes),
		slots:          make(chan struct{}, maxInFlightSends),
	}
	v.limits = newPersonLimiter(func() time.Time { return v.now() }, time.Duration(c.ResendCooldownSeconds)*time.Second, c.MaxSendsPerHour, c.MaxTrackedPeople)
	return v
}

// channels lists the configured channels in preference order.
func (v *messagingVerifier) channels() []string {
	out := make([]string, 0, len(v.config.Channels))
	for name := range v.config.Channels {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (v *messagingVerifier) emit(e OperatorEvent) {
	if v.p.signal != nil {
		v.p.signal(e)
	}
}

// SendOTP gives the same outward result whether or not a message is sent for a
// known, unknown, ineligible or contactless person, and when a limit applies.
// The Messaging call runs after the result is returned, so its outcome cannot
// reveal who exists. Only a malformed request, an unreachable BREG, or a full
// challenge store or limiter (which refuse everyone alike) is an error.
func (v *messagingVerifier) SendOTP(ctx context.Context, r OTPRequest) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !validBinding(r.Binding) || !validText(r.Identifier) || !validText(r.IdentifierType) {
		return ErrInvalidRequest
	}
	var channels []string
	for _, name := range v.channels() {
		for _, requested := range r.Channels {
			if requested == name {
				channels = append(channels, name)
				break
			}
		}
	}
	if len(channels) == 0 {
		return ErrInvalidRequest
	}
	// Capacity is reserved before the lookup, so a full store refuses everyone alike.
	release, err := v.begin()
	if err != nil {
		v.emit(EventStoreFull)
		return err
	}
	defer release()
	person := v.limits.person(r.IdentifierType, r.Identifier)
	adm, status := v.limits.admit(person, r.Binding)
	switch status {
	case limiterFull:
		v.emit(EventLimiterFull)
		return ErrUnavailable
	case limiterHeld:
		return nil
	}
	channel, contact, err := v.contact(ctx, r.Identifier, channels)
	if err != nil {
		v.limits.refund(adm)
		return err
	}
	if contact == "" {
		return nil
	}
	select {
	case v.slots <- struct{}{}:
	default:
		v.limits.refund(adm)
		v.emit(EventSendDropped)
		return nil
	}
	code, c, err := v.generate()
	if err != nil {
		<-v.slots
		v.limits.refund(adm)
		return err
	}
	key := challengeKey{r.Identifier, r.IdentifierType, r.Binding}
	// The challenge exists before the call so that a code delivered after an
	// ambiguous transport failure still verifies.
	previous, replaced := v.swap(key, c)
	v.sends.Add(1)
	go v.deliver(context.WithoutCancel(ctx), adm, key, c, previous, replaced, channel, contact, code)
	return nil
}

// deliver runs one Messaging call on a context of its own and settles the
// challenge and limits by the outcome.
func (v *messagingVerifier) deliver(ctx context.Context, adm admission, key challengeKey, c, previous challenge, replaced bool, channel, contact, code string) {
	defer v.sends.Done()
	defer func() { <-v.slots }()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Duration(v.p.config.HTTP.TimeoutSeconds)*time.Second)
	defer cancel()
	switch v.send(ctx, channel, contact, code, c.expires) {
	case sendAccepted:
	case sendRefused:
		v.undo(key, c, previous, replaced)
		v.limits.refund(adm)
		v.emit(EventSendRefused)
	case sendNotSent:
		v.undo(key, c, previous, replaced)
		v.limits.refund(adm)
		v.emit(EventSendFailed)
	default:
		v.limits.reopen(adm)
		v.emit(EventSendFailed)
	}
}

// wait blocks until every started send has finished.
func (v *messagingVerifier) wait() { v.sends.Wait() }

func (v *messagingVerifier) Verify(ctx context.Context, r ChallengeRequest) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	person := v.limits.person(r.IdentifierType, r.Identifier)
	if v.limits.locked(person) {
		return ErrChallengeFailed
	}
	err := v.check(challengeKey{r.Identifier, r.IdentifierType, r.Binding}, r.Challenge)
	if err != nil {
		v.limits.fail(person)
		return err
	}
	v.limits.reset(person)
	return nil
}

// contact returns the first channel, in preference order, that holds a valid
// contact for the person, or "" when the person is unknown, not eligible for
// sign-in, or has no usable contact. One BREG lookup reads every candidate.
func (v *messagingVerifier) contact(ctx context.Context, identifier string, channels []string) (channel, contact string, err error) {
	fields := append([]string(nil), v.p.config.BREG.AccountCheckFields...)
	for _, name := range channels {
		if field := v.config.ContactFields[name]; !contains(fields, field) {
			fields = append(fields, field)
		}
	}
	values, err := v.p.lookup(ctx, identifier, fields)
	if err == ErrSubjectDenied {
		return "", "", nil
	}
	if err != nil {
		return "", "", ErrUnavailable
	}
	if !v.p.accountOK(values, identifier) {
		return "", "", nil
	}
	for _, name := range channels {
		contact, _ := values[v.config.ContactFields[name]].(string)
		if (name == "email" && validMessagingEmail(contact)) || (name == "phone" && e164.MatchString(contact)) {
			return name, contact, nil
		}
	}
	return "", "", nil
}

type sendOutcome int

const (
	sendAccepted sendOutcome = iota
	// sendRefused: Messaging answered with a 4xx, so no message can reach the recipient.
	sendRefused
	// sendNotSent: the request never left the relay.
	sendNotSent
	// sendUnknown: a transport failure or server error, so a message may still arrive.
	sendUnknown
)

// send submits one message. A send is not retried by the relay. The Go HTTP
// transport may replay it once on a stale keep-alive connection, which is
// harmless because Messaging answers a repeated Idempotency-Key and body with
// the stored receipt.
func (v *messagingVerifier) send(ctx context.Context, channel, contact, code string, expires time.Time) sendOutcome {
	token, err := v.tokens.accessToken(ctx)
	if err != nil {
		return sendNotSent
	}
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return sendNotSent
	}
	ch := v.config.Channels[channel]
	minutes := int(v.ttl / time.Minute)
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
		return sendNotSent
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", hex.EncodeToString(key[:]))
	status, raw, err := v.p.request(req)
	if err != nil {
		return sendUnknown
	}
	if status >= 200 && status < 300 {
		return sendAccepted
	}
	var problem struct {
		Code string `json:"code"`
	}
	if status == http.StatusUnauthorized || (decodeJSON(raw, &problem) == nil && problem.Code == "authentication.refused") {
		v.tokens.invalidate(token)
	}
	if status >= 400 && status < 500 {
		return sendRefused
	}
	return sendUnknown
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// personLimiter spaces resends, caps sends per hour and counts failed
// verifications, all per person. People are keyed by an HMAC of identifier type
// and identifier under a random per-process key, so memory holds no raw
// identifiers and entries are fixed size. It counts every admitted request, so a
// caller cannot tell a known person from an unknown one by the limits.
type personLimiter struct {
	now       func() time.Time
	cooldown  time.Duration
	perHour   int
	maxPeople int
	key       [32]byte
	mu        sync.Mutex
	people    map[[32]byte]*personState
}

type personState struct {
	sends         []time.Time
	next          map[Binding]time.Time
	failures      int
	failuresSince time.Time
}

// admission records what one admitted request added, so it can be reversed.
type admission struct {
	person  [32]byte
	binding Binding
	at      time.Time
}

type limiterStatus int

const (
	limiterAdmitted limiterStatus = iota
	// limiterHeld: a cooldown, the hourly budget or a failure lock applies.
	limiterHeld
	// limiterFull: the limiter is at its bound and cannot track a new person.
	limiterFull
)

func newPersonLimiter(now func() time.Time, cooldown time.Duration, perHour, maxPeople int) *personLimiter {
	l := &personLimiter{now: now, cooldown: cooldown, perHour: perHour, maxPeople: maxPeople, people: map[[32]byte]*personState{}}
	// crypto/rand.Read does not return an error.
	_, _ = rand.Read(l.key[:])
	return l
}

func (l *personLimiter) person(identifierType, identifier string) [32]byte {
	m := hmac.New(sha256.New, l.key[:])
	_, _ = m.Write([]byte(strconv.Itoa(len(identifierType)) + ":" + identifierType + identifier))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// state returns the person's entry, creating it when there is room. The caller holds l.mu.
func (l *personLimiter) state(p [32]byte, now time.Time) (*personState, bool) {
	if st, ok := l.people[p]; ok {
		return st, true
	}
	if len(l.people) >= l.maxPeople {
		l.prune(now)
		if len(l.people) >= l.maxPeople {
			return nil, false
		}
	}
	st := &personState{next: map[Binding]time.Time{}}
	l.people[p] = st
	return st, true
}

func (st *personState) locked(now time.Time) bool {
	return st.failures >= failureLockThreshold && now.Before(st.failuresSince.Add(limiterWindow))
}

// admit reports whether a send may proceed and records it when it may.
func (l *personLimiter) admit(p [32]byte, b Binding) (admission, limiterStatus) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	st, ok := l.state(p, now)
	if !ok {
		return admission{}, limiterFull
	}
	if st.locked(now) {
		return admission{}, limiterHeld
	}
	if until, ok := st.next[b]; ok && now.Before(until) {
		return admission{}, limiterHeld
	}
	st.trim(now)
	if len(st.sends) >= l.perHour {
		return admission{}, limiterHeld
	}
	st.sends = append(st.sends, now)
	st.next[b] = now.Add(l.cooldown)
	return admission{p, b, now}, limiterAdmitted
}

// refund reverses an admission after a send that definitely did not happen.
func (l *personLimiter) refund(a admission) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.people[a.person]
	if !ok {
		return
	}
	for i, t := range st.sends {
		if t.Equal(a.at) {
			st.sends = append(st.sends[:i], st.sends[i+1:]...)
			break
		}
	}
	l.reopenLocked(st, a)
}

// reopen frees the resend cooldown after a send whose outcome is unknown. The
// hourly budget stays spent.
func (l *personLimiter) reopen(a admission) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, ok := l.people[a.person]; ok {
		l.reopenLocked(st, a)
	}
}

func (l *personLimiter) reopenLocked(st *personState, a admission) {
	if until, ok := st.next[a.binding]; ok && until.Equal(a.at.Add(l.cooldown)) {
		delete(st.next, a.binding)
	}
}

func (l *personLimiter) locked(p [32]byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.people[p]
	return ok && st.locked(l.now())
}

// fail counts one failed verification. A person the limiter cannot track keeps
// only the per-challenge attempt limit.
func (l *personLimiter) fail(p [32]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	st, ok := l.state(p, now)
	if !ok {
		return
	}
	if st.failures == 0 || !now.Before(st.failuresSince.Add(limiterWindow)) {
		st.failures, st.failuresSince = 0, now
	}
	st.failures++
}

func (l *personLimiter) reset(p [32]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, ok := l.people[p]; ok {
		st.failures = 0
	}
}

func (st *personState) trim(now time.Time) {
	kept := st.sends[:0]
	for _, t := range st.sends {
		if now.Sub(t) < limiterWindow {
			kept = append(kept, t)
		}
	}
	st.sends = kept
}

// prune drops entries with no live cooldown, budget or failure count.
func (l *personLimiter) prune(now time.Time) {
	for p, st := range l.people {
		st.trim(now)
		for b, until := range st.next {
			if !now.Before(until) {
				delete(st.next, b)
			}
		}
		if st.failures > 0 && !now.Before(st.failuresSince.Add(limiterWindow)) {
			st.failures = 0
		}
		if len(st.sends) == 0 && len(st.next) == 0 && st.failures == 0 {
			delete(l.people, p)
		}
	}
}
