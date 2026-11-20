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
	sweepInterval        = time.Second
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

	sweepMu   sync.Mutex
	nextSweep time.Time
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

// channelOrder is the preference order when a person holds a contact for more
// than one requested channel.
var channelOrder = []string{"email", "phone"}

// channels lists the configured channels in preference order.
func (v *messagingVerifier) channels() []string {
	out := make([]string, 0, len(channelOrder))
	for _, name := range channelOrder {
		if _, ok := v.config.Channels[name]; ok {
			out = append(out, name)
		}
	}
	return out
}

func (v *messagingVerifier) emit(e OperatorEvent) { v.p.emit(e) }

// maintain prunes the limiter and sweeps the store, at most once a second, so a
// request never pays for a full scan and memory stays bounded below the limits.
func (v *messagingVerifier) maintain() {
	now := v.now()
	v.sweepMu.Lock()
	due := !now.Before(v.nextSweep)
	if due {
		v.nextSweep = now.Add(sweepInterval)
	}
	v.sweepMu.Unlock()
	if due {
		v.limits.prune()
		v.sweep()
	}
}

// SendOTP gives the same outward result whether or not a message is sent for a
// known, unknown, ineligible or contactless person, and when a limit applies.
// The Messaging call runs after the result is returned, so its outcome cannot
// reveal who exists. Only a malformed request, an unreachable BREG, or a full
// challenge store or limiter (which refuse everyone alike) is an error.
//
// Stored state is a function of the requests received, never of what BREG or
// Messaging answered. An admitted request spends its cooldown and hourly budget
// and stores one challenge, whatever happens next. Nothing is refunded and no
// answer deletes an entry. A person who retries during a Messaging outage can
// therefore use up the hourly budget and be held silently after it ends.
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
	v.maintain()
	if v.full() {
		v.emit(EventStoreFull)
		return ErrUnavailable
	}
	switch v.limits.admit(v.limits.person(r.IdentifierType, r.Identifier), r.Binding) {
	case limiterFull:
		v.emit(EventLimiterFull)
		return ErrUnavailable
	case limiterHeld:
		return nil
	}
	code, c, err := v.generate()
	if err != nil {
		return err
	}
	key := challengeKey{r.Identifier, r.IdentifierType, r.Binding}
	channel, contact, err := v.contact(ctx, r.Identifier, channels)
	if err != nil {
		v.keep(key, c)
		return err
	}
	if contact == "" {
		v.keep(key, c)
		return nil
	}
	select {
	case v.slots <- struct{}{}:
	default:
		v.keep(key, c)
		v.emit(EventSendDropped)
		return nil
	}
	// The challenge exists before the call so that a code delivered after an
	// ambiguous transport failure still verifies.
	previous, replaced := v.swap(key, c)
	v.sends.Add(1)
	go v.deliver(context.WithoutCancel(ctx), key, c, previous, replaced, channel, contact, code)
	return nil
}

// deliver runs one Messaging call on a context of its own. The call lasts at
// most twice the HTTP timeout, which the resend cooldown must cover, so two
// sends for one person and binding never overlap.
func (v *messagingVerifier) deliver(ctx context.Context, key challengeKey, c, previous challenge, replaced bool, channel, contact, code string) {
	defer v.sends.Done()
	defer func() { <-v.slots }()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Duration(v.p.config.HTTP.TimeoutSeconds)*time.Second)
	defer cancel()
	switch v.send(ctx, channel, contact, code, c.expires) {
	case sendAccepted:
	case sendRefused:
		v.restore(key, c, previous, replaced)
		v.emit(EventSendRefused)
	case sendNotSent:
		v.restore(key, c, previous, replaced)
		v.emit(EventSendFailed)
	default:
		v.emit(EventSendFailed)
	}
}

// wait blocks until every started send has finished.
func (v *messagingVerifier) wait() { v.sends.Wait() }

// Verify counts a wrong code against the person only when a challenge was
// pending for the binding, so verification traffic for requests nobody made
// neither locks a person nor adds limiter entries.
func (v *messagingVerifier) Verify(ctx context.Context, r ChallengeRequest) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	person := v.limits.person(r.IdentifierType, r.Identifier)
	if v.limits.locked(person) {
		return ErrChallengeFailed
	}
	pending, err := v.check(challengeKey{r.Identifier, r.IdentifierType, r.Binding}, r.Challenge)
	if err != nil {
		if pending {
			v.limits.fail(person)
		}
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
// identifiers and entries are fixed size.
//
// Like the challenge store, its state is a function of the requests received:
// every admitted request is counted and nothing is refunded, so a caller cannot
// tell a known person from an unknown one by the limits. Only admit creates an
// entry. At its bound the limiter refuses every request, tracked or not.
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

type limiterStatus int

const (
	limiterAdmitted limiterStatus = iota
	// limiterHeld: a cooldown, the hourly budget or a failure lock applies.
	limiterHeld
	// limiterFull: the limiter is at its bound and refuses every request.
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

func (st *personState) locked(now time.Time) bool {
	return st.failures >= failureLockThreshold && now.Before(st.failuresSince.Add(limiterWindow))
}

// admit reports whether a send may proceed and records it when it may.
func (l *personLimiter) admit(p [32]byte, b Binding) limiterStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.people) >= l.maxPeople {
		return limiterFull
	}
	now := l.now()
	st, ok := l.people[p]
	if !ok {
		st = &personState{next: map[Binding]time.Time{}}
		l.people[p] = st
	}
	if st.locked(now) {
		return limiterHeld
	}
	if until, ok := st.next[b]; ok && now.Before(until) {
		return limiterHeld
	}
	st.trim(now)
	if len(st.sends) >= l.perHour {
		return limiterHeld
	}
	st.sends = append(st.sends, now)
	st.next[b] = now.Add(l.cooldown)
	return limiterAdmitted
}

func (l *personLimiter) locked(p [32]byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.people[p]
	return ok && st.locked(l.now())
}

// fail counts one failed verification against a person already tracked. It
// never creates an entry.
func (l *personLimiter) fail(p [32]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.people[p]
	if !ok {
		return
	}
	now := l.now()
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

// prune drops expired cooldowns and sends, and entries with nothing live.
func (l *personLimiter) prune() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
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
