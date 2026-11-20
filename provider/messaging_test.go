package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type sentMessage struct {
	authorization, idempotencyKey string
	body                          map[string]any
}

// messagingFixture runs fakes for the token endpoint, BREG and Registry Messaging.
type messagingFixture struct {
	*fixture
	server *httptest.Server
	// mu guards every field below, because sends run on their own goroutines.
	mu      sync.Mutex
	sent    []sentMessage
	handler func(http.ResponseWriter, *http.Request)
	person  map[string]any
	lookup  func(http.ResponseWriter)
	now     time.Time
	events  []OperatorEvent
}

func (m *messagingFixture) setHandler(f func(http.ResponseWriter, *http.Request)) {
	m.mu.Lock()
	m.handler = f
	m.mu.Unlock()
}

func (m *messagingFixture) setLookup(f func(http.ResponseWriter)) {
	m.mu.Lock()
	m.lookup = f
	m.mu.Unlock()
}

func (m *messagingFixture) clock() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

func (m *messagingFixture) advance(d time.Duration) {
	m.mu.Lock()
	m.now = m.now.Add(d)
	m.mu.Unlock()
}

func (m *messagingFixture) signal(e OperatorEvent) {
	m.mu.Lock()
	m.events = append(m.events, e)
	m.mu.Unlock()
}

// signals returns the operator events seen so far, after in-flight sends finish.
func (m *messagingFixture) signals() []OperatorEvent {
	m.verifier().wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]OperatorEvent(nil), m.events...)
}

func newMessagingFixture(t *testing.T, mutate func(*Config)) *messagingFixture {
	t.Helper()
	m := &messagingFixture{fixture: newFixture(t), now: time.Unix(2_000_000_000, 0)}
	m.person = map[string]any{"uin": "subject-canary", "status": "active", "email-address": "ada@example.test", "phone-number": "+94112223344"}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		_ = json.Unmarshal(body, &decoded)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("wrong Messaging route")
		}
		m.mu.Lock()
		m.sent = append(m.sent, sentMessage{r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key"), decoded})
		handler := m.handler
		m.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"id":"00000000-0000-4000-8000-000000000001","status":"queued","links":{}}`)
	}))
	t.Cleanup(m.server.Close)
	m.fixture.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		m.fixture.checkAssertionFor(r)
		token := "token-canary"
		if r.Form.Get("resource") == "urn:messaging:test" {
			token = "messaging-token-canary"
			if r.Form.Get("scope") != "messaging:send" {
				t.Error("wrong Messaging scope")
			}
		}
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":300}`, token)
	}
	m.fixture.handler = func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		lookup, person := m.lookup, m.person
		m.mu.Unlock()
		if lookup != nil {
			lookup(w)
			return
		}
		selected := strings.Split(r.URL.Query().Get("$select"), ",")
		domain := map[string]any{}
		for _, f := range selected {
			if v, ok := person[f]; ok {
				domain[f] = v
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"domainData": domain}})
	}
	c := m.fixture.config
	c.BREG.ProvisionedFields = append(append([]string(nil), c.BREG.ProvisionedFields...), "email-address", "phone-number")
	c.HTTP.TimeoutSeconds = 1
	c.Messaging = &MessagingConfig{
		BaseURL:       m.server.URL,
		TokenResource: "urn:messaging:test",
		TokenScopes:   []string{"messaging:send"},
		ContactFields: map[string]string{"email": "email-address", "phone": "phone-number"},
		Channels: map[string]MessagingChannelConfig{
			"email": {SenderProfile: "otp-email", TemplateID: "sign-in-code-email", TemplateVersion: "1", Locale: "en"},
			"phone": {SenderProfile: "otp-sms", TemplateID: "sign-in-code-sms", TemplateVersion: "1", Locale: "en"},
		},
	}
	if mutate != nil {
		mutate(&c)
	}
	m.fixture.config = c
	p, err := New(c, WithOperatorSignal(m.signal))
	if err != nil {
		t.Fatal(err)
	}
	m.fixture.p = p
	m.verifier().now = m.clock
	return m
}

func (m *messagingFixture) verifier() *messagingVerifier { return m.p.verifier.(*messagingVerifier) }
func (m *messagingFixture) sentCount() int {
	m.verifier().wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}
func (m *messagingFixture) lastCode(t *testing.T) string {
	t.Helper()
	m.verifier().wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		t.Fatal("no message sent")
	}
	data, _ := m.sent[len(m.sent)-1].body["data"].(map[string]any)
	code, _ := data["code"].(string)
	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(code) {
		t.Fatal("message lacks a six-digit code")
	}
	return code
}
func otpRequest(channel string) OTPRequest {
	return OTPRequest{Identifier: "subject-canary", IdentifierType: "uin", Binding: binding(), Channels: []string{channel}}
}
func challengeFor(code string) ChallengeRequest {
	return ChallengeRequest{Identifier: "subject-canary", IdentifierType: "uin", Binding: binding(), Challenge: code}
}

// checkAssertionFor parses the form and checks the shared client identity.
func (f *fixture) checkAssertionFor(r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.t.Error(err)
	}
	if r.Form.Get("client_id") != "client" || r.Form.Get("client_assertion") == "" || r.Form.Get("grant_type") != "client_credentials" {
		f.t.Error("token request does not use the shared client identity")
	}
}

func TestMessagingSendReachesMessagingAndVerifiesOnce(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	m := newMessagingFixture(t, nil)
	if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
		t.Fatal(err)
	}
	if m.sentCount() != 1 {
		t.Fatal("expected one Messaging call")
	}
	s := m.sent[0]
	if s.authorization != "Bearer messaging-token-canary" || len(s.idempotencyKey) < 16 || len(s.idempotencyKey) > 128 {
		t.Fatal("wrong Messaging credentials or idempotency key")
	}
	code := m.lastCode(t)
	want := map[string]any{
		"senderProfile": "otp-email",
		"to":            map[string]any{"email": "ada@example.test"},
		"template":      map[string]any{"id": "sign-in-code-email", "version": "1"},
		"locale":        "en",
		"data":          map[string]any{"code": code, "minutes": float64(5)},
		"expiresAt":     m.clock().Add(5 * time.Minute).UTC().Format(time.RFC3339),
	}
	got, _ := json.Marshal(s.body)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Fatalf("wrong Messaging body: %s", got)
	}
	// The BREG lookup reads the account-check fields and the channel's contact field only.
	if m.lookupCalls.Load() != 1 || m.tokenCalls.Load() != 2 {
		t.Fatal("expected one lookup and one token per resource")
	}
	if _, err := m.p.Authenticate(context.Background(), AuthenticationRequest{Identifier: "subject-canary", IdentifierType: "uin", Binding: binding(), Challenge: "000000"}); err != ErrChallengeFailed && code != "000000" {
		t.Fatal("wrong code accepted")
	}
	result, err := m.p.Authenticate(context.Background(), AuthenticationRequest{Identifier: "subject-canary", IdentifierType: "uin", Binding: binding(), Challenge: code})
	if err != nil || result.Subject == "" {
		t.Fatalf("delivered code did not authenticate: %v", err)
	}
	if err := m.p.verifier.Verify(context.Background(), challengeFor(code)); err != ErrChallengeFailed {
		t.Fatal("code reused")
	}
	for _, secret := range []string{code, "ada@example.test", "+94112223344", "subject-canary", "messaging-token-canary", s.idempotencyKey} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("sensitive value logged")
		}
	}
}

func TestMessagingPhoneChannelAndChannelSupport(t *testing.T) {
	m := newMessagingFixture(t, nil)
	if got := m.p.SupportedOTPChannels(); len(got) != 2 || got[0] != "email" || got[1] != "phone" {
		t.Fatalf("wrong channels %v", got)
	}
	if err := m.p.SendOTP(context.Background(), otpRequest("phone")); err != nil {
		t.Fatal(err)
	}
	m.sentCount()
	s := m.sent[0]
	if s.body["senderProfile"] != "otp-sms" || fmt.Sprint(s.body["to"]) != "map[phone:+94112223344]" || fmt.Sprint(s.body["template"]) != "map[id:sign-in-code-sms version:1]" {
		t.Fatal("wrong SMS message")
	}
	emailOnly := newMessagingFixture(t, func(c *Config) {
		delete(c.Messaging.Channels, "phone")
		delete(c.Messaging.ContactFields, "phone")
	})
	if got := emailOnly.p.SupportedOTPChannels(); len(got) != 1 || got[0] != "email" {
		t.Fatalf("wrong channels %v", got)
	}
	if err := emailOnly.p.SendOTP(context.Background(), otpRequest("phone")); err != ErrInvalidRequest || emailOnly.sentCount() != 0 {
		t.Fatal("unconfigured channel accepted")
	}
}

func TestMessagingCodeExpiryAttemptsAndBinding(t *testing.T) {
	m := newMessagingFixture(t, nil)
	send := func() string {
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
			t.Fatal(err)
		}
		return m.lastCode(t)
	}
	code := send()
	other := challengeFor(code)
	other.Binding.TransactionID = "other"
	if err := m.p.verifier.Verify(context.Background(), other); err != ErrChallengeFailed {
		t.Fatal("code accepted for another transaction")
	}
	m.advance(5 * time.Minute)
	if err := m.p.verifier.Verify(context.Background(), challengeFor(code)); err != ErrChallengeFailed {
		t.Fatal("expired code accepted")
	}
	m.advance(time.Hour)
	code = send()
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < challengeMaxAttempts; i++ {
		if err := m.p.verifier.Verify(context.Background(), challengeFor(wrong)); err != ErrChallengeFailed {
			t.Fatal("wrong code accepted")
		}
	}
	if err := m.p.verifier.Verify(context.Background(), challengeFor(code)); err != ErrChallengeFailed {
		t.Fatal("code accepted after attempt limit")
	}
}

func TestMessagingCooldownAndHourlyBudget(t *testing.T) {
	m := newMessagingFixture(t, func(c *Config) {
		c.Messaging.ResendCooldownSeconds = 60
		c.Messaging.MaxSendsPerHour = 3
	})
	send := func() {
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
			t.Fatal(err)
		}
	}
	send()
	send() // inside the cooldown: same outward result, nothing sent
	if m.sentCount() != 1 {
		t.Fatal("cooldown ignored")
	}
	first := m.lastCode(t)
	m.advance(61 * time.Second)
	send()
	m.advance(61 * time.Second)
	send()
	m.advance(61 * time.Second)
	send() // fourth send inside the hour
	if m.sentCount() != 3 {
		t.Fatalf("hourly budget ignored: %d", m.sentCount())
	}
	if err := m.p.verifier.Verify(context.Background(), challengeFor(first)); err != ErrChallengeFailed {
		t.Fatal("superseded code accepted")
	}
	m.advance(time.Hour)
	send()
	if m.sentCount() != 4 {
		t.Fatal("budget not restored after an hour")
	}
	// The cooldown is per person and binding, so a new transaction is not held
	// by it. The budget is per person, so the new transaction still counts.
	r := otpRequest("email")
	r.Binding.TransactionID = "second-transaction"
	for i := 0; i < 3; i++ {
		if err := m.p.SendOTP(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		r.Binding.TransactionID += "x"
	}
	if m.sentCount() != 6 {
		t.Fatalf("budget not shared across transactions: %d", m.sentCount())
	}
}

func TestMessagingNoEnumeration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		person map[string]any
		lookup func(http.ResponseWriter)
	}{
		{name: "unknown person", lookup: func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"code":"lookup.unresolved"}`)
		}},
		{name: "ineligible person", person: map[string]any{"uin": "subject-canary", "email-address": "ada@example.test"}},
		{name: "selector mismatch", person: map[string]any{"uin": "someone-else", "status": "active", "email-address": "ada@example.test"}},
		{name: "no contact", person: map[string]any{"uin": "subject-canary", "status": "active"}},
		{name: "invalid email", person: map[string]any{"uin": "subject-canary", "status": "active", "email-address": "not an address"}},
		{name: "non-string email", person: map[string]any{"uin": "subject-canary", "status": "active", "email-address": 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMessagingFixture(t, nil)
			if tc.person != nil {
				m.person = tc.person
			}
			m.setLookup(tc.lookup)
			if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
				t.Fatalf("outward result differs from a successful send: %v", err)
			}
			if m.sentCount() != 0 {
				t.Fatal("message sent")
			}
			for _, code := range []string{"000000", "123456"} {
				if err := m.p.verifier.Verify(context.Background(), challengeFor(code)); err != ErrChallengeFailed {
					t.Fatal("verify did not fail as for a wrong code")
				}
			}
		})
	}
	t.Run("invalid phone", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		m.person["phone-number"] = "0112223344"
		if err := m.p.SendOTP(context.Background(), otpRequest("phone")); err != nil || m.sentCount() != 0 {
			t.Fatal("non E.164 number used")
		}
	})
}

func hasEvent(events []OperatorEvent, want OperatorEvent) bool {
	for _, e := range events {
		if e == want {
			return true
		}
	}
	return false
}

// A failed Messaging call is invisible to the caller, who gets the same result
// as for an unknown person, and visible to the operator as a fixed event kind.
func TestMessagingSendFailuresAreSilentAndSignalled(t *testing.T) {
	t.Run("refusal", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		m.setHandler(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprint(w, `{"code":"template.locale-unavailable","detail":"ada@example.test"}`)
		})
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
			t.Fatalf("refusal reached the caller: %v", err)
		}
		if events := m.signals(); len(events) != 1 || events[0] != EventSendRefused {
			t.Fatalf("wrong events %v", events)
		}
		if len(m.verifier().pending) != 1 {
			t.Fatal("a refused send must leave the entry count unchanged")
		}
		m.setHandler(nil)
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil || m.sentCount() != 1 {
			t.Fatal("a refused send must still spend the resend cooldown")
		}
	})
	t.Run("refusal spends the hourly budget", func(t *testing.T) {
		m := newMessagingFixture(t, func(c *Config) { c.Messaging.MaxSendsPerHour = 1 })
		m.setHandler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) })
		_ = m.p.SendOTP(context.Background(), otpRequest("email"))
		m.signals()
		m.setHandler(nil)
		m.advance(61 * time.Second)
		_ = m.p.SendOTP(context.Background(), otpRequest("email"))
		if m.sentCount() != 1 {
			t.Fatal("a refused send must still spend the hourly budget")
		}
	})
	t.Run("timeout keeps the challenge and signals", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		m.setHandler(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
			}
		})
		start := time.Now()
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatal("SendOTP waited for Messaging")
		}
		if events := m.signals(); len(events) != 1 || events[0] != EventSendFailed {
			t.Fatalf("wrong events %v", events)
		}
		if len(m.verifier().pending) != 1 {
			t.Fatal("a code that may have been delivered must still verify")
		}
	})
	t.Run("rejected token is replaced", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		m.setHandler(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"code":"authentication.refused"}`)
		})
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
			t.Fatal(err)
		}
		m.signals()
		before := m.tokenCalls.Load()
		m.advance(2 * time.Minute)
		m.setHandler(nil)
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
			t.Fatal(err)
		}
		m.signals()
		if m.tokenCalls.Load() != before+1 {
			t.Fatal("rejected Messaging token was reused")
		}
	})
	t.Run("BREG unavailable is an error and still spends the budget", func(t *testing.T) {
		m := newMessagingFixture(t, func(c *Config) { c.Messaging.MaxSendsPerHour = 1 })
		m.setLookup(func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"code":"source.unavailable"}`)
		})
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != ErrUnavailable || m.sentCount() != 0 {
			t.Fatal("BREG outage not reported as unavailable")
		}
		m.setLookup(nil)
		m.advance(61 * time.Second)
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil || m.sentCount() != 0 {
			t.Fatal("a request during a BREG outage must still spend the hourly budget")
		}
	})
}

// A Messaging 429, a full challenge store and a full send queue all give a
// known person the same outward result as an unknown one.
func TestMessagingOutwardResultIsIdenticalForKnownAndUnknown(t *testing.T) {
	unknown := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"code":"lookup.unresolved"}`)
	}
	for _, tc := range []struct {
		name  string
		setup func(m *messagingFixture)
		event OperatorEvent
	}{
		{"messaging 429", func(m *messagingFixture) {
			m.setHandler(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprint(w, `{"code":"rate-limit.exceeded"}`)
			})
		}, EventSendRefused},
		{"challenge store full", func(m *messagingFixture) {
			v := m.verifier()
			for i := 0; i < v.maxPending; i++ {
				v.pending[challengeKey{identifier: fmt.Sprintf("filler-%d", i)}] = entry{hold: m.clock().Add(time.Minute)}
			}
		}, EventStoreFull},
		{"send queue full", func(m *messagingFixture) { m.verifier().slots = make(chan struct{}) }, EventSendDropped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMessagingFixture(t, nil)
			tc.setup(m)
			known := m.p.SendOTP(context.Background(), otpRequest("email"))
			m.setLookup(unknown)
			r := otpRequest("email")
			r.Identifier = "nobody"
			gone := m.p.SendOTP(context.Background(), r)
			if (known == nil) != (gone == nil) || (known != nil && known != gone) {
				t.Fatalf("known=%v unknown=%v", known, gone)
			}
			if !hasEvent(m.signals(), tc.event) {
				t.Fatalf("operator not told: %v", m.signals())
			}
		})
	}
}

func TestMessagingSendQueueIsBounded(t *testing.T) {
	m := newMessagingFixture(t, func(c *Config) { c.Messaging.MaxSendsPerHour = 60 })
	m.verifier().slots = make(chan struct{}, 2)
	release := make(chan struct{})
	m.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusAccepted)
	})
	r := otpRequest("email")
	for i := 0; i < 3; i++ {
		r.Binding.TransactionID = fmt.Sprintf("tx-%d", i)
		if err := m.p.SendOTP(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	if m.sentCount() != 2 {
		t.Fatalf("want 2 sends past the cap, got %d", m.sentCount())
	}
	if events := m.signals(); len(events) != 1 || events[0] != EventSendDropped {
		t.Fatalf("wrong events %v", events)
	}
	if len(m.verifier().pending) != 3 {
		t.Fatal("every admitted request stores one challenge, sent or dropped")
	}
}

// The operator signal carries only a fixed event kind.
func TestMessagingSignalsCarryNoValues(t *testing.T) {
	m := newMessagingFixture(t, nil)
	m.setHandler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnprocessableEntity) })
	_ = m.p.SendOTP(context.Background(), otpRequest("email"))
	code := m.lastCode(t)
	for _, e := range m.signals() {
		for _, secret := range []string{code, "ada@example.test", "subject-canary", "+94112223344"} {
			if strings.Contains(string(e), secret) {
				t.Fatalf("event %q carries a value", e)
			}
		}
	}
}

func TestMessagingChannelSelection(t *testing.T) {
	phoneOnly := map[string]any{"uin": "subject-canary", "status": "active", "phone-number": "+94112223344"}
	emailOnly := map[string]any{"uin": "subject-canary", "status": "active", "email-address": "ada@example.test"}
	for _, tc := range []struct {
		name     string
		person   map[string]any
		request  []string
		wantTo   string
		wantSent int
	}{
		{"overlay request, phone-only person", phoneOnly, []string{"email", "phone"}, "map[phone:+94112223344]", 1},
		{"overlay request, person with both prefers email", nil, []string{"phone", "email"}, "map[email:ada@example.test]", 1},
		{"phone only requested", nil, []string{"phone"}, "map[phone:+94112223344]", 1},
		{"phone only requested, email-only person", emailOnly, []string{"phone"}, "", 0},
		{"invalid email falls through to phone", map[string]any{"uin": "subject-canary", "status": "active", "email-address": "ada@localhost", "phone-number": "+94112223344"}, []string{"email", "phone"}, "map[phone:+94112223344]", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMessagingFixture(t, nil)
			if tc.person != nil {
				m.person = tc.person
			}
			r := otpRequest("email")
			r.Channels = tc.request
			if err := m.p.SendOTP(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			if m.sentCount() != tc.wantSent {
				t.Fatalf("sent %d", m.sentCount())
			}
			if tc.wantSent > 0 && fmt.Sprint(m.sent[0].body["to"]) != tc.wantTo {
				t.Fatalf("sent to %v", m.sent[0].body["to"])
			}
		})
	}
	t.Run("one lookup for every channel", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		r := otpRequest("email")
		r.Channels = []string{"email", "phone"}
		before := m.lookupCalls.Load()
		if err := m.p.SendOTP(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		if m.lookupCalls.Load()-before != 1 {
			t.Fatal("more than one BREG lookup")
		}
	})
}

func TestMessagingContactValidationMatchesMessaging(t *testing.T) {
	for address, want := range map[string]bool{
		"ada@example.org": true, "a.b+c@mail.example.org": true,
		"ada@localhost": false, "a,b@example.org": false, "a;b@example.org": false,
		"ada@.example.org": false, "ada@example.org.": false, "@example.org": false,
		"ada@@example.org": false, "ada@exa mple.org": false, "<ada@example.org>": false,
		"ada@example.org\n": false, "ada": false, "": false,
	} {
		if got := validMessagingEmail(address); got != want {
			t.Errorf("validMessagingEmail(%q) = %v, want %v", address, got, want)
		}
	}
	for number, want := range map[string]bool{"+94112223344": true, "+12": true, "+0123": false, "+1": false, "+1234567890123456": false, "94112223344": false} {
		if got := e164.MatchString(number); got != want {
			t.Errorf("e164(%q) = %v, want %v", number, got, want)
		}
	}
}

func TestMessagingLimiterBounds(t *testing.T) {
	m := newMessagingFixture(t, func(c *Config) { c.Messaging.MaxTrackedPeople = 20 })
	m.setLookup(func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"code":"lookup.unresolved"}`)
	})
	r := otpRequest("email")
	for i := 0; i < 20; i++ {
		r.Identifier = fmt.Sprintf("guess-%d", i)
		if err := m.p.SendOTP(context.Background(), r); err != nil {
			t.Fatalf("under the bound: %v", err)
		}
	}
	r.Identifier = "one-too-many"
	if err := m.p.SendOTP(context.Background(), r); err != ErrUnavailable || !hasEvent(m.signals(), EventLimiterFull) {
		t.Fatal("a full limiter must refuse and tell the operator")
	}
	m.advance(time.Hour + time.Second)
	m.setLookup(nil)
	if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil || m.sentCount() != 1 {
		t.Fatal("limiter did not recover after the window")
	}
	for p := range m.verifier().limits.people {
		if len(p) != 32 {
			t.Fatal("limiter key is not a fixed-size hash")
		}
	}
}

func TestMessagingFailureLockout(t *testing.T) {
	m := newMessagingFixture(t, func(c *Config) { c.Messaging.MaxSendsPerHour = 60 })
	send := func() {
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
			t.Fatal(err)
		}
		m.advance(61 * time.Second)
	}
	wrong := func(n int) {
		for i := 0; i < n; i++ {
			if m.p.verifier.Verify(context.Background(), challengeFor("not-a-code")) == nil {
				t.Fatal("wrong code accepted")
			}
		}
	}
	// Resends reset the per-code attempt count, but not the per-person count.
	for round := 0; round < 3; round++ {
		send()
		wrong(4)
	}
	send() // twelve attempts is past the threshold, so this code is never issued
	if m.sentCount() != 3 {
		t.Fatalf("locked person was sent a code: %d sends", m.sentCount())
	}
	if m.p.verifier.Verify(context.Background(), challengeFor(m.lastCode(t))) != ErrChallengeFailed {
		t.Fatal("locked person's code accepted")
	}
	m.advance(time.Hour)
	send()
	if err := m.p.verifier.Verify(context.Background(), challengeFor(m.lastCode(t))); err != nil {
		t.Fatalf("lock did not end with the window: %v", err)
	}
	// Success resets the count.
	for round := 0; round < 2; round++ {
		send()
		wrong(4)
	}
	send()
	if err := m.p.verifier.Verify(context.Background(), challengeFor(m.lastCode(t))); err != nil {
		t.Fatalf("count not reset by success: %v", err)
	}
}

func TestMessagingRefusedResendKeepsDeliveredCode(t *testing.T) {
	m := newMessagingFixture(t, nil)
	if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
		t.Fatal(err)
	}
	first := m.lastCode(t)
	m.advance(61 * time.Second)
	m.setHandler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) })
	if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
		t.Fatal(err)
	}
	m.signals()
	if err := m.p.verifier.Verify(context.Background(), challengeFor(first)); err != nil {
		t.Fatalf("refused resend invalidated the delivered code: %v", err)
	}
}

// A failure of an earlier send must not delete a challenge a later resend stored.
func TestMessagingStaleFailureKeepsNewerChallenge(t *testing.T) {
	m := newMessagingFixture(t, func(c *Config) { c.Messaging.ResendCooldownSeconds = 3 })
	v := m.verifier()
	key := challengeKey{"subject-canary", "uin", binding()}
	_, first, _ := v.generate()
	previous, replaced := v.swap(key, first)
	_, second, _ := v.generate()
	v.swap(key, second)
	v.restore(key, first, previous, replaced)
	if _, ok := v.pending[key]; !ok || v.pending[key].salt != second.salt {
		t.Fatal("stale failure removed the newer challenge")
	}
}

func TestMessagingTemplateVersionRule(t *testing.T) {
	for version, want := range map[string]bool{"1": true, "v1": true, "2026-01": true, "1.2": true, "V1": false, "": false, "1..2": false, "1.": false, "-1": false, "a_b": false, strings.Repeat("a", 33): false} {
		if got := validTemplateVersion(version); got != want {
			t.Errorf("validTemplateVersion(%q) = %v, want %v", version, got, want)
		}
	}
}

func TestMessagingConfigIsNotMutated(t *testing.T) {
	m := newMessagingFixture(t, nil)
	c := m.config
	mc := *c.Messaging
	mc.CodeTTLSeconds, mc.ResendCooldownSeconds, mc.MaxSendsPerHour, mc.MaxTrackedPeople, mc.MaxPendingCodes = 0, 0, 0, 0, 0
	c.Messaging = &mc
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
	if mc.CodeTTLSeconds != 0 || mc.MaxTrackedPeople != 0 {
		t.Fatal("New wrote defaults into the caller's configuration")
	}
}

func TestMessagingMinutesAreNotRoundedUp(t *testing.T) {
	m := newMessagingFixture(t, func(c *Config) { c.Messaging.CodeTTLSeconds = 90 })
	if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
		t.Fatal(err)
	}
	m.sentCount()
	data, _ := m.sent[0].body["data"].(map[string]any)
	if data["minutes"] != float64(1) {
		t.Fatalf("a 90 second code advertised %v minutes", data["minutes"])
	}
}

func TestMessagingConfigurationValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		field  string
	}{
		{"demo static conflict", func(c *Config) { c.Demo.StaticOTPEnabled = true; c.Demo.StaticOTPFile = "x" }, "demo.challenge_mode"},
		{"demo mailpit conflict", func(c *Config) {
			c.Demo.Mailpit = MailpitConfig{Enabled: true, SMTPAddress: "mailpit:1025", Sender: "a@example.test", Recipient: "b@example.test"}
		}, "demo.challenge_mode"},
		{"missing base url", func(c *Config) { c.Messaging.BaseURL = "" }, "messaging.base_url"},
		{"insecure base url", func(c *Config) {
			c.HTTP.AllowInsecureHTTP = false
			c.Messaging.BaseURL = "http://messaging.example.test"
		}, "messaging.base_url"},
		{"missing resource", func(c *Config) { c.Messaging.TokenResource = "" }, "messaging.token_resource"},
		{"missing scopes", func(c *Config) { c.Messaging.TokenScopes = nil }, "messaging.token_scopes"},
		{"no channels", func(c *Config) { c.Messaging.Channels = nil; c.Messaging.ContactFields = nil }, "messaging.channels"},
		{"unknown channel", func(c *Config) { c.Messaging.Channels["fax"] = MessagingChannelConfig{} }, "messaging.channels"},
		{"missing sender profile", func(c *Config) {
			ch := c.Messaging.Channels["email"]
			ch.SenderProfile = ""
			c.Messaging.Channels["email"] = ch
		}, "messaging.channels.email"},
		{"missing template", func(c *Config) {
			ch := c.Messaging.Channels["email"]
			ch.TemplateID = ""
			c.Messaging.Channels["email"] = ch
		}, "messaging.channels.email"},
		{"missing template version", func(c *Config) {
			ch := c.Messaging.Channels["phone"]
			ch.TemplateVersion = ""
			c.Messaging.Channels["phone"] = ch
		}, "messaging.channels.phone"},
		{"missing locale", func(c *Config) {
			ch := c.Messaging.Channels["phone"]
			ch.Locale = ""
			c.Messaging.Channels["phone"] = ch
		}, "messaging.channels.phone"},
		{"channel without contact field", func(c *Config) { delete(c.Messaging.ContactFields, "phone") }, "messaging.contact_fields"},
		{"contact field without channel", func(c *Config) { delete(c.Messaging.Channels, "phone") }, "messaging.contact_fields"},
		{"contact field not provisioned", func(c *Config) { c.Messaging.ContactFields["email"] = "unlisted" }, "messaging.contact_fields"},
		{"ttl too short", func(c *Config) { c.Messaging.CodeTTLSeconds = 10 }, "messaging.code_ttl_seconds"},
		{"ttl too long", func(c *Config) { c.Messaging.CodeTTLSeconds = 3600 }, "messaging.code_ttl_seconds"},
		{"cooldown too long", func(c *Config) { c.Messaging.ResendCooldownSeconds = 99999 }, "messaging.resend_cooldown_seconds"},
		{"budget too large", func(c *Config) { c.Messaging.MaxSendsPerHour = 1000 }, "messaging.max_sends_per_hour"},
		{"tracked people too many", func(c *Config) { c.Messaging.MaxTrackedPeople = 1_000_001 }, "messaging.max_tracked_people"},
		{"pending codes too many", func(c *Config) { c.Messaging.MaxPendingCodes = 100_000_000 }, "messaging.max_pending_codes"},
		{"template version uppercase", func(c *Config) {
			ch := c.Messaging.Channels["email"]
			ch.TemplateVersion = "V1"
			c.Messaging.Channels["email"] = ch
		}, "messaging.channels.email"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.config
			c.BREG.ProvisionedFields = append(append([]string(nil), c.BREG.ProvisionedFields...), "email-address", "phone-number")
			c.Messaging = &MessagingConfig{BaseURL: "https://messaging.example.test", TokenResource: "urn:messaging:test", TokenScopes: []string{"messaging:send"},
				ContactFields: map[string]string{"email": "email-address", "phone": "phone-number"},
				Channels: map[string]MessagingChannelConfig{
					"email": {SenderProfile: "otp-email", TemplateID: "t-email", TemplateVersion: "1", Locale: "en"},
					"phone": {SenderProfile: "otp-sms", TemplateID: "t-sms", TemplateVersion: "1", Locale: "en"}}}
			c.HTTP.AllowInsecureHTTP = true
			tc.mutate(&c)
			_, err := New(c)
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("want %s refused, got %v", tc.field, err)
			}
		})
	}
	t.Run("injected verifier conflicts", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		if _, err := New(m.config, WithChallengeVerifier(&verifierStub{})); err == nil {
			t.Fatal("messaging and injected verifier accepted together")
		}
	})
	t.Run("injected verifier still works without messaging", func(t *testing.T) {
		f := newFixture(t)
		if f.p.verifier == nil {
			t.Fatal("no verifier")
		}
	})
}

func TestMessagingConfigurationFile(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	doc := fmt.Sprintf(`
subject_id_type: uin
psut_secret_file: %s
breg:
  base_url: %s
  route: population
  selector: by-uin
  provisioned_fields: [uin, status, email-address]
token_client:
  token_endpoint: %s/token
  assertion_audience: %s
  client_id: client
  private_key_file: %s
  key_id: test-key
  resource: urn:breg:test:population
  scopes: [registry.read]
http:
  allow_insecure_http: true
messaging:
  base_url: http://127.0.0.1:1
  token_resource: urn:messaging:test
  token_scopes: [messaging:send]
  contact_fields: {email: email-address}
  channels:
    email: {sender_profile: otp-email, template_id: code-email, template_version: 1, locale: en}
`, f.config.PSUTSecretFile, f.config.BREG.BaseURL, f.config.BREG.BaseURL, f.config.BREG.BaseURL, f.config.TokenClient.PrivateKeyFile)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Messaging.CodeTTLSeconds != 300 || c.Messaging.ResendCooldownSeconds != 60 || c.Messaging.MaxSendsPerHour != 5 || c.Messaging.MaxTrackedPeople != 100000 || c.Messaging.MaxPendingCodes != 100000 || c.Messaging.Channels["email"].TemplateVersion != "1" {
		t.Fatalf("wrong defaults: %+v", c.Messaging)
	}
	p, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.SupportedOTPChannels(); len(got) != 1 || got[0] != "email" {
		t.Fatalf("wrong channels %v", got)
	}
}
