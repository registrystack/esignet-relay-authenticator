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
	server  *httptest.Server
	mu      sync.Mutex
	sent    []sentMessage
	handler func(http.ResponseWriter, *http.Request)
	person  map[string]any
	lookup  func(http.ResponseWriter)
	now     time.Time
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
		m.mu.Unlock()
		if m.handler != nil {
			m.handler(w, r)
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
		if m.lookup != nil {
			m.lookup(w)
			return
		}
		selected := strings.Split(r.URL.Query().Get("$select"), ",")
		domain := map[string]any{}
		for _, f := range selected {
			if v, ok := m.person[f]; ok {
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
	p, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	m.fixture.p = p
	m.verifier().now = func() time.Time { return m.now }
	return m
}

func (m *messagingFixture) verifier() *messagingVerifier { return m.p.verifier.(*messagingVerifier) }
func (m *messagingFixture) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}
func (m *messagingFixture) lastCode(t *testing.T) string {
	t.Helper()
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
		"expiresAt":     m.now.Add(5 * time.Minute).UTC().Format(time.RFC3339),
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
	m.now = m.now.Add(5 * time.Minute)
	if err := m.p.verifier.Verify(context.Background(), challengeFor(code)); err != ErrChallengeFailed {
		t.Fatal("expired code accepted")
	}
	m.now = m.now.Add(time.Hour)
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
	m.now = m.now.Add(61 * time.Second)
	send()
	m.now = m.now.Add(61 * time.Second)
	send()
	m.now = m.now.Add(61 * time.Second)
	send() // fourth send inside the hour
	if m.sentCount() != 3 {
		t.Fatalf("hourly budget ignored: %d", m.sentCount())
	}
	if err := m.p.verifier.Verify(context.Background(), challengeFor(first)); err != ErrChallengeFailed {
		t.Fatal("superseded code accepted")
	}
	m.now = m.now.Add(time.Hour)
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
			m.lookup = tc.lookup
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

func TestMessagingFailuresSurfaceAsUnavailable(t *testing.T) {
	t.Run("refusal", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		m.handler = func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprint(w, `{"code":"template.locale-unavailable","detail":"ada@example.test"}`)
		}
		err := m.p.SendOTP(context.Background(), otpRequest("email"))
		if err != ErrUnavailable || len(m.verifier().pending) != 0 {
			t.Fatal("refused send left a usable challenge")
		}
		m.handler = nil
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil || m.sentCount() != 2 {
			t.Fatal("failed send consumed the resend cooldown")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		m.handler = func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
			}
		}
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != ErrUnavailable {
			t.Fatalf("want unavailable, got %v", err)
		}
	})
	t.Run("rejected token is replaced", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		m.handler = func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"code":"authentication.refused"}`)
		}
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != ErrUnavailable {
			t.Fatal("rejected token accepted")
		}
		before := m.tokenCalls.Load()
		m.now = m.now.Add(2 * time.Minute)
		m.handler = nil
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil || m.tokenCalls.Load() != before+1 {
			t.Fatal("rejected Messaging token was reused")
		}
	})
	t.Run("BREG unavailable", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		m.lookup = func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"code":"source.unavailable"}`)
		}
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != ErrUnavailable || m.sentCount() != 0 {
			t.Fatal("BREG outage not reported as unavailable")
		}
	})
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
	if c.Messaging.CodeTTLSeconds != 300 || c.Messaging.ResendCooldownSeconds != 60 || c.Messaging.MaxSendsPerHour != 5 || c.Messaging.Channels["email"].TemplateVersion != "1" {
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
