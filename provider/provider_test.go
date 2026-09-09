package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type verifierStub struct {
	verifyErr error
	verifyFn  func(context.Context) error
	calls     atomic.Int32
}

func (v *verifierStub) Verify(ctx context.Context, _ ChallengeRequest) error {
	v.calls.Add(1)
	if v.verifyFn != nil {
		return v.verifyFn(ctx)
	}
	return v.verifyErr
}
func (v *verifierStub) SendOTP(context.Context, OTPRequest) error { return nil }

type fixture struct {
	p                      *Provider
	config                 Config
	mintCalls, lookupCalls atomic.Int32
	handler                func(http.ResponseWriter, *http.Request)
	tokenHandler           func(http.ResponseWriter, *http.Request)
	key                    *ecdsa.PrivateKey
	t                      *testing.T
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t}
	dir := t.TempDir()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	f.key = key
	enc := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	jwk, _ := json.Marshal(map[string]string{"kty": "EC", "alg": "ES256", "use": "sig", "kid": "test-key", "crv": "P-256", "x": enc(key.X), "y": enc(key.Y), "d": enc(key.D)})
	keyPath := filepath.Join(dir, "key.json")
	if e = os.WriteFile(keyPath, jwk, 0600); e != nil {
		t.Fatal(e)
	}
	secretPath := filepath.Join(dir, "psut")
	if e = os.WriteFile(secretPath, []byte(strings.Repeat("s", 32)), 0600); e != nil {
		t.Fatal(e)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			f.mintCalls.Add(1)
			if f.tokenHandler != nil {
				f.tokenHandler(w, r)
				return
			}
			f.checkAssertion(r)
			fmt.Fprint(w, `{"access_token":"token-canary","token_type":"Bearer","expires_in":300}`)
			return
		}
		f.lookupCalls.Add(1)
		if f.handler != nil {
			f.handler(w, r)
			return
		}
		f.checkLookup(r)
		fmt.Fprint(w, `{"data":{"recordIdentifier":"hidden-metadata","domainData":{"uin":"subject-canary","status":"active","givenName":"Ada","familyName":"Lovelace","gender":"female","operatorNote":"forbidden-canary"}},"meta":{"email":"hidden"}}`)
	}))
	t.Cleanup(s.Close)
	f.config = Config{PSUTSecretFile: secretPath, BREG: BREGConfig{BaseURL: s.URL, Route: "population", Selector: "by-uin", AccessProfile: "esignet-source", ProvisionedFields: []string{"uin", "status", "givenName", "familyName", "gender"}}, Mint: MintConfig{TokenEndpoint: s.URL + "/token", ClientID: "client"}, ClaimMap: map[string]string{"sub": "$psut", "given_name": "givenName", "family_name": "familyName", "gender": "gender", "email": "email"}, HTTP: HTTPConfig{AllowInsecureHTTP: true}}
	f.config.Mint.PrivateKeyFile = keyPath
	f.p, e = New(f.config, WithChallengeVerifier(&verifierStub{}))
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *fixture) checkAssertion(r *http.Request) {
	t := f.t
	if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Error("wrong Mint method/content type")
	}
	if e := r.ParseForm(); e != nil {
		t.Error(e)
	}
	if len(r.PostForm) != 3 || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Error("wrong Mint form")
	}
	parts := strings.Split(r.Form.Get("client_assertion"), ".")
	if len(parts) != 3 {
		t.Error("assertion missing")
		return
	}
	head, _ := base64.RawURLEncoding.DecodeString(parts[0])
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	var h, c map[string]any
	_ = json.Unmarshal(head, &h)
	_ = json.Unmarshal(body, &c)
	if h["alg"] != "ES256" || h["kid"] != "test-key" || h["typ"] != "JWT" || len(h) != 3 {
		t.Error("wrong assertion header")
	}
	if c["iss"] != "client" || c["sub"] != "client" || c["aud"] != f.p.config.Mint.AssertionAudience || c["jti"] == "" || len(c) != 6 {
		t.Error("wrong assertion claims")
	}
	if c["exp"].(float64)-c["iat"].(float64) != 120 {
		t.Error("wrong assertion lifetime")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&f.key.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("signature invalid")
	}
}
func (f *fixture) checkLookup(r *http.Request) {
	t := f.t
	if r.Method != "POST" || r.URL.Path != "/v1/records/population:lookup" || r.Header.Get("Authorization") != "Bearer token-canary" || r.Header.Get("Data-Purpose") != "" {
		t.Error("wrong BREG contract")
	}
	q := r.URL.Query()
	if len(q) != 2 || q.Get("accessProfile") != "esignet-source" || q.Get("$select") == "" {
		t.Error("wrong projection query")
	}
	var body map[string]any
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		t.Error("bad request JSON")
	}
	if len(body) != 2 || body["selector"] != "by-uin" || !reflect.DeepEqual(body["values"], map[string]any{"uin": "subject-canary"}) {
		t.Error("wrong selector body")
	}
	if strings.Contains(r.URL.String(), "subject-canary") {
		t.Error("identifier in URL")
	}
}
func binding() Binding { return Binding{"rp", "client", "transaction"} }
func authenticate(t *testing.T, f *fixture) AuthenticationResult {
	t.Helper()
	r, e := f.p.Authenticate(context.Background(), AuthenticationRequest{Identifier: "subject-canary", IdentifierType: "uin", Challenge: "otp-canary", Binding: binding()})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestAuthenticationAndConsentContract(t *testing.T) {
	f := newFixture(t)
	a := authenticate(t, f)
	if a.Subject == "subject-canary" || len(a.Subject) != 43 {
		t.Fatal("subject is not a PSUT")
	}
	attrs, e := f.p.GetAttributes(context.Background(), a.Context, binding(), []string{"given_name", "gender", "email", "operatorNote", "sub"})
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(attrs, map[string]any{"given_name": "Ada", "gender": "female", "sub": a.Subject}) {
		t.Fatalf("wrong attribute keys: %v", reflect.ValueOf(attrs).MapKeys())
	}
	if f.mintCalls.Load() != 1 || f.lookupCalls.Load() != 2 {
		t.Fatal("wrong calls")
	}
	for _, v := range f.p.SupportedClaims() {
		if v == "email" {
			t.Fatal("unprovisioned inventory claim")
		}
	}
	if _, e = f.p.GetAttributes(context.Background(), a.Context, binding(), nil); e != ErrInvalidRequest {
		t.Fatal("nil consent not rejected")
	}
	attrs, e = f.p.GetAttributes(context.Background(), a.Context, binding(), []string{})
	if e != nil || len(attrs) != 0 || f.lookupCalls.Load() != 2 {
		t.Fatal("empty consent disclosed")
	}
}
func TestChallengeFailureNoDownstreamCalls(t *testing.T) {
	f := newFixture(t)
	f.p.verifier = &verifierStub{verifyErr: fmt.Errorf("OTP identifier secret-canary")}
	_, e := f.p.Authenticate(context.Background(), AuthenticationRequest{Identifier: "subject-canary", IdentifierType: "uin", Challenge: "bad", Binding: binding()})
	if e != ErrChallengeFailed || f.mintCalls.Load() != 0 || f.lookupCalls.Load() != 0 {
		t.Fatal("bad challenge reached downstream")
	}
}
func TestChallengeCancellationNoDownstreamCalls(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel", "cancel-with-success", "wrapped-deadline", "wrapped-cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.p.config.HTTP.TimeoutSeconds = 1
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v := &verifierStub{verifyFn: func(callCtx context.Context) error {
				switch mode {
				case "wrapped-deadline":
					return fmt.Errorf("verification interrupted: %w", context.DeadlineExceeded)
				case "wrapped-cancel":
					return fmt.Errorf("verification interrupted: %w", context.Canceled)
				case "cancel", "cancel-with-success":
					cancel()
				}
				<-callCtx.Done()
				if mode == "cancel-with-success" {
					return nil
				}
				return callCtx.Err()
			}}
			f.p.verifier = v
			result, err := f.p.Authenticate(ctx, AuthenticationRequest{Identifier: "subject-canary", IdentifierType: "uin", Challenge: "valid", Binding: binding()})
			if err != ErrUnavailable {
				t.Fatalf("want unavailable, got %v", err)
			}
			if v.calls.Load() != 1 || f.mintCalls.Load() != 0 || f.lookupCalls.Load() != 0 || result.Subject != "" || result.Context != nil {
				t.Fatal("interrupted verification produced authentication state or downstream traffic")
			}
		})
	}
}
func TestRestoredContextBindingsAndExpiry(t *testing.T) {
	f := newFixture(t)
	a := authenticate(t, f)
	raw, _ := json.Marshal(a.Context)
	var restored map[string]any
	_ = json.Unmarshal(raw, &restored)
	subject, e := f.p.Subject(context.Background(), restored, binding())
	if e != nil || subject != a.Subject {
		t.Fatal("JSON state round trip failed")
	}
	for _, b := range []Binding{{"other", "client", "transaction"}, {"rp", "other", "transaction"}, {"rp", "client", "other"}} {
		if _, e = f.p.GetAttributes(context.Background(), restored, b, []string{"given_name"}); e != ErrContextInvalid {
			t.Fatal("binding mismatch accepted")
		}
	}
	for _, change := range []func(map[string]any){func(s map[string]any) { s["version"] = 2 }, func(s map[string]any) { s["expires_at"] = 1e90 }, func(s map[string]any) { s["extra"] = "value" }, func(s map[string]any) { s["subject_type"] = "other" }, func(s map[string]any) { s["issued_at"] = time.Now().Add(time.Minute).Unix() }} {
		var s map[string]any
		_ = json.Unmarshal(raw, &s)
		change(s)
		if _, e = f.p.GetAttributes(context.Background(), s, binding(), []string{"given_name"}); e != ErrContextInvalid {
			t.Fatal("malformed context accepted")
		}
	}
	f.p.now = func() time.Time { return time.Now().Add(301 * time.Second) }
	if _, e = f.p.GetAttributes(context.Background(), restored, binding(), []string{"given_name"}); e != ErrContextExpired {
		t.Fatal("expired state accepted")
	}
	if f.lookupCalls.Load() != 1 {
		t.Fatal("invalid context called downstream")
	}
}
func TestPSUTTupleUnambiguousAndPartnerSpecific(t *testing.T) {
	f := newFixture(t)
	s := authContext{RelyingPartyID: "a:b", ClientID: "c", IdentifierType: "uin", Identifier: "d"}
	one := f.p.psut(s)
	s.RelyingPartyID = "a"
	s.ClientID = "b:c"
	if one == f.p.psut(s) {
		t.Fatal("delimiter collision")
	}
	s.Identifier = "other"
	if one == f.p.psut(s) {
		t.Fatal("subject collision")
	}
}
func TestTokenSingleFlight(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := f.p.lookup(context.Background(), "subject-canary", []string{"uin", "status"})
			if e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if f.mintCalls.Load() != 1 {
		t.Fatalf("Mint called %d times", f.mintCalls.Load())
	}
}
func TestProblemClassificationInvalidationAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		code        string
		status      int
		want        error
		invalidates bool
	}{{"lookup.unresolved", 503, ErrSubjectDenied, false}, {"resource.not_found", 401, ErrSubjectDenied, false}, {"authentication.refused", 404, ErrUnavailable, true}, {"source.unavailable", 404, ErrUnavailable, false}, {"unknown", 403, ErrUnavailable, false}} {
		t.Run(tc.code, func(t *testing.T) {
			f := newFixture(t)
			f.handler = func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"code":%q,"detail":"subject-canary token-canary otp-canary"}`, tc.code)
			}
			for i := 0; i < 2; i++ {
				_, e := f.p.lookup(context.Background(), "subject-canary", []string{"uin"})
				if e != tc.want || strings.Contains(e.Error(), "canary") {
					t.Fatal("wrong or sensitive outcome")
				}
			}
			want := int32(1)
			if tc.invalidates {
				want = 2
			}
			if f.mintCalls.Load() != want || f.lookupCalls.Load() != 2 {
				t.Fatal("unexpected replay or token reuse")
			}
		})
	}
}
func TestMalformedBoundedAndRedirectResponses(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":{"domainData":null}}`, `{"data":{"domainData":[]}}`, `{"data":{"domainData":{}}} {}`, strings.Repeat("x", 1025)} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			f := newFixture(t)
			f.p.config.HTTP.MaxResponseBytes = 1024
			f.handler = func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }
			_, e := f.p.lookup(context.Background(), "subject-canary", []string{"uin"})
			if e != ErrUnavailable {
				t.Fatal("invalid response accepted")
			}
		})
	}
	f := newFixture(t)
	f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/leak", http.StatusTemporaryRedirect)
	}
	_, e := f.p.lookup(context.Background(), "subject-canary", []string{"uin"})
	if e != ErrUnavailable || f.lookupCalls.Load() != 0 {
		t.Fatal("redirect followed")
	}
}
func TestRSAAssertionAndKeyValidation(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600)
	k, e := loadKey(path, "rsa-key")
	if e != nil {
		t.Fatal(e)
	}
	token, e := k.assertion("client", "https://mint/token", 100, 200)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		t.Fatal("RSA assertion signature")
	}
	if _, e = loadKey(path, ""); e == nil {
		t.Fatal("missing kid accepted")
	}
}
func TestConfigAndMissingVerifierFailClosed(t *testing.T) {
	f := newFixture(t)
	if _, e := New(f.config); e == nil || e.Error() != "production challenge verifier required" {
		t.Fatal("missing verifier accepted")
	}
	for _, input := range []string{"unknown: secret-canary\n", "demo:\n  static_otp_enabled: false\n  unknown: secret-canary\n", "demo: [broken]\n", "---\n{}\n---\n{}\n"} {
		path := filepath.Join(t.TempDir(), "registry.yaml")
		_ = os.WriteFile(path, []byte(input), 0600)
		_, e := LoadConfig(path)
		if e == nil || strings.Contains(e.Error(), "secret-canary") {
			t.Fatal("YAML not rejected safely")
		}
	}
}

func TestCacheDeadlineFromAcquisitionStartAndCap(t *testing.T) {
	for _, tc := range []struct {
		name           string
		elapsed, after int64
		wantCalls      int32
		wantErr        bool
	}{
		{"cached", 0, 5, 1, false}, {"server lifetime", 5, 6, 2, false}, {"spent during acquisition", 11, 0, 1, true}, {"configured maximum", 0, 21, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			var tick atomic.Int64
			tick.Store(1000)
			f.p.now = func() time.Time { return time.Unix(tick.Load(), 0) }
			f.p.config.Mint.TokenCacheMaxSeconds = 20
			f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
				tick.Add(tc.elapsed)
				expiry := 10
				if tc.name == "configured maximum" {
					expiry = 300
				}
				fmt.Fprintf(w, `{"access_token":"cache-token","token_type":"Bearer","expires_in":%d}`, expiry)
			}
			_, e := f.p.accessToken(context.Background())
			if tc.wantErr {
				if e != ErrUnavailable {
					t.Fatal("expired acquisition returned token")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			tick.Add(tc.after)
			_, e = f.p.accessToken(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if f.mintCalls.Load() != tc.wantCalls {
				t.Fatal("cache deadline not acquisition bounded")
			}
		})
	}
}
func TestCacheWaiterCancellationAndFailure(t *testing.T) {
	f := newFixture(t)
	flight := &tokenFlight{done: make(chan struct{})}
	f.p.acquiring = flight
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := f.p.accessToken(ctx); e != ErrUnavailable {
		t.Fatal("cancellation ignored")
	}
	finished := make(chan error, 1)
	go func() { _, e := f.p.accessToken(context.Background()); finished <- e }()
	flight.err = ErrUnavailable
	close(flight.done)
	if e := <-finished; e != ErrUnavailable {
		t.Fatal("acquisition failure not shared")
	}
	if f.mintCalls.Load() != 0 {
		t.Fatal("waiter retried failed acquisition")
	}
}
func TestMintMalformedTokenAndFreshAssertions(t *testing.T) {
	for _, response := range []string{`{"access_token":"secret-canary","token_type":"Bearer","expires_in":0}`, `{"access_token":"secret-canary","token_type":"Basic","expires_in":3}`, `{"access_token":"secret-canary","token_type":"Bearer","expires_in":1.5}`, `{"access_token":"line\nbreak","token_type":"Bearer","expires_in":3}`, `{"access_token":"x","token_type":"Bearer","expires_in":3} {}`} {
		t.Run(fmt.Sprint(len(response)), func(t *testing.T) {
			f := newFixture(t)
			f.tokenHandler = func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, response) }
			_, e := f.p.lookup(context.Background(), "subject-canary", []string{"uin"})
			if e != ErrUnavailable || f.lookupCalls.Load() != 0 {
				t.Fatal("malformed token released downstream request")
			}
		})
	}
	f := newFixture(t)
	first, e := f.p.key.assertion("client", "https://audience/token", 100, 200)
	if e != nil {
		t.Fatal(e)
	}
	second, e := f.p.key.assertion("client", "https://audience/token", 100, 200)
	if e != nil {
		t.Fatal(e)
	}
	decode := func(s string) map[string]any {
		parts := strings.Split(s, ".")
		b, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		return out
	}
	if decode(first)["jti"] == decode(second)["jti"] {
		t.Fatal("assertion jti reused")
	}
}
func TestMissingAccountFieldAndUnsolicitedProperties(t *testing.T) {
	f := newFixture(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"domainData":{"uin":"subject-canary"}}}`)
	}
	_, e := f.p.Authenticate(context.Background(), AuthenticationRequest{Identifier: "subject-canary", IdentifierType: "uin", Challenge: "otp", Binding: binding()})
	if e != ErrUnavailable {
		t.Fatal("missing account field accepted")
	}
}
func TestDemoIsExplicitAndConfigurationDetachesCaller(t *testing.T) {
	f := newFixture(t)
	otp := filepath.Join(t.TempDir(), "otp")
	_ = os.WriteFile(otp, []byte("123456\n"), 0600)
	c := f.config
	c.Demo = DemoConfig{StaticOTPEnabled: true, StaticOTPFile: otp}
	p, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.verifier.Verify(context.Background(), ChallengeRequest{Challenge: "123456"}); e != nil {
		t.Fatal(e)
	}
	if e = p.verifier.Verify(context.Background(), ChallengeRequest{Challenge: "bad"}); e != ErrChallengeFailed {
		t.Fatal("bad demo OTP accepted")
	}
	c.ClaimMap["extra"] = "operatorNote"
	c.BREG.ProvisionedFields[0] = "operatorNote"
	if _, ok := p.config.ClaimMap["extra"]; ok || p.config.BREG.ProvisionedFields[0] == "operatorNote" {
		t.Fatal("caller mutated policy")
	}
}

func TestConfigFieldsNameOnlyAndProtocolClaimProtection(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*Config)
		field  string
	}{
		{"endpoint", func(c *Config) { c.Mint.TokenEndpoint = "secret-canary" }, "mint.token_endpoint"},
		{"projection", func(c *Config) { c.BREG.AccountCheckFields = []string{"operatorNote"} }, "breg.account_check_fields"},
		{"protocol", func(c *Config) { c.ClaimMap = map[string]string{"iss": "givenName"} }, "claim_map"},
		{"subject", func(c *Config) { c.ClaimMap = map[string]string{"sub": "uin"} }, "claim_map"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := f.config
			tc.change(&c)
			_, e := New(c, WithChallengeVerifier(&verifierStub{}))
			if e == nil || !strings.Contains(e.Error(), tc.field) || strings.Contains(e.Error(), "secret-canary") {
				t.Fatal("configuration diagnosis missing field or discloses value")
			}
		})
	}
}

func TestMalformedSigningKeyMetadata(t *testing.T) {
	f := newFixture(t)
	raw, e := os.ReadFile(f.config.Mint.PrivateKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(map[string]any){func(j map[string]any) { j["alg"] = "none" }, func(j map[string]any) { j["use"] = "enc" }, func(j map[string]any) { j["key_ops"] = []string{"verify"} }, func(j map[string]any) { j["kid"] = "" }, func(j map[string]any) { j["crv"] = "P-384" }, func(j map[string]any) { j["d"] = "AQ" }} {
		var j map[string]any
		_ = json.Unmarshal(raw, &j)
		change(j)
		b, _ := json.Marshal(j)
		path := filepath.Join(t.TempDir(), "jwk.json")
		_ = os.WriteFile(path, b, 0600)
		if _, e := loadKey(path, ""); e == nil {
			t.Fatal("invalid signing key accepted")
		}
	}
	weak, e := rsa.GenerateKey(rand.Reader, 1024)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "weak.pem")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}), 0600)
	if _, e = loadKey(path, "weak"); e == nil {
		t.Fatal("weak RSA key accepted")
	}
}
func TestHTTPDeadlineIsGeneric(t *testing.T) {
	f := newFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	f.handler = func(w http.ResponseWriter, r *http.Request) { close(entered); <-release }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := f.p.lookup(ctx, "subject-canary", []string{"uin"}); done <- e }()
	<-entered
	cancel()
	if e := <-done; e != ErrUnavailable {
		t.Fatal("transport error not classified")
	}
}
func TestJSONNumbersKeepPrecision(t *testing.T) {
	var out map[string]any
	if e := decodeJSON([]byte(`{"number":9007199254740993}`), &out); e != nil {
		t.Fatal(e)
	}
	if out["number"] != json.Number("9007199254740993") {
		t.Fatal("JSON number lost precision")
	}
}
