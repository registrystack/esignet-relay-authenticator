package provider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

const contextTTL = 300 * time.Second

type Provider struct {
	config        Config
	verifier      ChallengeVerifier
	secret        []byte
	key           assertionKey
	http          *http.Client
	now           func() time.Time
	mu            sync.Mutex
	token         []byte
	tokenDeadline time.Time
	acquiring     *tokenFlight
}

func New(c Config, options ...Option) (*Provider, error) {
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	// Detach mutable configuration from the caller.
	m := make(map[string]string, len(c.ClaimMap))
	for k, v := range c.ClaimMap {
		m[k] = v
	}
	c.ClaimMap = m
	c.BREG.ProvisionedFields = append([]string(nil), c.BREG.ProvisionedFields...)
	c.BREG.AccountCheckFields = append([]string(nil), c.BREG.AccountCheckFields...)
	c.TokenClient.Scopes = append([]string(nil), c.TokenClient.Scopes...)
	p := &Provider{config: c, now: time.Now}
	for _, o := range options {
		if o != nil {
			o(p)
		}
	}
	if p.verifier == nil {
		if c.Demo.Mailpit.Enabled {
			p.verifier = newMailpitVerifier(c.Demo.Mailpit, time.Duration(c.HTTP.TimeoutSeconds)*time.Second)
		} else if !c.Demo.StaticOTPEnabled {
			return nil, errors.New("production challenge verifier required")
		} else {
			otp, e := readBounded(c.Demo.StaticOTPFile, 1024)
			if e != nil || len(bytes.TrimSpace(otp)) == 0 {
				return nil, errors.New("demo OTP file invalid")
			}
			p.verifier = &staticVerifier{otp: bytes.TrimSpace(otp)}
		}
	}
	var e error
	p.secret, e = readBounded(c.PSUTSecretFile, 4096)
	if e != nil || len(p.secret) < 32 {
		return nil, errors.New("PSUT secret file must contain at least 32 bytes")
	}
	p.key, e = loadKey(c.TokenClient.PrivateKeyFile, c.TokenClient.KeyID)
	if e != nil {
		clear(p.secret)
		return nil, e
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.HTTP.CAFile != "" {
		b, err := readBounded(c.HTTP.CAFile, 1<<20)
		if err != nil {
			return nil, errors.New("CA file unavailable")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("CA file invalid")
		}
		tlsConfig.RootCAs = roots
	}
	timeout := time.Duration(c.HTTP.TimeoutSeconds) * time.Second
	p.http = &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxIdleConns: 10, MaxIdleConnsPerHost: 5, IdleConnTimeout: 90 * time.Second}}
	return p, nil
}
func validBinding(b Binding) bool {
	return validText(b.RelyingPartyID) && validText(b.ClientID) && validText(b.TransactionID)
}
func validText(s string) bool { return !blank(s) && len(s) <= 4096 }
func (p *Provider) validSubject(id, kind string) bool {
	return validText(id) && kind == p.config.SubjectIDType
}
func (p *Provider) Authenticate(ctx context.Context, r AuthenticationRequest) (AuthenticationResult, error) {
	if !p.validSubject(r.Identifier, r.IdentifierType) || !validBinding(r.Binding) || !validText(r.Challenge) {
		return AuthenticationResult{}, ErrInvalidRequest
	}
	if ctx.Err() != nil {
		return AuthenticationResult{}, ErrUnavailable
	}
	verifyCtx, cancel := context.WithTimeout(ctx, time.Duration(p.config.HTTP.TimeoutSeconds)*time.Second)
	defer cancel()
	verifyErr := p.verifier.Verify(verifyCtx, r)
	if verifyCtx.Err() != nil || errors.Is(verifyErr, context.DeadlineExceeded) || errors.Is(verifyErr, context.Canceled) {
		return AuthenticationResult{}, ErrUnavailable
	}
	if verifyErr != nil {
		return AuthenticationResult{}, ErrChallengeFailed
	}
	fields, err := p.lookup(ctx, r.Identifier, p.config.BREG.AccountCheckFields)
	if err != nil {
		return AuthenticationResult{}, err
	}
	for _, field := range p.config.BREG.AccountCheckFields {
		if v, ok := fields[field]; !ok || v == nil {
			return AuthenticationResult{}, ErrUnavailable
		}
	}
	if v, ok := fields[p.config.BREG.SelectorField]; ok && v != r.Identifier {
		return AuthenticationResult{}, ErrUnavailable
	}
	now := p.now()
	state := authContext{Version: 1, Identifier: r.Identifier, IdentifierType: r.IdentifierType, RelyingPartyID: r.Binding.RelyingPartyID, ClientID: r.Binding.ClientID, TransactionID: r.Binding.TransactionID, IssuedAt: now.Unix(), ExpiresAt: now.Add(contextTTL).Unix()}
	b, _ := json.Marshal(state)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return AuthenticationResult{Subject: p.psut(state), Context: out}, nil
}
func (p *Provider) SendOTP(ctx context.Context, r OTPRequest) error {
	if !p.validSubject(r.Identifier, r.IdentifierType) || !validBinding(r.Binding) || len(r.Channels) == 0 {
		return ErrInvalidRequest
	}
	for _, ch := range r.Channels {
		if ch != "email" && ch != "phone" {
			return ErrInvalidRequest
		}
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(p.config.HTTP.TimeoutSeconds)*time.Second)
	defer cancel()
	if p.verifier.SendOTP(callCtx, r) != nil || callCtx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
func (p *Provider) SupportedOTPChannels() []string {
	if p.config.Demo.Mailpit.Enabled {
		return []string{"email"}
	}
	return []string{"email", "phone"}
}
func (p *Provider) SupportedClaims() []string {
	claims := []string{}
	for k, v := range p.config.ClaimMap {
		if v == "$psut" || contains(p.config.BREG.ProvisionedFields, v) {
			claims = append(claims, k)
		}
	}
	sort.Strings(claims)
	return claims
}
func (p *Provider) GetAttributes(ctx context.Context, state map[string]any, b Binding, approved []string) (map[string]any, error) {
	if approved == nil {
		return nil, ErrInvalidRequest
	}
	s, err := p.restore(state, b)
	if err != nil {
		return nil, err
	}
	result := map[string]any{}
	fields := []string{}
	for _, claim := range approved {
		source, ok := p.config.ClaimMap[claim]
		if ok && source != "$psut" && contains(p.config.BREG.ProvisionedFields, source) && !contains(fields, source) {
			fields = append(fields, source)
		}
	}
	values := map[string]any{}
	if len(fields) > 0 {
		values, err = p.lookup(ctx, s.Identifier, fields)
		if err != nil {
			return nil, err
		}
	}
	for _, claim := range approved {
		source, ok := p.config.ClaimMap[claim]
		if !ok {
			continue
		}
		if source == "$psut" {
			result[claim] = p.psut(s)
		} else if contains(fields, source) {
			if v, ok := values[source]; ok {
				result[claim] = v
			}
		}
	}
	return result, nil
}
func (p *Provider) Subject(ctx context.Context, state map[string]any, b Binding) (string, error) {
	if ctx.Err() != nil {
		return "", ErrUnavailable
	}
	s, e := p.restore(state, b)
	if e != nil {
		return "", e
	}
	return p.psut(s), nil
}

// authContext is server-held eSignet session state, not a bearer credential.
// It must not be accepted from an HTTP caller or exposed to relying parties.
type authContext struct {
	Version        int    `json:"version"`
	Identifier     string `json:"subject_locator"`
	IdentifierType string `json:"subject_type"`
	RelyingPartyID string `json:"relying_party_id"`
	ClientID       string `json:"client_id"`
	TransactionID  string `json:"transaction_id"`
	IssuedAt       int64  `json:"issued_at"`
	ExpiresAt      int64  `json:"expires_at"`
}

func (p *Provider) restore(state map[string]any, b Binding) (authContext, error) {
	var s authContext
	if state == nil || !validBinding(b) {
		return s, ErrContextInvalid
	}
	raw, e := json.Marshal(state)
	if e != nil || len(raw) > 32<<10 {
		return s, ErrContextInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || s.Version != 1 || !p.validSubject(s.Identifier, s.IdentifierType) || s.RelyingPartyID != b.RelyingPartyID || s.ClientID != b.ClientID || s.TransactionID != b.TransactionID {
		return authContext{}, ErrContextInvalid
	}
	now := p.now().Unix()
	if s.IssuedAt <= 0 || s.IssuedAt > now || s.ExpiresAt <= s.IssuedAt || s.ExpiresAt-s.IssuedAt > int64(contextTTL/time.Second) {
		return authContext{}, ErrContextInvalid
	}
	if s.ExpiresAt <= now {
		return authContext{}, ErrContextExpired
	}
	return s, nil
}
func (p *Provider) psut(s authContext) string {
	tuple, _ := json.Marshal([]string{"registry-psut-v1", s.RelyingPartyID, s.ClientID, s.IdentifierType, s.Identifier})
	mac := hmac.New(sha256.New, p.secret)
	_, _ = mac.Write(tuple)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func contains(items []string, item string) bool {
	for _, v := range items {
		if v == item {
			return true
		}
	}
	return false
}

type staticVerifier struct{ otp []byte }

func (v *staticVerifier) Verify(ctx context.Context, r ChallengeRequest) error {
	if ctx.Err() != nil || subtle.ConstantTimeCompare(v.otp, []byte(r.Challenge)) != 1 {
		return ErrChallengeFailed
	}
	return nil
}
func (v *staticVerifier) SendOTP(ctx context.Context, _ OTPRequest) error { return ctx.Err() }

// String prevents accidental formatting from exposing provider state or secrets.
func (p *Provider) String() string { return "registry identity provider" }

func (p *Provider) GoString() string { return p.String() }
