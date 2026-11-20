package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type tokenFlight struct {
	done chan struct{}
	err  error
}

// tokenSource obtains and caches access tokens for one resource and scope set.
// Every source authenticates as the same client with the same private key.
type tokenSource struct {
	owner         *Provider
	resource      string
	scopes        []string
	mu            sync.Mutex
	token         []byte
	tokenDeadline time.Time
	acquiring     *tokenFlight
}

func newTokenSource(owner *Provider, resource string, scopes []string) tokenSource {
	return tokenSource{owner: owner, resource: resource, scopes: append([]string(nil), scopes...)}
}

// accessToken coalesces acquisition while allowing waiters to honor cancellation.
// A failed acquisition is never cached; the initiating call is never replayed.
func (t *tokenSource) accessToken(ctx context.Context) (string, error) {
	for {
		if ctx.Err() != nil {
			return "", ErrUnavailable
		}
		t.mu.Lock()
		if len(t.token) > 0 && t.owner.now().Before(t.tokenDeadline) {
			token := string(t.token)
			t.mu.Unlock()
			return token, nil
		}
		clear(t.token)
		t.token = nil
		if wait := t.acquiring; wait != nil {
			t.mu.Unlock()
			select {
			case <-wait.done:
				if wait.err != nil {
					return "", wait.err
				}
				continue
			case <-ctx.Done():
				return "", ErrUnavailable
			}
		}
		flight := &tokenFlight{done: make(chan struct{})}
		t.acquiring = flight
		t.mu.Unlock()
		start := t.owner.now()
		token, lifetime, err := t.acquire(ctx, start)
		t.mu.Lock()
		if err == nil {
			deadline := start.Add(lifetime)
			if !t.owner.now().Before(deadline) {
				err = ErrUnavailable
			} else {
				t.token = []byte(token)
				t.tokenDeadline = deadline
			}
		}
		flight.err = err
		t.acquiring = nil
		close(flight.done)
		t.mu.Unlock()
		if err != nil {
			return "", err
		}
		return token, nil
	}
}
func (t *tokenSource) invalidate(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if string(t.token) == token {
		clear(t.token)
		t.token = nil
		t.tokenDeadline = time.Time{}
	}
}
func (t *tokenSource) acquire(ctx context.Context, start time.Time) (string, time.Duration, error) {
	p := t.owner
	c := p.config.TokenClient
	assertion, e := p.key.assertion(c.ClientID, c.AssertionAudience, start.Unix(), start.Unix()+int64(c.AssertionTTLSeconds))
	if e != nil {
		return "", 0, ErrUnavailable
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.ClientID}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}, "resource": {t.resource}, "scope": {strings.Join(t.scopes, " ")}}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenEndpoint, strings.NewReader(form.Encode()))
	if e != nil {
		return "", 0, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	status, body, e := p.request(req)
	if e != nil || status != http.StatusOK {
		return "", 0, ErrUnavailable
	}
	var out struct {
		AccessToken string  `json:"access_token"`
		TokenType   string  `json:"token_type"`
		ExpiresIn   int64   `json:"expires_in"`
		Scope       *string `json:"scope"`
	}
	if decodeJSON(body, &out) != nil || out.AccessToken == "" || len(out.AccessToken) > 64<<10 || !strings.EqualFold(out.TokenType, "Bearer") || out.ExpiresIn <= 0 {
		return "", 0, ErrUnavailable
	}
	if out.Scope != nil {
		granted, valid := parseScope(*out.Scope)
		if !valid {
			return "", 0, ErrUnavailable
		}
		for _, requested := range t.scopes {
			if !contains(granted, requested) {
				return "", 0, ErrUnavailable
			}
		}
	}
	for _, r := range out.AccessToken {
		if r <= 32 || r >= 127 {
			return "", 0, ErrUnavailable
		}
	}
	max := int64(c.TokenCacheMaxSeconds)
	if out.ExpiresIn > max {
		out.ExpiresIn = max
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}
func (p *Provider) lookup(ctx context.Context, id string, fields []string) (map[string]any, error) {
	if len(fields) == 0 {
		return nil, ErrInvalidRequest
	}
	token, e := p.tokens.accessToken(ctx)
	if e != nil {
		return nil, ErrUnavailable
	}
	u, e := url.Parse(strings.TrimRight(p.config.BREG.BaseURL, "/") + "/v1/records/" + url.PathEscape(p.config.BREG.Route) + ":lookup")
	if e != nil {
		return nil, ErrUnavailable
	}
	query := url.Values{"$select": {strings.Join(fields, ",")}}
	if p.config.BREG.AccessProfile != "" {
		query.Set("accessProfile", p.config.BREG.AccessProfile)
	}
	u.RawQuery = query.Encode()
	body, _ := json.Marshal(map[string]any{"selector": p.config.BREG.Selector, "values": map[string]string{p.config.BREG.SelectorField: id}})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if e != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	status, raw, e := p.request(req)
	if e != nil {
		return nil, ErrUnavailable
	}
	if status != http.StatusOK {
		var problem struct {
			Code string `json:"code"`
		}
		if decodeJSON(raw, &problem) != nil {
			return nil, ErrUnavailable
		}
		switch problem.Code {
		case "lookup.unresolved", "resource.not_found":
			return nil, ErrSubjectDenied
		case "authentication.refused":
			p.tokens.invalidate(token)
		}
		return nil, ErrUnavailable
	}
	var out struct {
		Data struct {
			DomainData map[string]any `json:"domainData"`
		} `json:"data"`
	}
	if decodeJSON(raw, &out) != nil || out.Data.DomainData == nil {
		return nil, ErrUnavailable
	}
	return out.Data.DomainData, nil
}
func (p *Provider) request(req *http.Request) (int, []byte, error) {
	response, e := p.http.Do(req)
	if e != nil {
		return 0, nil, ErrUnavailable
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, p.config.HTTP.MaxResponseBytes+1))
	if e != nil || int64(len(raw)) > p.config.HTTP.MaxResponseBytes {
		return 0, nil, ErrUnavailable
	}
	return response.StatusCode, raw, nil
}
func decodeJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e := d.Decode(out); e != nil {
		return ErrUnavailable
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return ErrUnavailable
	}
	return nil
}
