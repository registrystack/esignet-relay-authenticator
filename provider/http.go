package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type tokenFlight struct {
	done chan struct{}
	err  error
}

// accessToken coalesces acquisition while allowing waiters to honor cancellation.
// A failed acquisition is never cached; the initiating call is never replayed.
func (p *Provider) accessToken(ctx context.Context) (string, error) {
	for {
		if ctx.Err() != nil {
			return "", ErrUnavailable
		}
		p.mu.Lock()
		if len(p.token) > 0 && p.now().Before(p.tokenDeadline) {
			token := string(p.token)
			p.mu.Unlock()
			return token, nil
		}
		clear(p.token)
		p.token = nil
		if wait := p.acquiring; wait != nil {
			p.mu.Unlock()
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
		p.acquiring = flight
		p.mu.Unlock()
		start := p.now()
		token, lifetime, err := p.acquire(ctx, start)
		p.mu.Lock()
		if err == nil {
			deadline := start.Add(lifetime)
			if !p.now().Before(deadline) {
				err = ErrUnavailable
			} else {
				p.token = []byte(token)
				p.tokenDeadline = deadline
			}
		}
		flight.err = err
		p.acquiring = nil
		close(flight.done)
		p.mu.Unlock()
		if err != nil {
			return "", err
		}
		return token, nil
	}
}
func (p *Provider) invalidate(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if string(p.token) == token {
		clear(p.token)
		p.token = nil
		p.tokenDeadline = time.Time{}
	}
}
func (p *Provider) acquire(ctx context.Context, start time.Time) (string, time.Duration, error) {
	assertion, e := p.key.assertion(p.config.Mint.ClientID, p.config.Mint.AssertionAudience, start.Unix(), start.Unix()+int64(p.config.Mint.AssertionTTLSeconds))
	if e != nil {
		return "", 0, ErrUnavailable
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, p.config.Mint.TokenEndpoint, strings.NewReader(form.Encode()))
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
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if decodeJSON(body, &out) != nil || out.AccessToken == "" || len(out.AccessToken) > 64<<10 || !strings.EqualFold(out.TokenType, "Bearer") || out.ExpiresIn <= 0 {
		return "", 0, ErrUnavailable
	}
	for _, r := range out.AccessToken {
		if r <= 32 || r >= 127 {
			return "", 0, ErrUnavailable
		}
	}
	max := int64(p.config.Mint.TokenCacheMaxSeconds)
	if out.ExpiresIn > max {
		out.ExpiresIn = max
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}
func (p *Provider) lookup(ctx context.Context, id string, fields []string) (map[string]any, error) {
	if len(fields) == 0 {
		return nil, ErrInvalidRequest
	}
	token, e := p.accessToken(ctx)
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
			p.invalidate(token)
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
