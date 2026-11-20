// Package provider authenticates challenges and obtains consented attributes from BREG.
// It contains no eSignet runtime types and never signs protocol responses.
package provider

import (
	"context"
	"errors"
)

var (
	ErrInvalidRequest  = errors.New("registry_auth_invalid_request")
	ErrChallengeFailed = errors.New("registry_auth_challenge_failed")
	ErrSubjectDenied   = errors.New("registry_auth_subject_denied")
	ErrUnavailable     = errors.New("registry_auth_unavailable")
	ErrContextInvalid  = errors.New("registry_auth_context_invalid")
	ErrContextExpired  = errors.New("registry_auth_context_expired")
)

type Binding struct{ RelyingPartyID, ClientID, TransactionID string }
type ChallengeRequest struct {
	Identifier, IdentifierType, Challenge string
	Binding                               Binding
}
type AuthenticationRequest = ChallengeRequest
type OTPRequest struct {
	Identifier, IdentifierType string
	Binding                    Binding
	Channels                   []string
}

// ChallengeVerifier is supplied by the deployment's authentication integration.
// Implementations must honor cancellation and never log identifiers or challenges.
type ChallengeVerifier interface {
	Verify(context.Context, ChallengeRequest) error
	SendOTP(context.Context, OTPRequest) error
}
type AuthenticationResult struct {
	Subject string
	Context map[string]any
}
type Option func(*Provider)

func WithChallengeVerifier(v ChallengeVerifier) Option { return func(p *Provider) { p.verifier = v } }

// OperatorEvent names a condition an operator may need to act on. It carries no
// code, contact, identifier or Messaging response.
type OperatorEvent string

const (
	// EventSendRefused: Registry Messaging refused a message, so no message went out.
	EventSendRefused OperatorEvent = "send-refused"
	// EventSendFailed: a message could not be handed to Registry Messaging and its outcome is unknown.
	EventSendFailed OperatorEvent = "send-failed"
	// EventSendDropped: too many sends were in flight, so a message was not sent.
	EventSendDropped OperatorEvent = "send-dropped"
	// EventLimiterFull: the per-person limiter reached its bound and refused a request.
	EventLimiterFull OperatorEvent = "limiter-full"
	// EventStoreFull: the pending challenge store reached its bound and refused a request.
	EventStoreFull OperatorEvent = "store-full"
)

// WithOperatorSignal reports operator events. The function is called from
// several goroutines, must not block, and receives only the event kind. A
// sign-in code that is silently not sent is visible nowhere else.
func WithOperatorSignal(f func(OperatorEvent)) Option { return func(p *Provider) { p.signal = f } }
