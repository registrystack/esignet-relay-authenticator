// Package breg adapts the standalone BREG identity provider to eSignet.
package breg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"

	core "github.com/registrystack/esignet-relay-authenticator/provider"
	"github.com/mosip/esignet/internal/clientmgmt"
	"github.com/mosip/esignet/internal/engine/shared"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

const transactionKey = "provider_ext_TransactionID"

type clientResolver interface {
	GetClient(context.Context, string) (clientmgmt.ClientResponse, error)
}

type identityProvider interface {
	SendOTP(context.Context, core.OTPRequest) error
	Authenticate(context.Context, core.AuthenticationRequest) (core.AuthenticationResult, error)
	GetAttributes(context.Context, map[string]any, core.Binding, []string) (map[string]any, error)
}

type authenticator struct {
	identity       identityProvider
	clients        clientResolver
	identifierType string
	channels       []string
}

var _ shared.ConsolidatedAuthnProvider = (*authenticator)(nil)

// Init constructs the provider from its mounted configuration. The host owns
// OAuth clients, encrypted flow storage, consent records, and token cryptography.
func Init(clients *clientmgmt.Service) (shared.ConsolidatedAuthnProvider, providers.ObservabilityProvider, error) {
	cfg, err := core.LoadConfigFromEnv()
	if err != nil {
		return nil, nil, err
	}
	identity, err := core.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	return &authenticator{identity: identity, clients: clients,
		identifierType: cfg.SubjectIDType, channels: identity.SupportedOTPChannels()}, shared.NewNoopAuditor(), nil
}

func (p *authenticator) binding(ctx context.Context, metadata map[string][]string, requireTransaction bool) (core.Binding, *common.ServiceError) {
	ids := metadata["initiator_query_client_id"]
	if len(ids) != 1 || ids[0] == "" || p.clients == nil {
		return core.Binding{}, shared.InvalidRequestError
	}
	client, err := p.clients.GetClient(ctx, ids[0])
	if err != nil {
		if errors.Is(err, clientmgmt.ErrClientNotFound) {
			return core.Binding{}, shared.ClientNotFoundError
		}
		return core.Binding{}, shared.InternalServerError
	}
	if client.ClientID != ids[0] || client.RpID == "" {
		return core.Binding{}, shared.InvalidRequestError
	}
	binding := core.Binding{ClientID: client.ClientID, RelyingPartyID: client.RpID}
	transactions := metadata[transactionKey]
	if len(transactions) == 1 && transactions[0] != "" {
		binding.TransactionID = transactions[0]
	} else if requireTransaction || len(transactions) != 0 {
		return core.Binding{}, shared.InvalidRequestError
	}
	return binding, nil
}

func (p *authenticator) SendOTP(ctx context.Context, identifiers map[string]any, metadata *providers.AuthnMetadata) (*shared.SendOTPResult, *common.ServiceError) {
	if metadata == nil {
		return nil, shared.InvalidRequestError
	}
	identifier, ok := identifiers["username"].(string)
	if !ok || identifier == "" {
		return nil, shared.InvalidRequestError
	}
	binding, svcErr := p.binding(ctx, metadata.RuntimeMetadata, false)
	if svcErr != nil {
		return nil, svcErr
	}
	if binding.TransactionID == "" {
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, shared.InternalServerError
		}
		binding.TransactionID = hex.EncodeToString(entropy[:])
	}
	if err := p.identity.SendOTP(ctx, core.OTPRequest{Identifier: identifier, IdentifierType: p.identifierType,
		Binding: binding, Channels: append([]string(nil), p.channels...)}); err != nil {
		return nil, providerError(err)
	}
	return &shared.SendOTPResult{TransactionID: binding.TransactionID}, nil
}

func (p *authenticator) Authenticate(ctx context.Context, identifiers, credentials map[string]any, metadata *providers.AuthnMetadata) (*providers.AuthnResult, *common.ServiceError) {
	if metadata == nil {
		return nil, shared.InvalidRequestError
	}
	identifier, idOK := identifiers["username"].(string)
	challenge, otpOK := credentials["otp"].(string)
	if !idOK || !otpOK || identifier == "" || challenge == "" {
		return nil, shared.InvalidRequestError
	}
	// This integration supports exactly one authentication method.
	if len(credentials) != 1 {
		return nil, shared.InvalidRequestError
	}
	binding, svcErr := p.binding(ctx, metadata.RuntimeMetadata, true)
	if svcErr != nil {
		return nil, svcErr
	}
	result, err := p.identity.Authenticate(ctx, core.AuthenticationRequest{
		Identifier: identifier, IdentifierType: p.identifierType, Challenge: challenge, Binding: binding})
	if err != nil {
		return nil, providerError(err)
	}
	if result.Subject == "" || result.Context == nil {
		return nil, shared.InternalServerError
	}
	return &providers.AuthnResult{EntityReference: &providers.EntityReference{EntityID: result.Subject},
		AttributeToken: result.Context}, nil
}

func (p *authenticator) GetAttributes(ctx context.Context, token any, requested *providers.RequestedAttributes, metadata *providers.GetAttributesMetadata) (*providers.AttributesResponse, *common.ServiceError) {
	// The host probes prerequisites before consent using nil. An error preserves
	// its lazy attribute token; successful empty attributes would consume it.
	if requested == nil || metadata == nil {
		return nil, shared.InvalidRequestError
	}
	if len(requested.Verifications) != 0 {
		return nil, shared.InvalidRequestError
	}
	state, ok := token.(map[string]any)
	if !ok || state == nil {
		return nil, shared.InvalidRequestError
	}
	binding, svcErr := p.binding(ctx, metadata.RuntimeMetadata, true)
	if svcErr != nil {
		return nil, svcErr
	}
	names := make([]string, 0, len(requested.Attributes))
	for name, constraint := range requested.Attributes {
		if constraint != nil {
			return nil, shared.InvalidRequestError
		}
		names = append(names, name)
	}
	sort.Strings(names)
	values, err := p.identity.GetAttributes(ctx, state, binding, names)
	if err != nil {
		return nil, providerError(err)
	}
	result := &providers.AttributesResponse{Attributes: make(map[string]*providers.AttributeResponse)}
	for _, name := range names {
		if value, exists := values[name]; exists {
			result.Attributes[name] = &providers.AttributeResponse{Value: value}
		}
	}
	return result, nil
}

func providerError(err error) *common.ServiceError {
	if errors.Is(err, core.ErrUnavailable) {
		return shared.InternalServerError
	}
	if errors.Is(err, core.ErrInvalidRequest) {
		return shared.InvalidRequestError
	}
	if errors.Is(err, core.ErrChallengeFailed) || errors.Is(err, core.ErrSubjectDenied) ||
		errors.Is(err, core.ErrContextInvalid) || errors.Is(err, core.ErrContextExpired) {
		return shared.AuthenticationFailedError
	}
	return shared.InternalServerError
}

func (*authenticator) GetEntityReference(context.Context, any) (*providers.EntityReference, *common.ServiceError) {
	// Authentication returns the resolved reference, so no identity lookup is needed here.
	return nil, shared.InvalidRequestError
}
func (*authenticator) InitiateAuthentication(context.Context, string, any, *providers.AuthnMetadata) (any, *common.ServiceError) {
	return nil, shared.NotImplementedError
}
func (*authenticator) InitiateEnrollment(context.Context, string, any, *providers.AuthnMetadata) (any, *common.ServiceError) {
	return nil, shared.NotImplementedError
}
func (*authenticator) Enroll(context.Context, map[string]any, map[string]any, *providers.AuthnMetadata) (*providers.AuthnResult, *common.ServiceError) {
	return nil, shared.NotImplementedError
}
