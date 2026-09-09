package breg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	core "github.com/registrystack/esignet-relay-authenticator/provider"
	"github.com/mosip/esignet/internal/clientmgmt"
	"github.com/mosip/esignet/internal/engine/shared"
	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

type fakeClients struct{ err error }

func (f fakeClients) GetClient(_ context.Context, id string) (clientmgmt.ClientResponse, error) {
	return clientmgmt.ClientResponse{ClientID: id, RpID: "institution-a"}, f.err
}

type fakeIdentity struct {
	sends     []core.OTPRequest
	auths     []core.AuthenticationRequest
	bindings  []core.Binding
	requested [][]string
	err       error
}

func (f *fakeIdentity) SendOTP(_ context.Context, req core.OTPRequest) error {
	f.sends = append(f.sends, req)
	return f.err
}
func (f *fakeIdentity) Authenticate(_ context.Context, req core.AuthenticationRequest) (core.AuthenticationResult, error) {
	f.auths = append(f.auths, req)
	return core.AuthenticationResult{Subject: "pairwise-subject", Context: map[string]any{"version": float64(1), "client": req.Binding.ClientID, "transaction": req.Binding.TransactionID}}, f.err
}
func (f *fakeIdentity) GetAttributes(_ context.Context, state map[string]any, binding core.Binding, names []string) (map[string]any, error) {
	f.bindings = append(f.bindings, binding)
	f.requested = append(f.requested, names)
	if state["client"] != binding.ClientID || state["transaction"] != binding.TransactionID {
		return nil, core.ErrContextInvalid
	}
	return map[string]any{"name": "Example Person", "email": "not-approved@example.test"}, f.err
}

type AdapterSuite struct {
	suite.Suite
	identity *fakeIdentity
	adapter  *authenticator
}

func (s *AdapterSuite) SetupTest() {
	s.identity = &fakeIdentity{}
	s.adapter = &authenticator{identity: s.identity, clients: fakeClients{}, identifierType: "uin", channels: []string{"email"}}
}
func TestAdapterSuite(t *testing.T) { suite.Run(t, new(AdapterSuite)) }
func (s *AdapterSuite) metadata(transaction string) map[string][]string {
	m := map[string][]string{"initiator_query_client_id": {"client-a"}}
	if transaction != "" {
		m[transactionKey] = []string{transaction}
	}
	return m
}
func (s *AdapterSuite) TestOTPToConsentJSONRoundTrip() {
	ctx := context.Background()
	sent, err := s.adapter.SendOTP(ctx, map[string]any{"username": "1234567890"}, &providers.AuthnMetadata{RuntimeMetadata: s.metadata("")})
	s.Require().Nil(err)
	s.Len(sent.TransactionID, 32)
	meta := s.metadata(sent.TransactionID)
	auth, err := s.adapter.Authenticate(ctx, map[string]any{"username": "1234567890"}, map[string]any{"otp": "123456"}, &providers.AuthnMetadata{RuntimeMetadata: meta})
	s.Require().Nil(err)
	s.Equal("pairwise-subject", auth.EntityReference.EntityID)
	s.Nil(auth.Attributes)
	user := providers.AuthUser{}
	user.SetStateFor("default", providers.AuthState{EntityReference: auth.EntityReference, AttributeToken: auth.AttributeToken})
	encoded, marshalErr := json.Marshal(&user)
	s.Require().NoError(marshalErr)
	var restored providers.AuthUser
	s.Require().NoError(json.Unmarshal(encoded, &restored))
	state, ok := restored.StateFor("default")
	s.Require().True(ok)
	attrs, err := s.adapter.GetAttributes(ctx, state.AttributeToken, nil, &providers.GetAttributesMetadata{RuntimeMetadata: meta})
	s.Nil(attrs)
	s.Equal(shared.InvalidRequestError, err)
	s.Empty(s.identity.requested)
	attrs, err = s.adapter.GetAttributes(ctx, state.AttributeToken, &providers.RequestedAttributes{Attributes: map[string]*providers.AttributeMetadataRequest{"name": nil}}, &providers.GetAttributesMetadata{RuntimeMetadata: meta})
	s.Require().Nil(err)
	s.Len(attrs.Attributes, 1)
	s.Equal("Example Person", attrs.Attributes["name"].Value)
	s.Equal(s.identity.sends[0].Binding, s.identity.auths[0].Binding)
	s.Equal(s.identity.auths[0].Binding, s.identity.bindings[0])
	s.Equal([]string{"name"}, s.identity.requested[0])
}
func (s *AdapterSuite) TestEmptyConsentNeverReleasesClaims() {
	state := map[string]any{"client": "client-a", "transaction": "tx"}
	attrs, err := s.adapter.GetAttributes(context.Background(), state, &providers.RequestedAttributes{Attributes: map[string]*providers.AttributeMetadataRequest{}}, &providers.GetAttributesMetadata{RuntimeMetadata: s.metadata("tx")})
	s.Require().Nil(err)
	s.Empty(attrs.Attributes)
	s.Require().Len(s.identity.requested, 1)
	s.NotNil(s.identity.requested[0])
	s.Empty(s.identity.requested[0])
}
func (s *AdapterSuite) TestBindingsCannotMoveAcrossClientsOrTransactions() {
	for _, state := range []map[string]any{{"client": "other", "transaction": "tx"}, {"client": "client-a", "transaction": "other"}} {
		_, err := s.adapter.GetAttributes(context.Background(), state, &providers.RequestedAttributes{}, &providers.GetAttributesMetadata{RuntimeMetadata: s.metadata("tx")})
		s.Equal(shared.AuthenticationFailedError, err)
	}
}
func (s *AdapterSuite) TestMissingOrDuplicateMetadataRejected() {
	for _, meta := range []map[string][]string{nil, s.metadata(""), {"initiator_query_client_id": {"client-a", "other"}, transactionKey: {"tx"}}} {
		_, err := s.adapter.Authenticate(context.Background(), map[string]any{"username": "123"}, map[string]any{"otp": "456"}, &providers.AuthnMetadata{RuntimeMetadata: meta})
		s.Equal(shared.InvalidRequestError, err)
	}
	s.Empty(s.identity.auths)
}
func (s *AdapterSuite) TestUnsupportedFactorsAndConstraintsRejected() {
	_, err := s.adapter.Authenticate(context.Background(), map[string]any{"username": "123"}, map[string]any{"otp": "456", "password": "secret"}, &providers.AuthnMetadata{RuntimeMetadata: s.metadata("tx")})
	s.Equal(shared.InvalidRequestError, err)
	s.Empty(s.identity.auths)
	_, err = s.adapter.GetAttributes(context.Background(), map[string]any{}, &providers.RequestedAttributes{Attributes: map[string]*providers.AttributeMetadataRequest{"name": {}}}, &providers.GetAttributesMetadata{RuntimeMetadata: s.metadata("tx")})
	s.Equal(shared.InvalidRequestError, err)
	s.Empty(s.identity.requested)
}
func (s *AdapterSuite) TestFailuresRemainSanitized() {
	s.identity.err = fmt.Errorf("private backend detail: %w", core.ErrUnavailable)
	_, err := s.adapter.SendOTP(context.Background(), map[string]any{"username": "123"}, &providers.AuthnMetadata{RuntimeMetadata: s.metadata("")})
	s.Equal(shared.InternalServerError, err)
	s.NotContains(err.ErrorDescription.DefaultValue, "private")
	s.adapter.clients = fakeClients{err: errors.New("database private detail")}
	_, err = s.adapter.SendOTP(context.Background(), map[string]any{"username": "123"}, &providers.AuthnMetadata{RuntimeMetadata: s.metadata("")})
	s.Equal(shared.InternalServerError, err)
}

type fakeConsent struct {
	providers.ConsentProvider
	forced       []bool
	deniedBefore bool
	records      int
	recordError  *common.ServiceError
}

func (f *fakeConsent) ResolveConsent(_ context.Context, _, _, _, _ string, _, _, _ []string, _ *providers.AttributesResponse, force bool, _ map[string][]string) (*providers.ConsentPromptData, *common.ServiceError) {
	f.forced = append(f.forced, force)
	if f.deniedBefore && !force {
		return nil, nil
	}
	return &providers.ConsentPromptData{}, nil
}
func (f *fakeConsent) RecordConsent(_ context.Context, _, _, _ string, _ *providers.ConsentDecisions, _ string, _ int64, _ map[string][]string) (*providers.Consent, *common.ServiceError) {
	f.deniedBefore = true
	f.records++
	return &providers.Consent{ID: "consent"}, f.recordError
}
func (s *AdapterSuite) TestEssentialRefusalUsesPinnedEngineErrorCode() {
	denied := &common.ServiceError{Type: common.ClientErrorType, Code: "essential_consent_denied"}
	base := &fakeConsent{recordError: denied}
	wrapped := WithFreshConsent("breg", base)
	record, err := wrapped.RecordConsent(context.Background(), "ou", "app", "subject", &providers.ConsentDecisions{}, "session", 120, nil)
	s.Equal(1, base.records)
	s.Equal("consent", record.ID)
	s.Require().NotNil(err)
	s.Equal("AUTH-CES-1006", err.Code)
	s.Equal(common.ClientErrorType, err.Type)
	s.Equal("essential_consent_denied", denied.Code)
	other := &common.ServiceError{Type: common.ClientErrorType, Code: "consent_record_failed"}
	base.recordError = other
	_, err = wrapped.RecordConsent(context.Background(), "ou", "app", "subject", nil, "session", 120, nil)
	s.Same(other, err)
}
func (s *AdapterSuite) TestFreshConsentAfterPriorOptionalRefusal() {
	base := &fakeConsent{}
	wrapped := WithFreshConsent("breg", base)
	for i := 0; i < 2; i++ {
		prompt, err := wrapped.ResolveConsent(context.Background(), "ou", "app", "app", "subject", nil, []string{"email"}, nil, nil, false, nil)
		s.Require().Nil(err)
		s.NotNil(prompt)
		_, err = wrapped.RecordConsent(context.Background(), "ou", "app", "subject", &providers.ConsentDecisions{}, "", 0, nil)
		s.Require().Nil(err)
	}
	s.Equal([]bool{true, true}, base.forced)
	s.Equal(2, base.records)
	s.Same(base, WithFreshConsent("mosip", base))
}
