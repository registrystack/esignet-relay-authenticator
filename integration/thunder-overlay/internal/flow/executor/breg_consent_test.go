package executor

import (
	"context"
	"encoding/json"
	"testing"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunderid/internal/attributecache"
	"github.com/thunder-id/thunderid/internal/flow/common"
	inboundmodel "github.com/thunder-id/thunderid/internal/inboundclient/model"
	"github.com/thunder-id/thunderid/tests/mocks/attributecachemock"
	"github.com/thunder-id/thunderid/tests/mocks/authnprovider/managermock"
	"github.com/thunder-id/thunderid/tests/mocks/consentprovidermock"
	"github.com/thunder-id/thunderid/tests/mocks/flow/coremock"
	"github.com/thunder-id/thunderid/tests/mocks/jose/jwtmock"
)

func TestBREGConsentTimeoutDoesNotFetchOrReleaseRequestedAttributes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cache bool
	}{{"assertion", false}, {"userinfo_cache", true}} {
		t.Run(tc.name, func(t *testing.T) { testBREGConsentTimeout(t, tc.cache) })
	}
}

func testBREGConsentTimeout(t *testing.T, cacheAttributes bool) {
	t.Helper()
	authUser := authenticatedBREGConsentUser(t)
	entityRef := &providers.EntityReference{EntityID: "person-123"}
	decisionsJSON, err := json.Marshal(providers.ConsentDecisions{
		Reason: providers.ConsentDecisionReasonTimeout,
	})
	require.NoError(t, err)

	consentFactory := coremock.NewFlowFactoryInterfaceMock(t)
	consentBase := coremock.NewExecutorInterfaceMock(t)
	consentFactory.On("CreateExecutor", ExecutorNameConsent, providers.ExecutorTypeUtility,
		mock.Anything, mock.Anything, mock.Anything).Return(consentBase)
	consentProvider := consentprovidermock.NewConsentProviderMock(t)
	consentAuthnProvider := managermock.NewAuthnProviderManagerMock(t)
	consentExecutor := newConsentExecutor(consentFactory, consentProvider, consentAuthnProvider)

	ctx := &providers.NodeContext{
		Context:     context.Background(),
		ExecutionID: "breg-timeout",
		EntityID:    "relying-party",
		AuthUser:    authUser,
		UserInputs: map[string]string{
			userInputConsentDecisions: string(decisionsJSON),
		},
		RuntimeData: map[string]string{
			common.RuntimeKeyRequiredOptionalAttributes: "individual_id",
			common.RuntimeKeyStepTimeout:                "1",
		},
		NodeProperties: map[string]interface{}{"timeout": "120"},
		Application: providers.Application{
			InboundAuthProfile: providers.InboundAuthProfile{
				Assertion: &inboundmodel.AssertionConfig{
					UserAttributes: []string{"individual_id"},
				},
			},
		},
	}
	if cacheAttributes {
		ctx.RuntimeData[common.RuntimeKeyUserAttributesCacheTTLSeconds] = "300"
	}

	consentBase.On("ValidatePrerequisites", ctx, mock.Anything, mock.Anything).Return(true)
	consentBase.On("HasRequiredInputs", ctx, mock.Anything).Return(true)
	consentAuthnProvider.On("GetEntityReference", mock.Anything, mock.Anything).
		Return(authUser, entityRef, (*tidcommon.ServiceError)(nil))
	consentAuthnProvider.On("GetUserAvailableAttributes", mock.Anything, mock.Anything).
		Return(&providers.AttributesResponse{Attributes: map[string]*providers.AttributeResponse{
			"individual_id": nil,
		}}, (*tidcommon.ServiceError)(nil))

	consentResponse, err := consentExecutor.Execute(ctx)
	require.NoError(t, err)
	require.Equal(t, providers.ExecComplete, consentResponse.Status)
	require.Contains(t, consentResponse.RuntimeData, common.RuntimeKeyConsentedAttributes)
	require.Empty(t, consentResponse.RuntimeData[common.RuntimeKeyConsentedAttributes])
	require.NotContains(t, consentResponse.RuntimeData, common.RuntimeKeyConsentID)
	consentProvider.AssertNotCalled(t, "RecordConsent", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	for key, value := range consentResponse.RuntimeData {
		ctx.RuntimeData[key] = value
	}
	ctx.ExecutionHistory = map[string]*providers.NodeExecutionRecord{}

	authAssertFactory := coremock.NewFlowFactoryInterfaceMock(t)
	authAssertBase := coremock.NewExecutorInterfaceMock(t)
	authAssertFactory.On("CreateExecutor", ExecutorNameAuthAssert, providers.ExecutorTypeUtility,
		[]providers.Input{}, []providers.Input{}, mock.Anything).Return(authAssertBase)
	authAssertProvider := managermock.NewAuthnProviderManagerMock(t)
	jwtService := jwtmock.NewJWTServiceInterfaceMock(t)
	attributeCacheService := attributecachemock.NewAttributeCacheServiceInterfaceMock(t)
	attributeCacheService.On("CreateAttributeCache", mock.Anything, mock.Anything).
		Return(&attributecache.AttributeCache{ID: "unapproved-cache"}, nil).Maybe()
	authAssertExecutor := newAuthAssertExecutor(authAssertFactory, jwtService, nil, nil,
		authAssertProvider, nil, attributeCacheService, nil)

	var requestedAttributes map[string]*providers.AttributeMetadataRequest
	authAssertProvider.On("GetEntityReference", mock.Anything, mock.Anything).
		Return(authUser, entityRef, (*tidcommon.ServiceError)(nil))
	authAssertProvider.On("GetUserAttributes", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			requestedAttributes = args.Get(1).(*providers.RequestedAttributes).Attributes
		}).
		Return(authUser, &providers.AttributesResponse{Attributes: map[string]*providers.AttributeResponse{
			"individual_id": {Value: "should-not-be-released"},
		}}, (*tidcommon.ServiceError)(nil))

	var generatedClaims map[string]interface{}
	jwtService.On("GenerateJWT", mock.Anything, "person-123", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			generatedClaims = args.Get(4).(map[string]interface{})
		}).
		Return("auth-assertion", int64(3600), nil)

	authAssertResponse, err := authAssertExecutor.Execute(ctx)
	require.NoError(t, err)
	require.Equal(t, providers.ExecComplete, authAssertResponse.Status)
	assert.NotContains(t, requestedAttributes, "individual_id")
	assert.NotContains(t, generatedClaims, "individual_id")
	assert.NotContains(t, generatedClaims, "aci")
	attributeCacheService.AssertNotCalled(t, "CreateAttributeCache", mock.Anything, mock.Anything)
}

func TestBREGConsentAttributesWithoutConsentIDTakePrecedence(t *testing.T) {
	authAssertFactory := coremock.NewFlowFactoryInterfaceMock(t)
	authAssertFactory.On("CreateExecutor", ExecutorNameAuthAssert, providers.ExecutorTypeUtility,
		[]providers.Input{}, []providers.Input{}, mock.Anything).
		Return(coremock.NewExecutorInterfaceMock(t))
	authAssertExecutor := newAuthAssertExecutor(authAssertFactory, nil, nil, nil, nil, nil, nil, nil)

	ctx := &providers.NodeContext{
		Context:     context.Background(),
		ExecutionID: "breg-explicit-consent",
		RuntimeData: map[string]string{
			common.RuntimeKeyConsentedAttributes:        "family_name",
			common.RuntimeKeyRequiredOptionalAttributes: "family_name individual_id",
		},
	}

	assert.Equal(t, []string{"family_name"}, authAssertExecutor.getRequiredUserAttributes(ctx))
}

func authenticatedBREGConsentUser(t *testing.T) providers.AuthUser {
	t.Helper()

	var authUser providers.AuthUser
	require.NoError(t, authUser.UnmarshalJSON([]byte(
		`{"default":{"entityReferenceToken":"entity-token","attributeToken":"attribute-token"}}`,
	)))
	return authUser
}
