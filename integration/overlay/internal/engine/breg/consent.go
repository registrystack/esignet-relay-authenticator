package breg

import (
	"context"

	"github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

type freshConsentProvider struct{ providers.ConsentProvider }

// WithFreshConsent requires an explicit sharing decision for each BREG login.
// Other configured identity providers retain their existing consent policy.
func WithFreshConsent(provider string, consent providers.ConsentProvider) providers.ConsentProvider {
	if provider != "breg" {
		return consent
	}
	return &freshConsentProvider{ConsentProvider: consent}
}

func (p *freshConsentProvider) RecordConsent(ctx context.Context, ouID, appID, userID string,
	decisions *providers.ConsentDecisions, sessionToken string, validityPeriod int64,
	metadata map[string][]string) (*providers.Consent, *common.ServiceError) {
	record, err := p.ConsentProvider.RecordConsent(ctx, ouID, appID, userID, decisions,
		sessionToken, validityPeriod, metadata)
	if err != nil && err.Code == "essential_consent_denied" {
		// The pinned Thunder ConsentExecutor recognizes this provider error code
		// as an essential refusal and stops the flow without issuing a code.
		mapped := *err
		mapped.Code = "AUTH-CES-1006"
		return record, &mapped
	}
	return record, err
}

func (p *freshConsentProvider) ResolveConsent(ctx context.Context, ouID, appID, appName, userID string,
	essential, optional, permissions []string, available *providers.AttributesResponse, _ bool,
	metadata map[string][]string) (*providers.ConsentPromptData, *common.ServiceError) {
	return p.ConsentProvider.ResolveConsent(ctx, ouID, appID, appName, userID,
		essential, optional, permissions, available, true, metadata)
}
