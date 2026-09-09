package engine

import (
	"context"
	"testing"

	"github.com/mosip/esignet/internal/config"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// The demo's static verifier must not advertise generated-code or password
// assurance. LOGIN_OPTIONS records the selected class for AuthAssert to enforce.
func TestBREGDemoAssuranceMapping(t *testing.T) {
	p := NewFlowProvider(&config.AppConfig{DataDir: "../../data", AuthFlowID: "flow-breg-otp"}, nil, 0)
	flow, err := p.GetFlow(context.Background(), "flow-breg-otp")
	if err != nil {
		t.Fatalf("load candidate flow: %v", err)
	}
	for _, node := range flow.Nodes {
		if node.ID != "select_otp" {
			continue
		}
		if node.Variant != providers.NodeVariantLoginOptions {
			t.Fatal("method selection must record the actual authentication class")
		}
		mapping, ok := node.Properties["authMethodMapping"].(map[string]any)
		if !ok || len(mapping) != 1 || mapping["mosip:idp:acr:static-code"] != "select_otp_action" {
			t.Fatal("demo flow must advertise only static-code assurance")
		}
		if len(node.Prompts) != 1 || len(node.Prompts[0].Inputs) != 0 || node.Prompts[0].Action.NextNode != "prompt_identifier" {
			t.Fatal("single-method selection must complete before requesting identifier input")
		}
		return
	}
	t.Fatal("method selection missing")
}

func TestBREGConsentActionsCarryDecisions(t *testing.T) {
	p := NewFlowProvider(&config.AppConfig{DataDir: "../../data", AuthFlowID: "flow-breg-otp"}, nil, 0)
	flow, err := p.GetFlow(context.Background(), "flow-breg-otp")
	if err != nil {
		t.Fatalf("load candidate flow: %v", err)
	}
	for _, node := range flow.Nodes {
		if node.ID != "prompt_consent" {
			continue
		}
		if len(node.Prompts) != 2 {
			t.Fatal("consent must support approval and refusal")
		}
		for _, prompt := range node.Prompts {
			if len(prompt.Inputs) != 1 || prompt.Inputs[0].Identifier != "consent_decisions" || !prompt.Inputs[0].Required {
				t.Fatal("each consent action must carry the user's decisions to ConsentExecutor")
			}
		}
		return
	}
	t.Fatal("consent prompt missing")
}
