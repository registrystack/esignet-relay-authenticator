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

// The adapter binds SendOTP, Authenticate and GetAttributes to the flow's
// transaction id, which only the host's seed executor places in runtime data.
// Every path from START must run that seed before any other task executes.
func TestBREGTransactionIDSeededBeforeTasks(t *testing.T) {
	p := NewFlowProvider(&config.AppConfig{DataDir: "../../data", AuthFlowID: "flow-breg-otp"}, nil, 0)
	flow, err := p.GetFlow(context.Background(), "flow-breg-otp")
	if err != nil {
		t.Fatalf("load candidate flow: %v", err)
	}
	nodes := make(map[string]providers.NodeDefinition, len(flow.Nodes))
	start := ""
	for _, node := range flow.Nodes {
		nodes[node.ID] = node
		if node.Type == "START" {
			start = node.ID
		}
	}
	if start == "" {
		t.Fatal("flow start missing")
	}
	seeded := false
	visited := map[string]bool{}
	pending := []string{start}
	for len(pending) > 0 {
		id := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if id == "" || visited[id] {
			continue
		}
		visited[id] = true
		node, ok := nodes[id]
		if !ok {
			t.Fatalf("flow references unknown node %q", id)
		}
		if node.Type == "TASK_EXECUTION" {
			if node.Executor != nil && node.Executor.Name == "eSignetTransactionIDExecutor" {
				seeded = true
				continue
			}
			t.Fatalf("task %q can run before the transaction id is seeded", id)
		}
		pending = append(pending, node.OnSuccess, node.OnFailure, node.OnIncomplete, node.Next)
		if node.Condition != nil {
			pending = append(pending, node.Condition.OnSkip)
		}
		for _, prompt := range node.Prompts {
			if prompt.Action != nil {
				pending = append(pending, prompt.Action.NextNode)
			}
		}
	}
	if !seeded {
		t.Fatal("flow never seeds the transaction id")
	}
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
