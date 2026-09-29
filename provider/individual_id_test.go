package provider

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func TestIndividualIDRequiresMappingProvisioningAndConsent(t *testing.T) {
	for _, source := range []string{"", "email", "uin"} {
		t.Run("source_"+source, func(t *testing.T) {
			f := newFixture(t)
			if source != "" {
				f.p.config.ClaimMap["individual_id"] = source
			}
			auth := authenticate(t, f)
			raw, err := json.Marshal(auth.Context)
			if err != nil {
				t.Fatal(err)
			}
			var restored map[string]any
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if _, err := f.p.GetAttributes(ctx, restored, binding(), nil); err != ErrInvalidRequest {
				t.Fatal("missing consent accepted")
			}
			for _, approved := range [][]string{{}, {"sub"}} {
				attrs, err := f.p.GetAttributes(ctx, restored, binding(), approved)
				if err != nil {
					t.Fatal(err)
				}
				if _, exists := attrs["individual_id"]; exists || f.lookupCalls.Load() != 1 {
					t.Fatal("unapproved business identifier disclosed or fetched")
				}
			}
			attrs, err := f.p.GetAttributes(ctx, restored, binding(), []string{"individual_id", "sub"})
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]any{"sub": auth.Subject}
			wantLookups := int32(1)
			if source == "uin" {
				want["individual_id"] = "subject-canary"
				wantLookups++
			}
			if !reflect.DeepEqual(attrs, want) || f.lookupCalls.Load() != wantLookups {
				t.Fatal("business identifier release changed the mapping, projection, or pairwise subject contract")
			}
			if auth.Subject == "subject-canary" {
				t.Fatal("business identifier replaced the pairwise subject")
			}
		})
	}
}
