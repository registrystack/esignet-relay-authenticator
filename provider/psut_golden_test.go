package provider

import "testing"

// These public synthetic vectors were computed with v0.5.0 (c064ff8).
// Keep the outputs fixed across upstream rebases and serialization changes.
func TestPSUTGoldenVectors(t *testing.T) {
	p := &Provider{secret: []byte("0123456789abcdef0123456789abcdef")}
	for _, tc := range []struct {
		name       string
		identifier string
		want       string
	}{
		{"ordinary", "000000000001", "c-Fyq5HSOUlDKJJD6XEw8EZrIbYRqyfsq9HQR0ewF-U"},
		{"json_escaping", "<citizen>&\u2028", "_S0K7k98eOYQn-cM15-glcy4ZjfJF9u3U7axaT1ViDs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := authContext{RelyingPartyID: "solmara", ClientID: "portal", IdentifierType: "uin", Identifier: tc.identifier}
			if got := p.psut(state); got != tc.want {
				t.Fatalf("PSUT changed: got %q, want %q", got, tc.want)
			}
		})
	}
}
