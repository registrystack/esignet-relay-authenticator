package provider

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func unknownPerson(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `{"code":"lookup.unresolved"}`)
}

// storedState summarises what the relay holds: one line per limiter entry
// (without the keyed hash, which differs per process) and the pending count.
func (m *messagingFixture) storedState() string {
	v := m.verifier()
	v.limits.mu.Lock()
	var entries []string
	for _, st := range v.limits.people {
		entries = append(entries, fmt.Sprintf("sends=%d cooldowns=%d failures=%d", len(st.sends), len(st.next), st.failures))
	}
	v.limits.mu.Unlock()
	sort.Strings(entries)
	v.mu.Lock()
	defer v.mu.Unlock()
	return fmt.Sprintf("pending=%d people=[%s]", len(v.pending), strings.Join(entries, "; "))
}

// The relay's stored state and its BREG traffic are a function of the requests
// it received, never of whether the person exists or what Messaging answered.
func TestMessagingStateDoesNotDependOnWhoExists(t *testing.T) {
	scenarios := []struct {
		name  string
		setup func(*messagingFixture)
	}{
		{"messaging accepts", func(*messagingFixture) {}},
		{"messaging 429", func(m *messagingFixture) {
			m.setHandler(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprint(w, `{"code":"rate-limit.exceeded"}`)
			})
		}},
		{"messaging times out", func(m *messagingFixture) {
			m.setHandler(func(_ http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(5 * time.Second):
				case <-r.Context().Done():
				}
			})
		}},
		{"send queue full", func(m *messagingFixture) { m.verifier().slots = make(chan struct{}) }},
	}
	// run sends the same requests and wrong codes to a fixture and reports the
	// BREG lookups each made and the state left behind.
	run := func(t *testing.T, m *messagingFixture) (lookups []int32, state string) {
		other := func(tx string) OTPRequest { r := otpRequest("email"); r.Binding.TransactionID = tx; return r }
		steps := []struct {
			advance time.Duration
			request OTPRequest
		}{
			{0, otpRequest("email")}, // admitted
			{0, otpRequest("email")}, // inside the cooldown
			{0, other("second")},     // another transaction, same hourly budget
			{0, other("third")},
			{61 * time.Second, otpRequest("email")}, // cooldown over
			{0, otpRequest("email")},                // inside the cooldown again
		}
		for _, s := range steps {
			m.advance(s.advance)
			before := m.lookupCalls.Load()
			if err := m.p.SendOTP(context.Background(), s.request); err != nil {
				t.Fatal(err)
			}
			lookups = append(lookups, m.lookupCalls.Load()-before)
		}
		// A wrong code for a request that was made, and one for a transaction that never asked.
		_ = m.p.verifier.Verify(context.Background(), challengeFor("not-a-code"))
		stranger := challengeFor("not-a-code")
		stranger.Binding.TransactionID = "never-asked"
		_ = m.p.verifier.Verify(context.Background(), stranger)
		m.signals()
		return lookups, m.storedState()
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			known := newMessagingFixture(t, nil)
			sc.setup(known)
			gone := newMessagingFixture(t, nil)
			sc.setup(gone)
			gone.setLookup(unknownPerson)
			knownLookups, knownState := run(t, known)
			goneLookups, goneState := run(t, gone)
			if fmt.Sprint(knownLookups) != "[1 0 1 1 1 0]" || fmt.Sprint(goneLookups) != fmt.Sprint(knownLookups) {
				t.Fatalf("BREG calls per request: known %v, unknown %v", knownLookups, goneLookups)
			}
			if knownState != goneState {
				t.Fatalf("stored state differs:\nknown:   %s\nunknown: %s", knownState, goneState)
			}
		})
	}
}

// A full limiter refuses every request alike, including one from a person it
// already tracks, so refusal does not reveal who signed in recently.
func TestMessagingFullLimiterRefusesEveryone(t *testing.T) {
	m := newMessagingFixture(t, func(c *Config) { c.Messaging.MaxTrackedPeople = 20 })
	m.setLookup(unknownPerson)
	r := otpRequest("email")
	for i := 0; i < 20; i++ {
		r.Identifier = fmt.Sprintf("guess-%d", i)
		if err := m.p.SendOTP(context.Background(), r); err != nil {
			t.Fatalf("under the bound: %v", err)
		}
	}
	for _, id := range []string{"guess-0", "someone-new"} {
		r.Identifier = id
		r.Binding.TransactionID = "another"
		if err := m.p.SendOTP(context.Background(), r); err != ErrUnavailable {
			t.Fatalf("%s: a full limiter must refuse everyone, got %v", id, err)
		}
	}
	if !hasEvent(m.signals(), EventLimiterFull) {
		t.Fatal("operator not told")
	}
	m.advance(time.Hour + time.Second)
	if err := m.p.SendOTP(context.Background(), r); err != nil {
		t.Fatalf("limiter did not recover after the window: %v", err)
	}
}

// Failed verifications never create limiter entries, and a wrong code counts
// only against a request that was actually made.
func TestMessagingWrongCodesNeedAPendingChallenge(t *testing.T) {
	m := newMessagingFixture(t, func(c *Config) { c.Messaging.MaxTrackedPeople = 50 })
	for i := 0; i < 50; i++ {
		err := m.p.verifier.Verify(context.Background(), ChallengeRequest{Identifier: fmt.Sprintf("guess-%d", i), IdentifierType: "uin", Binding: binding(), Challenge: "000000"})
		if err != ErrChallengeFailed {
			t.Fatal(err)
		}
	}
	if n := len(m.verifier().limits.people); n != 0 {
		t.Fatalf("failed verifications created %d limiter entries", n)
	}
	if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
		t.Fatalf("verify traffic alone refused a send: %v", err)
	}
	genuine := m.lastCode(t)
	other := binding()
	other.TransactionID = "another-transaction"
	for i := 0; i < failureLockThreshold; i++ {
		_ = m.p.verifier.Verify(context.Background(), ChallengeRequest{Identifier: "subject-canary", IdentifierType: "uin", Binding: other, Challenge: "000000"})
	}
	if err := m.p.verifier.Verify(context.Background(), challengeFor(genuine)); err != nil {
		t.Fatalf("wrong codes for a request nobody made locked the person: %v", err)
	}
}

// The store's fill level, checked before the lookup, does not depend on the
// candidate, and no capacity is held while the lookup runs.
func TestMessagingStoreCheckIgnoresTheCandidate(t *testing.T) {
	t.Run("fill level after a known and an unknown candidate", func(t *testing.T) {
		after := func(lookup func(http.ResponseWriter), id string) error {
			m := newMessagingFixture(t, func(c *Config) { c.Messaging.MaxPendingCodes = 3 })
			v := m.verifier()
			for i := 0; i < 2; i++ {
				v.pending[challengeKey{identifier: fmt.Sprintf("filler-%d", i)}] = challenge{expires: m.clock().Add(time.Minute)}
			}
			m.setLookup(lookup)
			r := otpRequest("email")
			r.Identifier = id
			_ = m.p.SendOTP(context.Background(), r)
			m.setLookup(nil)
			follow := otpRequest("email")
			follow.Identifier = "follow-up"
			return m.p.SendOTP(context.Background(), follow)
		}
		if known, unknown := after(nil, "subject-canary"), after(unknownPerson, "nobody"); known != unknown {
			t.Fatalf("known %v, unknown %v", known, unknown)
		}
	})
	t.Run("slow lookups hold no capacity", func(t *testing.T) {
		m := newMessagingFixture(t, func(c *Config) { c.Messaging.MaxPendingCodes = 2 })
		gate, entered := make(chan struct{}), make(chan struct{}, 2)
		m.setLookup(func(w http.ResponseWriter) {
			entered <- struct{}{}
			<-gate
			unknownPerson(w)
		})
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				r := otpRequest("email")
				r.Identifier = fmt.Sprintf("slow-%d", i)
				_ = m.p.SendOTP(context.Background(), r)
			}(i)
		}
		<-entered
		<-entered
		m.setLookup(nil)
		err := m.p.SendOTP(context.Background(), otpRequest("email"))
		close(gate)
		wg.Wait()
		if err != nil {
			t.Fatalf("in-flight lookups refused a real person: %v", err)
		}
	})
	t.Run("a refused send never removes an entry", func(t *testing.T) {
		m := newMessagingFixture(t, nil)
		m.setHandler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) })
		if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
			t.Fatal(err)
		}
		m.signals()
		if len(m.verifier().pending) != 1 {
			t.Fatalf("pending entries %d, want 1", len(m.verifier().pending))
		}
	})
}

// The limiter and the store are swept at most once a second, not per request,
// and the sweep also drops expired cooldowns so memory stays bounded.
func TestMessagingSweepRunsOncePerSecond(t *testing.T) {
	m := newMessagingFixture(t, nil)
	v := m.verifier()
	m.setLookup(unknownPerson)
	if err := m.p.SendOTP(context.Background(), otpRequest("email")); err != nil {
		t.Fatal(err)
	}
	// An expired entry planted after the first sweep survives until the next one.
	v.mu.Lock()
	v.pending[challengeKey{identifier: "expired"}] = challenge{expires: m.clock().Add(-time.Second)}
	v.mu.Unlock()
	other := otpRequest("email")
	other.Identifier = "someone-else"
	if err := m.p.SendOTP(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.pending[challengeKey{identifier: "expired"}]; !ok {
		t.Fatal("store swept on every request")
	}
	m.advance(1100 * time.Millisecond)
	other.Identifier = "a-third"
	if err := m.p.SendOTP(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.pending[challengeKey{identifier: "expired"}]; ok {
		t.Fatal("store not swept after a second")
	}
	// Cooldowns past their end are dropped while the person's budget is still live.
	m.advance(2 * time.Minute)
	other.Identifier = "a-fourth"
	if err := m.p.SendOTP(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	for _, st := range v.limits.people {
		if len(st.next) > 1 {
			t.Fatalf("expired cooldowns kept: %d", len(st.next))
		}
	}
}

func TestMessagingResendCooldownCoversASend(t *testing.T) {
	m := newMessagingFixture(t, nil)
	c := m.fixture.config
	mc := *c.Messaging
	mc.ResendCooldownSeconds = 1
	c.Messaging = &mc
	_, err := New(c)
	if err == nil || !strings.Contains(err.Error(), "messaging.resend_cooldown_seconds") || !strings.Contains(err.Error(), "http.timeout_seconds") {
		t.Fatalf("a cooldown shorter than twice the HTTP timeout must be refused, naming both keys: %v", err)
	}
	mc.ResendCooldownSeconds = 2
	if _, err := New(c); err != nil {
		t.Fatalf("a cooldown of twice the timeout is allowed: %v", err)
	}
}

func TestMessagingChannelOrderIsEmailThenPhone(t *testing.T) {
	m := newMessagingFixture(t, nil)
	if got := fmt.Sprint(m.verifier().channels()); got != "[email phone]" {
		t.Fatalf("channels %s", got)
	}
	delete(m.verifier().config.Channels, "email")
	if got := fmt.Sprint(m.verifier().channels()); got != "[phone]" {
		t.Fatalf("channels %s", got)
	}
}

// A panic in the operator's callback must not take the process down.
func TestOperatorSignalPanicIsContained(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	m := newMessagingFixture(t, nil)
	p, err := New(m.fixture.config, WithOperatorSignal(func(OperatorEvent) { panic("callback failure") }))
	if err != nil {
		t.Fatal(err)
	}
	m.setHandler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnprocessableEntity) })
	if err := p.SendOTP(context.Background(), otpRequest("email")); err != nil {
		t.Fatal(err)
	}
	p.verifier.(*messagingVerifier).wait()
	full := p.verifier.(*messagingVerifier)
	full.slots = make(chan struct{})
	r := otpRequest("email")
	r.Binding.TransactionID = "another"
	if err := p.SendOTP(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got := logged.String(); !strings.Contains(got, "operator signal callback panicked") || strings.Contains(got, "callback failure") {
		t.Fatalf("a contained panic is reported once, without its value: %q", got)
	}
}
