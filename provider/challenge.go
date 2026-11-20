package provider

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"
)

// Defaults shared by the verifiers that issue one-time codes.
const (
	defaultChallengeTTL    = 5 * time.Minute
	defaultMaxPendingCodes = 100_000
	challengeMaxAttempts   = 5
)

// challengeKey binds a code to the exact person and flow it was issued for.
type challengeKey struct {
	identifier, identifierType string
	binding                    Binding
}

// challenge holds a salted digest of a code, never the code itself.
type challenge struct {
	digest   [32]byte
	salt     [16]byte
	expires  time.Time
	attempts int
}

// challengeStore issues and checks single-use codes. Pending challenges live in
// process memory, so a restart drops them and a deployment runs one replica.
//
// What the store holds is a function of the requests received, never of who
// exists or of what BREG or Registry Messaging answered. Every admitted request
// stores one challenge, a discarded one when nothing is sent, and no answer
// deletes an entry. The one allowed exception is the value of a pending code:
// a refused resend restores the code it replaced, matched by salt, and never
// changes the number of entries.
type challengeStore struct {
	ttl        time.Duration
	maxPending int
	now        func() time.Time
	mu         sync.Mutex
	pending    map[challengeKey]challenge
}

func newChallengeStore(ttl time.Duration, maxPending int) *challengeStore {
	return &challengeStore{ttl: ttl, maxPending: maxPending, now: time.Now, pending: make(map[challengeKey]challenge)}
}

// full reports whether the store is at its bound. It looks only at the count,
// so it refuses every request alike. Capacity is not held across a lookup, so
// concurrent requests can overshoot the bound by at most their number.
func (s *challengeStore) full() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending) >= s.maxPending
}

// sweep drops expired challenges.
func (s *challengeStore) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, c := range s.pending {
		if !now.Before(c.expires) {
			delete(s.pending, k)
		}
	}
}

// generate returns a six-digit code and the challenge that verifies it.
func (s *challengeStore) generate() (string, challenge, error) {
	var c challenge
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", c, ErrUnavailable
	}
	code := fmt.Sprintf("%06d", n.Int64())
	if _, err := rand.Read(c.salt[:]); err != nil {
		return "", c, ErrUnavailable
	}
	c.digest = challengeDigest(c.salt, code)
	c.expires = s.now().Add(s.ttl)
	return code, c, nil
}

func (s *challengeStore) put(k challengeKey, c challenge) { s.swap(k, c) }

// swap stores c and returns the challenge it replaced, if any.
func (s *challengeStore) swap(k challengeKey, c challenge) (previous challenge, replaced bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, replaced = s.pending[k]
	s.pending[k] = c
	return previous, replaced
}

// keep stores c only when the key holds no live challenge. A request that sends
// nothing uses it, so the entry count matches a request that did send.
func (s *challengeStore) keep(k challengeKey, c challenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.pending[k]; !ok || !s.now().Before(current.expires) {
		s.pending[k] = c
	}
}

// restore puts back the value mine replaced. It never adds or removes an entry,
// and does nothing once another request has replaced mine.
func (s *challengeStore) restore(k challengeKey, mine, previous challenge, replaced bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.pending[k]; ok && current.salt == mine.salt && replaced && s.now().Before(previous.expires) {
		s.pending[k] = previous
	}
}

func challengeDigest(salt [16]byte, code string) [32]byte {
	h := sha256.New()
	_, _ = h.Write(salt[:])
	_, _ = io.WriteString(h, code)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// check consumes the challenge on success, expiry or the last allowed attempt.
// pending reports whether a live challenge existed, so a caller can count only
// the failures that answer a request somebody made.
func (s *challengeStore) check(k challengeKey, code string) (pending bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.pending[k]
	if !ok || !s.now().Before(c.expires) {
		delete(s.pending, k)
		return false, ErrChallengeFailed
	}
	c.attempts++
	submitted := challengeDigest(c.salt, code)
	match := subtle.ConstantTimeCompare(c.digest[:], submitted[:]) == 1
	if match || c.attempts >= challengeMaxAttempts {
		delete(s.pending, k)
	} else {
		s.pending[k] = c
	}
	if !match {
		return true, ErrChallengeFailed
	}
	return true, nil
}
