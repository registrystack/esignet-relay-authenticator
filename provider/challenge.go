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
	defaultChallengeTTL  = 5 * time.Minute
	challengeMaxPending  = 1024
	challengeMaxAttempts = 5
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
type challengeStore struct {
	ttl      time.Duration
	now      func() time.Time
	mu       sync.Mutex
	pending  map[challengeKey]challenge
	inFlight int
}

func newChallengeStore(ttl time.Duration) *challengeStore {
	return &challengeStore{ttl: ttl, now: time.Now, pending: make(map[challengeKey]challenge)}
}

// begin drops expired challenges and reserves capacity for one new challenge.
// The returned function releases the reservation and must be called once.
func (s *challengeStore) begin() (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.pending {
		if !s.now().Before(c.expires) {
			delete(s.pending, k)
		}
	}
	if len(s.pending)+s.inFlight >= challengeMaxPending {
		return nil, ErrUnavailable
	}
	s.inFlight++
	return func() { s.mu.Lock(); s.inFlight--; s.mu.Unlock() }, nil
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

func (s *challengeStore) put(k challengeKey, c challenge) {
	s.mu.Lock()
	s.pending[k] = c
	s.mu.Unlock()
}

func (s *challengeStore) discard(k challengeKey) {
	s.mu.Lock()
	delete(s.pending, k)
	s.mu.Unlock()
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
func (s *challengeStore) check(k challengeKey, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.pending[k]
	if !ok || !s.now().Before(c.expires) {
		delete(s.pending, k)
		return ErrChallengeFailed
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
		return ErrChallengeFailed
	}
	return nil
}
