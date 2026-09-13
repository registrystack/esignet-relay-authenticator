package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The Mailpit verifier is synthetic and process-local. Its recipient is fixed
// by the operator; possession of the Mailpit inbox is not identity proof.
const (
	mailpitChallengeTTL = 5 * time.Minute
	mailpitMaxPending   = 1024
	mailpitMaxAttempts  = 5
)

type mailpitKey struct {
	identifier, identifierType string
	binding                    Binding
}
type mailpitChallenge struct {
	digest   [32]byte
	salt     [16]byte
	expires  time.Time
	attempts int
}
type mailpitVerifier struct {
	config   MailpitConfig
	timeout  time.Duration
	now      func() time.Time
	mu       sync.Mutex
	pending  map[mailpitKey]mailpitChallenge
	inFlight int
}

func newMailpitVerifier(c MailpitConfig, timeout time.Duration) *mailpitVerifier {
	return &mailpitVerifier{config: c, timeout: timeout, now: time.Now, pending: make(map[mailpitKey]mailpitChallenge)}
}

func validMailpitAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || len(address) > 255 || (host != "mailpit" && host != "localhost" && (ip == nil || !ip.IsLoopback())) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func validMailAddress(address string) bool {
	if len(address) < 3 || len(address) > 254 || strings.Count(address, "@") != 1 || strings.ContainsAny(address, "\r\n<>\x00 \t") {
		return false
	}
	for _, char := range address {
		if char < 33 || char > 126 {
			return false
		}
	}
	parts := strings.Split(address, "@")
	return parts[0] != "" && parts[1] != ""
}

func (v *mailpitVerifier) SendOTP(ctx context.Context, r OTPRequest) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(r.Channels) != 1 || r.Channels[0] != "email" || !validBinding(r.Binding) || !validText(r.Identifier) || !validText(r.IdentifierType) {
		return ErrInvalidRequest
	}
	key := mailpitKey{r.Identifier, r.IdentifierType, r.Binding}
	v.mu.Lock()
	for k, challenge := range v.pending {
		if !v.now().Before(challenge.expires) {
			delete(v.pending, k)
		}
	}
	if len(v.pending)+v.inFlight >= mailpitMaxPending {
		v.mu.Unlock()
		return ErrUnavailable
	}
	v.inFlight++
	v.mu.Unlock()
	defer func() { v.mu.Lock(); v.inFlight--; v.mu.Unlock() }()

	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return ErrUnavailable
	}
	code := fmt.Sprintf("%06d", n.Int64())
	var challenge mailpitChallenge
	if _, err := rand.Read(challenge.salt[:]); err != nil {
		return ErrUnavailable
	}
	challenge.digest = mailpitDigest(challenge.salt, code)
	challenge.expires = v.now().Add(mailpitChallengeTTL)
	if err := v.deliver(ctx, code); err != nil {
		return ErrUnavailable
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	v.mu.Lock()
	v.pending[key] = challenge
	v.mu.Unlock()
	return nil
}

func mailpitDigest(salt [16]byte, code string) [32]byte {
	h := sha256.New()
	_, _ = h.Write(salt[:])
	_, _ = io.WriteString(h, code)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func (v *mailpitVerifier) Verify(ctx context.Context, r ChallengeRequest) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	key := mailpitKey{r.Identifier, r.IdentifierType, r.Binding}
	v.mu.Lock()
	defer v.mu.Unlock()
	challenge, ok := v.pending[key]
	if !ok || !v.now().Before(challenge.expires) {
		delete(v.pending, key)
		return ErrChallengeFailed
	}
	challenge.attempts++
	submitted := mailpitDigest(challenge.salt, r.Challenge)
	match := subtle.ConstantTimeCompare(challenge.digest[:], submitted[:]) == 1
	if match || challenge.attempts >= mailpitMaxAttempts {
		delete(v.pending, key)
	} else {
		v.pending[key] = challenge
	}
	if !match {
		return ErrChallengeFailed
	}
	return nil
}

func (v *mailpitVerifier) deliver(ctx context.Context, code string) error {
	dialer := &net.Dialer{Timeout: v.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", v.config.SMTPAddress)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(v.timeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	client, err := smtp.NewClient(conn, "mailpit")
	if err != nil {
		return err
	}
	defer client.Close()
	if err = client.Mail(v.config.Sender); err != nil {
		return err
	}
	if err = client.Rcpt(v.config.Recipient); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "From: %s\r\nTo: %s\r\nSubject: Synthetic eSignet code\r\n\r\nYour synthetic login code is %s\r\n", v.config.Sender, v.config.Recipient, code)
	if err != nil {
		_ = w.Close()
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	if err := client.Quit(); err != nil {
		return err
	}
	return ctx.Err()
}
