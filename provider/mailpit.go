package provider

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// The Mailpit verifier is synthetic and process-local. Its recipient is fixed
// by the operator; possession of the Mailpit inbox is not identity proof.
type mailpitVerifier struct {
	*challengeStore
	config  MailpitConfig
	timeout time.Duration
}

func newMailpitVerifier(c MailpitConfig, timeout time.Duration) *mailpitVerifier {
	return &mailpitVerifier{challengeStore: newChallengeStore(defaultChallengeTTL), config: c, timeout: timeout}
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
	release, err := v.begin()
	if err != nil {
		return err
	}
	defer release()
	code, c, err := v.generate()
	if err != nil {
		return err
	}
	if err := v.deliver(ctx, code); err != nil {
		return ErrUnavailable
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	v.put(challengeKey{r.Identifier, r.IdentifierType, r.Binding}, c)
	return nil
}

func (v *mailpitVerifier) Verify(ctx context.Context, r ChallengeRequest) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return v.check(challengeKey{r.Identifier, r.IdentifierType, r.Binding}, r.Challenge)
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
