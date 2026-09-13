package provider

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

func smtpFixture(t *testing.T) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	messages := make(chan string, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				_, _ = fmt.Fprint(conn, "220 mailpit local\r\n")
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO "):
						_, _ = fmt.Fprint(conn, "250 mailpit\r\n")
					case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
						_, _ = fmt.Fprint(conn, "250 ok\r\n")
					case strings.HasPrefix(line, "DATA"):
						_, _ = fmt.Fprint(conn, "354 go\r\n")
						var message strings.Builder
						for {
							line, err = reader.ReadString('\n')
							if err != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
							message.WriteString(line)
						}
						messages <- message.String()
						_, _ = fmt.Fprint(conn, "250 accepted\r\n")
					case strings.HasPrefix(line, "QUIT"):
						_, _ = fmt.Fprint(conn, "221 bye\r\n")
						return
					default:
						_, _ = fmt.Fprint(conn, "500 unsupported\r\n")
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), messages
}

func mailpitCode(t *testing.T, messages <-chan string) string {
	t.Helper()
	select {
	case message := <-messages:
		if !strings.Contains(message, "To: synthetic@example.test") {
			t.Fatal("unexpected recipient")
		}
		code := regexp.MustCompile(`code is ([0-9]{6})`).FindStringSubmatch(message)
		if len(code) != 2 {
			t.Fatal("SMTP message lacks generated code")
		}
		return code[1]
	case <-time.After(time.Second):
		t.Fatal("SMTP message not delivered")
		return ""
	}
}

func TestMailpitChallengeDeliveryBindingExpiryAndConsumption(t *testing.T) {
	addr, messages := smtpFixture(t)
	v := newMailpitVerifier(MailpitConfig{Enabled: true, SMTPAddress: addr, Sender: "demo@example.test", Recipient: "synthetic@example.test"}, time.Second)
	now := time.Now()
	v.now = func() time.Time { return now }
	r := OTPRequest{Identifier: "synthetic-123", IdentifierType: "uin", Binding: Binding{"rp", "client", "txn"}, Channels: []string{"email"}}
	if err := v.SendOTP(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	code := mailpitCode(t, messages)
	challenge := ChallengeRequest{Identifier: r.Identifier, IdentifierType: r.IdentifierType, Binding: r.Binding, Challenge: code}
	for _, bad := range []ChallengeRequest{
		{Identifier: r.Identifier, IdentifierType: r.IdentifierType, Binding: r.Binding, Challenge: "000000-not-the-code"},
		{Identifier: "another", IdentifierType: r.IdentifierType, Binding: r.Binding, Challenge: code},
		{Identifier: r.Identifier, IdentifierType: r.IdentifierType, Binding: Binding{"rp", "client", "other"}, Challenge: code},
		{Identifier: r.Identifier, IdentifierType: r.IdentifierType, Binding: Binding{"other", "client", "txn"}, Challenge: code},
		{Identifier: r.Identifier, IdentifierType: r.IdentifierType, Binding: Binding{"rp", "other", "txn"}, Challenge: code},
	} {
		if err := v.Verify(context.Background(), bad); err != ErrChallengeFailed {
			t.Fatal("wrong code or context accepted")
		}
	}
	if err := v.Verify(context.Background(), challenge); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), challenge); err != ErrChallengeFailed {
		t.Fatal("reused code accepted")
	}
	if err := v.SendOTP(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	expiredCode := mailpitCode(t, messages)
	now = now.Add(mailpitChallengeTTL)
	challenge.Challenge = expiredCode
	if err := v.Verify(context.Background(), challenge); err != ErrChallengeFailed || len(v.pending) != 0 {
		t.Fatal("expired challenge accepted or retained")
	}
}

func TestMailpitAttemptsAndCapacity(t *testing.T) {
	addr, messages := smtpFixture(t)
	v := newMailpitVerifier(MailpitConfig{Enabled: true, SMTPAddress: addr, Sender: "demo@example.test", Recipient: "synthetic@example.test"}, time.Second)
	r := OTPRequest{Identifier: "synthetic", IdentifierType: "uin", Binding: Binding{"rp", "client", "txn"}, Channels: []string{"email"}}
	if err := v.SendOTP(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	code := mailpitCode(t, messages)
	for i := 0; i < mailpitMaxAttempts; i++ {
		if err := v.Verify(context.Background(), ChallengeRequest{Identifier: r.Identifier, IdentifierType: r.IdentifierType, Binding: r.Binding, Challenge: "invalid"}); err != ErrChallengeFailed {
			t.Fatal("wrong code accepted")
		}
	}
	if err := v.Verify(context.Background(), ChallengeRequest{Identifier: r.Identifier, IdentifierType: r.IdentifierType, Binding: r.Binding, Challenge: code}); err != ErrChallengeFailed {
		t.Fatal("code accepted after attempt limit")
	}
	for i := 0; i < mailpitMaxPending; i++ {
		v.pending[mailpitKey{identifier: fmt.Sprintf("%d", i)}] = mailpitChallenge{expires: time.Now().Add(time.Minute)}
	}
	if err := v.SendOTP(context.Background(), r); err != ErrUnavailable {
		t.Fatal("pending challenge bound ignored")
	}
}

func TestMailpitConfigurationAndDeliveryFailure(t *testing.T) {
	f := newFixture(t)
	f.config.Demo.Mailpit = MailpitConfig{Enabled: true, SMTPAddress: "127.0.0.1:1", Sender: "demo@example.test", Recipient: "synthetic@example.test"}
	p, err := New(f.config)
	if err != nil || len(p.SupportedOTPChannels()) != 1 || p.SupportedOTPChannels()[0] != "email" {
		t.Fatal("mailpit verifier not selected")
	}
	r := OTPRequest{Identifier: "synthetic", IdentifierType: "uin", Binding: Binding{"rp", "client", "txn"}, Channels: []string{"email"}}
	if err := p.SendOTP(context.Background(), r); err != ErrUnavailable || len(p.verifier.(*mailpitVerifier).pending) != 0 {
		t.Fatal("failed delivery issued a usable challenge")
	}
	for _, address := range []string{"example.org:1025", "mailpit:0", "mailpit:65536", "https://mailpit:1025", "localhost:1\n"} {
		f.config.Demo.Mailpit.SMTPAddress = address
		if _, err := New(f.config); err == nil {
			t.Fatal("invalid synthetic SMTP address accepted")
		}
	}
	f.config.Demo.Mailpit.SMTPAddress = "mailpit:1025"
	f.config.Demo.StaticOTPEnabled = true
	if _, err := New(f.config); err == nil {
		t.Fatal("conflicting synthetic challenge modes accepted")
	}
}

func TestMailpitProviderStopsBeforeTokenAndBREG(t *testing.T) {
	f := newFixture(t)
	addr, messages := smtpFixture(t)
	f.config.Demo.Mailpit = MailpitConfig{Enabled: true, SMTPAddress: addr, Sender: "demo@example.test", Recipient: "synthetic@example.test"}
	p, err := New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.p = p
	r := OTPRequest{Identifier: "subject-canary", IdentifierType: "uin", Binding: binding(), Channels: []string{"email"}}
	if err := p.SendOTP(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	code := mailpitCode(t, messages)
	a := AuthenticationRequest{Identifier: r.Identifier, IdentifierType: r.IdentifierType, Binding: r.Binding, Challenge: "invalid"}
	if _, err := p.Authenticate(context.Background(), a); err != ErrChallengeFailed || f.tokenCalls.Load() != 0 || f.lookupCalls.Load() != 0 {
		t.Fatal("wrong Mailpit code reached token issuer or BREG")
	}
	a.Challenge = code
	if result, err := p.Authenticate(context.Background(), a); err != nil || result.Subject == "" || f.tokenCalls.Load() != 1 || f.lookupCalls.Load() != 1 {
		t.Fatal("delivered Mailpit code did not authorize governed lookup")
	}
	if _, err := p.Authenticate(context.Background(), a); err != ErrChallengeFailed || f.lookupCalls.Load() != 1 {
		t.Fatal("consumed Mailpit code reached BREG")
	}
}
