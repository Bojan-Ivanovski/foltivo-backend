// Package mailer implements bounded SMTP delivery without logging email payloads.
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

type SMTP struct {
	Address, From, Username, Password string
	RequireTLS                        bool
}

func (s *SMTP) Validate(local bool) error {
	host, _, err := net.SplitHostPort(s.Address)
	if err != nil {
		return errors.New("SMTP_ADDR must contain a host and port")
	}
	a, err := mail.ParseAddress(s.From)
	if err != nil || a.Address != s.From || strings.ContainsAny(s.From, "\r\n") {
		return errors.New("SMTP_FROM must be a plain sender address")
	}
	ip := net.ParseIP(host)
	if !s.RequireTLS && (!local || (host != "localhost" && (ip == nil || !ip.IsLoopback()))) {
		return errors.New("unencrypted SMTP is allowed only for local development loopback delivery")
	}
	if (s.Username == "") != (s.Password == "") {
		return errors.New("SMTP_USERNAME and SMTP_PASSWORD must be configured together")
	}
	return nil
}
func (s *SMTP) Send(ctx context.Context, to, subject, body string) error {
	if strings.ContainsAny(to+subject, "\r\n") {
		return errors.New("invalid mail envelope")
	}
	host, _, _ := net.SplitHostPort(s.Address)
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", s.Address)
	if err != nil {
		return errors.New("SMTP delivery unavailable")
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return errors.New("SMTP delivery unavailable")
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}) != nil {
			return errors.New("SMTP TLS failed")
		}
	} else if s.RequireTLS {
		return errors.New("SMTP TLS required")
	}
	if s.Username != "" {
		if client.Auth(smtp.PlainAuth("", s.Username, s.Password, host)) != nil {
			return errors.New("SMTP authentication failed")
		}
	}
	if client.Mail(s.From) != nil || client.Rcpt(to) != nil {
		return errors.New("SMTP delivery rejected")
	}
	writer, err := client.Data()
	if err != nil {
		return errors.New("SMTP delivery unavailable")
	}
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s", s.From, to, subject, strings.ReplaceAll(body, "\n", "\r\n"))
	if _, err = writer.Write([]byte(message)); err != nil {
		return errors.New("SMTP message failed")
	}
	if writer.Close() != nil {
		return errors.New("SMTP message failed")
	}
	_ = client.Quit()
	return nil
}
