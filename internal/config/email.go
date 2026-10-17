package config

import (
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/mailer"
	"os"
)

func LoadEmail(c Config, a Auth) (*auth.EmailDelivery, error) {
	secrets, err := auth.NewSecrets(os.Getenv("AUTH_ENCRYPTION_KEY"))
	if err != nil {
		return nil, err
	}
	sender := &mailer.SMTP{Address: os.Getenv("SMTP_ADDR"), From: os.Getenv("SMTP_FROM"), Username: os.Getenv("SMTP_USERNAME"), Password: os.Getenv("SMTP_PASSWORD"), RequireTLS: os.Getenv("SMTP_REQUIRE_TLS") != "false"}
	if err = sender.Validate(c.Environment != "production"); err != nil {
		return nil, err
	}
	return &auth.EmailDelivery{Origin: a.Origin, Secrets: secrets, Sender: sender}, nil
}
