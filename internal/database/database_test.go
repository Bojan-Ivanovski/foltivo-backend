package database

import (
	"context"
	"strings"
	"testing"
)

func TestMalformedURLDoesNotLeakCredentials(t *testing.T) {
	secret := "postgres://user:secret-password@localhost/%zz"
	for name, open := range map[string]func() error{
		"pool": func() error { _, err := OpenPool(context.Background(), secret); return err },
		"sql":  func() error { _, err := OpenSQL(secret); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := open()
			if err == nil || strings.Contains(err.Error(), "secret-password") || err.Error() != "invalid DATABASE_URL" {
				t.Fatalf("unsafe parse error: %v", err)
			}
		})
	}
}

func TestPoolDoesNotRequireDatabaseAtStartup(t *testing.T) {
	p, err := OpenPool(context.Background(), "postgres://user:placeholder@127.0.0.1:1/test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
}
