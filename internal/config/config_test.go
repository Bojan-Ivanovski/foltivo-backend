package config

import "testing"

func TestLoad(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://placeholder")
	t.Setenv("APP_ENV", "")
	t.Setenv("HTTP_ADDR", "")
	c, err := Load()
	if err != nil || c.Environment != "production" || c.HTTPAddr != ":8080" {
		t.Fatalf("defaults: %#v, %v", c, err)
	}
	t.Setenv("APP_ENV", "invalid-secret")
	if _, err := Load(); err == nil || err.Error() != "APP_ENV must be development, test or production" {
		t.Fatalf("invalid environment: %v", err)
	}
	t.Setenv("APP_ENV", "test")
	t.Setenv("DATABASE_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("missing database URL accepted")
	}
}
