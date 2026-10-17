package main

import (
	"io"
	"strings"
	"testing"
)

func TestCommandValidation(t *testing.T) {
	for _, args := range [][]string{
		{}, {"unknown"}, {"up", "extra"}, {"create", "../escape"}, {"create"}, {"--timeout", "0s", "up"},
	} {
		if err := run(args, io.Discard); err == nil {
			t.Errorf("accepted invalid arguments %v", args)
		}
	}
}

func TestRollbackGuardRunsBeforeDatabaseConnection(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:secret-password@127.0.0.1:1/test")
	for _, env := range []string{"", "production", "development"} {
		t.Setenv("APP_ENV", env)
		if err := run([]string{"reset"}, io.Discard); err == nil || !strings.Contains(err.Error(), "rollback requires") {
			t.Fatalf("unguarded rollback: %v", err)
		}
	}
	t.Setenv("APP_ENV", "production")
	if err := run([]string{"--allow-unsafe", "down"}, io.Discard); err == nil || !strings.Contains(err.Error(), "rollback requires") {
		t.Fatalf("production rollback accepted: %v", err)
	}
}
