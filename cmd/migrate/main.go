package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/config"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/database"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/migrate"
	"github.com/pressly/goose/v3"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	flags.SetOutput(out)
	unsafe := flags.Bool("allow-unsafe", false, "allow rollback against an explicitly selected development/test database")
	timeout := flags.Duration("timeout", 5*time.Minute, "maximum migration operation duration")
	if err := flags.Parse(args); err != nil {
		return errors.New("invalid arguments; use migrate --help")
	}
	args = flags.Args()
	if len(args) == 0 {
		return errors.New("usage: migrate [--allow-unsafe] [--timeout 5m] up|status|version|create NAME|down|reset")
	}
	command := args[0]
	if command == "create" {
		if len(args) != 2 || !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(args[1]) {
			return errors.New("create requires a lowercase snake_case migration name")
		}
		// Source creation uses the real repository filesystem, never embedded files.
		if _, err := os.Stat("internal/migrate/sql/00001_bootstrap.sql"); err != nil {
			return errors.New("create must run from the backend repository root")
		}
		if err := goose.Create(nil, "internal/migrate/sql", args[1], "sql"); err != nil {
			return errors.New("cannot create migration; check permissions and duplicate timestamp/name")
		}
		return nil
	}
	if len(args) != 1 || (command != "up" && command != "status" && command != "version" && command != "down" && command != "reset") {
		return errors.New("unknown migration command or unexpected argument")
	}
	if *timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	c, err := config.Load()
	if err != nil {
		return err
	}
	if err := migrate.CheckUnsafe(command, c.Environment, *unsafe); err != nil {
		return err
	}
	db, err := database.OpenSQL(c.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	p, err := migrate.Provider(db, migrate.Files())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	return migrate.Run(ctx, p, command, out)
}
