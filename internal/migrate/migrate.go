// Package migrate provides the application's embedded Goose migration runner.
package migrate

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed sql/*.sql
var files embed.FS

func Files() fs.FS {
	sub, _ := fs.Sub(files, "sql")
	return sub
}

func Provider(db *sql.DB, files fs.FS) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockTimeout(1, 30), lock.WithUnlockTimeout(1, 5))
	if err != nil {
		return nil, errors.New("cannot initialize migration lock")
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, files,
		goose.WithSessionLocker(locker), goose.WithLogger(goose.NopLogger()), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		return nil, errors.New("cannot initialize migrations; check ordered SQL sources")
	}
	return p, nil
}

func CheckUnsafe(command, environment string, allow bool) error {
	if command != "down" && command != "reset" {
		return nil
	}
	if !allow || (environment != "development" && environment != "test") {
		return errors.New("rollback requires APP_ENV=development or test and --allow-unsafe; verify the target and backup first")
	}
	return nil
}

// Run prints only known migration metadata; raw SQL/driver errors may expose
// secrets and are intentionally replaced with a safe operational message.
func Run(ctx context.Context, p *goose.Provider, command string, out io.Writer) error {
	var err error
	switch command {
	case "up":
		var results []*goose.MigrationResult
		results, err = p.Up(ctx)
		if err == nil {
			fmt.Fprintf(out, "Applied %d migration(s)\n", len(results))
		}
	case "status":
		var statuses []*goose.MigrationStatus
		statuses, err = p.Status(ctx)
		if err == nil {
			for _, status := range statuses {
				fmt.Fprintf(out, "%d %s %s\n", status.Source.Version, status.State, filepath.Base(status.Source.Path))
			}
		}
	case "version":
		var version int64
		version, err = p.GetDBVersion(ctx)
		if err == nil {
			fmt.Fprintf(out, "%d\n", version)
		}
	case "down":
		_, err = p.Down(ctx)
	case "reset":
		_, err = p.DownTo(ctx, 0)
	default:
		return errors.New("unknown migration command")
	}
	if err != nil {
		return errors.New("migration command failed; check database availability, lock contention and reviewed migration SQL (connection details suppressed)")
	}
	return nil
}
