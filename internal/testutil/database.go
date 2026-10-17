// Package testutil provides isolated PostgreSQL schemas for integration tests.
package testutil

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/database"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/migrate"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Database(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to an isolated PostgreSQL database")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	admin, err := database.OpenSQL(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("auth_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		admin.Close()
		t.Fatal("cannot create test schema")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	conn, err := database.OpenSQL(u.String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := migrate.Provider(conn, migrate.Files())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(context.Background()); err != nil {
		t.Fatal("cannot apply test migrations")
	}
	conn.Close()
	pool, err := database.OpenPool(context.Background(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			t.Error("cannot drop test schema")
		}
		admin.Close()
	})
	return pool
}
