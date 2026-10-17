package migrate

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/database"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

func testDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to an isolated PostgreSQL test database")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid TEST_DATABASE_URL")
	}
	admin, err := database.OpenSQL(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("migration_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		admin.Close()
		t.Fatal("cannot create test schema")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := database.OpenSQL(u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			t.Error("cannot clean test schema")
		}
		admin.Close()
	})
	return db
}

func provider(t *testing.T, db *sql.DB, files fs.FS) *goose.Provider {
	t.Helper()
	p, err := Provider(db, files)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIntegrationMigrationLifecycle(t *testing.T) {
	db := testDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	bootstrap, _ := fs.ReadFile(Files(), "00001_bootstrap.sql")
	p := provider(t, db, fstest.MapFS{"00001_bootstrap.sql": {Data: bootstrap}})
	var out bytes.Buffer
	if err := Run(ctx, p, "status", &out); err != nil || !strings.Contains(out.String(), "pending") {
		t.Fatalf("fresh status: %v %s", err, &out)
	}
	if err := Run(ctx, p, "up", io.Discard); err != nil {
		t.Fatal(err)
	}
	if results, err := p.Up(ctx); err != nil || len(results) != 0 {
		t.Fatalf("repeat apply: %v", err)
	}
	files := fstest.MapFS{
		"00001_bootstrap.sql": {Data: bootstrap},
		"00002_probe.sql":     {Data: []byte("-- +goose Up\nCREATE TABLE migration_probe(id integer);\n-- +goose Down\nDROP TABLE migration_probe;\n")},
	}
	p = provider(t, db, files)
	if err := Run(ctx, p, "up", io.Discard); err != nil {
		t.Fatal(err)
	}
	if version, err := p.GetDBVersion(ctx); err != nil || version != 2 {
		t.Fatalf("subsequent version=%d err=%v", version, err)
	}
	files["00003_failure.sql"] = &fstest.MapFile{Data: []byte("-- +goose Up\nCREATE TABLE must_rollback(id integer);\nSELECT nonexistent_column;\n")}
	p = provider(t, db, files)
	if err := Run(ctx, p, "up", io.Discard); err == nil {
		t.Fatal("invalid migration succeeded")
	}
	var exists bool
	if err := db.QueryRow("SELECT to_regclass('must_rollback') IS NOT NULL").Scan(&exists); err != nil || exists {
		t.Fatal("failed migration was not rolled back atomically")
	}
	if version, err := p.GetDBVersion(ctx); err != nil || version != 2 {
		t.Fatalf("failed migration changed history: %d %v", version, err)
	}
	delete(files, "00003_failure.sql")
	p = provider(t, db, files)
	if err := Run(ctx, p, "down", io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, p, "reset", io.Discard); err != nil {
		t.Fatal(err)
	}
	if version, err := p.GetDBVersion(ctx); err != nil || version != 0 {
		t.Fatalf("reset version=%d err=%v", version, err)
	}
}

func TestIntegrationConcurrentMigrationLock(t *testing.T) {
	db := testDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Hold exactly the lock Goose uses on a separate dedicated connection.
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal("cannot acquire test connection")
	}
	defer conn.Close()
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		t.Fatal(err)
	}
	if err := locker.SessionLock(ctx, conn); err != nil {
		t.Fatal("cannot hold test advisory lock")
	}
	held := true
	defer func() {
		if held {
			_ = locker.SessionUnlock(context.Background(), conn)
		}
	}()
	p := provider(t, db, Files())
	blockedCtx, blockedCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer blockedCancel()
	if _, err := p.Up(blockedCtx); err == nil {
		t.Fatal("migration bypassed another runner's lock")
	}
	if err := locker.SessionUnlock(ctx, conn); err != nil {
		t.Fatal("cannot release test advisory lock")
	}
	held = false
	if _, err := p.Up(ctx); err != nil {
		t.Fatal("migration failed after competing lock was released")
	}
}
