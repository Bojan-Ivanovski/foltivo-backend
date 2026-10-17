// Package database owns PostgreSQL connection construction. Driver errors must
// not escape this boundary: they can contain connection strings and credentials.
package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

func OpenPool(ctx context.Context, url string) (*pgxpool.Pool, error) {
	c, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("invalid DATABASE_URL")
	}
	c.ConnConfig.ConnectTimeout = 5 * time.Second
	c.MaxConns = 10
	p, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		return nil, errors.New("cannot initialize database pool")
	}
	// Connections are lazy so liveness remains available during a database outage.
	return p, nil
}

func OpenSQL(url string) (*sql.DB, error) {
	c, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, errors.New("invalid DATABASE_URL")
	}
	c.ConnectTimeout = 5 * time.Second
	db := stdlib.OpenDB(*c)
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	return db, nil
}
