// Package config reads process configuration without exposing connection secrets.
package config

import (
	"errors"
	"os"
)

type Config struct {
	HTTPAddr    string
	DatabaseURL string
	Environment string
}

func Load() (Config, error) {
	c := Config{HTTPAddr: os.Getenv("HTTP_ADDR"), DatabaseURL: os.Getenv("DATABASE_URL"), Environment: os.Getenv("APP_ENV")}
	if c.HTTPAddr == "" {
		c.HTTPAddr = ":8080"
	}
	if c.Environment == "" {
		c.Environment = "production"
	}
	if c.Environment != "development" && c.Environment != "test" && c.Environment != "production" {
		return Config{}, errors.New("APP_ENV must be development, test or production")
	}
	if c.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	return c, nil
}
