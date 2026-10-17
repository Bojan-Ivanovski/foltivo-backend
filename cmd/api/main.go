package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/api"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/config"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/database"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	c, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db, err := database.OpenPool(ctx, c.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	server := &http.Server{
		Addr:              c.HTTPAddr,
		Handler:           api.Handler(db),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	log.Printf("Foltivo API listening on %s", c.HTTPAddr)
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTP server failed to listen")
	case <-ctx.Done():
		stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return errors.New("HTTP server graceful shutdown timed out")
		}
		return nil
	}
}
