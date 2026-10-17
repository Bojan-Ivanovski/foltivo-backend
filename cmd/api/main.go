package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/api"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/authhttp"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/config"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/database"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("api_failed", "reason", err.Error())
		os.Exit(1)
	}
}

func run() error {
	c, err := config.Load()
	if err != nil {
		return err
	}
	authConfig, err := config.LoadAuth(c)
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
	passwords, err := auth.NewPasswords()
	if err != nil {
		return err
	}
	service := auth.NewService(auth.NewStore(db), passwords)
	email, err := config.LoadEmail(c, authConfig)
	if err != nil {
		return err
	}
	service.ConfigureEmail(email)
	if err = service.ConfigurePasskeys(authConfig.Origin); err != nil {
		return errors.New("invalid WebAuthn relying-party configuration")
	}
	workerCtx, workerCancel := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); service.EmailLoop(workerCtx) }()
	defer func() { workerCancel(); <-workerDone }()
	authHandler := authhttp.New(service, authConfig.Origin, authConfig.SecureCookies)
	server := &http.Server{
		Addr:              c.HTTPAddr,
		Handler:           api.Handler(db, authHandler.Routes()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	slog.Info("api_started")
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTP server failed to listen")
	case <-ctx.Done():
		slog.Info("api_shutdown_started")
		stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return errors.New("HTTP server graceful shutdown timed out")
		}
		slog.Info("api_stopped")
		return nil
	}
}
