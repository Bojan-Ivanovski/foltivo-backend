package api

import (
	"context"
	"io"
	"net/http"
	"time"
)

type Pinger interface {
	Ping(context.Context) error
}

func Handler(db Pinger, application ...http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, "{\"status\":\"ok\"}\n")
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			respond(w, http.StatusServiceUnavailable, "{\"status\":\"unavailable\"}\n")
			return
		}
		respond(w, http.StatusOK, "{\"status\":\"ready\"}\n")
	})
	if len(application) > 0 {
		mux.Handle("/api/", application[0])
	}
	return mux
}

func respond(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
