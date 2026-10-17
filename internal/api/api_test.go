package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type pingFunc func(context.Context) error

func (f pingFunc) Ping(ctx context.Context) error { return f(ctx) }

func TestHealthAndReadiness(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		fail bool
		code int
		body string
	}{
		{"liveness during outage", "/health", true, 200, "{\"status\":\"ok\"}\n"},
		{"ready", "/ready", false, 200, "{\"status\":\"ready\"}\n"},
		{"unavailable", "/ready", true, 503, "{\"status\":\"unavailable\"}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := Handler(pingFunc(func(ctx context.Context) error {
				called = true
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 2*time.Second {
					t.Error("readiness ping must have a bounded deadline")
				}
				if tc.fail {
					return errors.New("postgres://secret-password@database")
				}
				return nil
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != tc.code || w.Body.String() != tc.body {
				t.Fatalf("got %d %q", w.Code, w.Body.String())
			}
			if called != (tc.path == "/ready") {
				t.Fatal("liveness must not ping; readiness must ping")
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
				t.Fatal("missing JSON/cache headers")
			}
		})
	}
}
