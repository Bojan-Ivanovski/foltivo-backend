package authhttp

import (
	"context"
	"net/http"
	"time"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
)

func (h *Handler) registerOAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/providers/complete", h.wrap(h.completeOAuth, true))
	mux.HandleFunc("GET /api/v1/auth/providers", h.wrap(h.providers, false))
	mux.HandleFunc("POST /api/v1/auth/providers/{provider}/link", h.wrap(h.beginOAuth("link"), true))
	mux.HandleFunc("POST /api/v1/auth/providers/{provider}/login", h.wrap(h.beginOAuth("login"), true))
	mux.HandleFunc("DELETE /api/v1/auth/providers/{provider}", h.wrap(h.unlinkOAuth, true))
	// Cross-site top-level provider returns do not carry our Origin/CSRF header.
	// The service instead checks single-use state bound to the browser cookie.
	mux.HandleFunc("GET /api/v1/auth/providers/{provider}/callback", h.finishOAuth)
}
func (h *Handler) providers(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	providers, err := h.service.Providers(r.Context(), s)
	if err != nil {
		return err
	}
	write(w, 200, map[string]any{"providers": providers})
	return nil
}
func (h *Handler) beginOAuth(operation string) endpoint {
	return func(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
		if operation == "login" {
			if err := anonymous(s); err != nil {
				return err
			}
		}
		var body struct{}
		if err := decode(w, r, &body); err != nil {
			return err
		}
		target, err := h.service.BeginOAuth(r.Context(), s, h.peer(r), r.PathValue("provider"), operation)
		if err != nil {
			return err
		}
		write(w, 200, map[string]string{"url": target})
		return nil
	}
}
func (h *Handler) unlinkOAuth(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	if err := h.service.UnlinkOAuth(r.Context(), s, r.PathValue("provider")); err != nil {
		return err
	}
	write(w, 200, map[string]bool{"ok": true})
	return nil
}
func (h *Handler) finishOAuth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	w.Header().Set("Referrer-Policy", "no-referrer")
	target := h.origin + "/sign-in?provider=failed"
	current, err := h.service.Session(ctx, h.token(r), h.peer(r), false)
	if err == nil {
		if current.User != nil {
			target = h.origin + "/settings?provider=failed"
		}
		{
			code := r.URL.Query().Get("code")
			if r.URL.Query().Get("error") != "" {
				code = ""
			}
			result, finishErr := h.service.FinishOAuth(ctx, current, h.peer(r), r.PathValue("provider"), r.URL.Query().Get("state"), code)
			if finishErr == nil {
				if result.Operation == "link" {
					target = h.origin + "/settings?provider=linked"
				} else {
					target = h.origin + "/complete-provider-sign-in#token=" + result.Grant
				}
			}
		}
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (h *Handler) completeOAuth(w http.ResponseWriter, r *http.Request, current *auth.Session) error {
	if err := anonymous(current); err != nil {
		return err
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	next, err := h.service.CompleteOAuth(r.Context(), current, h.peer(r), body.Token)
	if err != nil {
		return err
	}
	h.cookie(w, next)
	write(w, 200, next)
	return nil
}
