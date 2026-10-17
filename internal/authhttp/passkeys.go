package authhttp

import (
	"encoding/json"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
	"net/http"
)

func (h *Handler) beginPasskey(kind string) endpoint {
	return func(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
		var value string
		if kind == "registration" {
			var dto struct {
				Name string `json:"name"`
			}
			if err := decode(w, r, &dto); err != nil {
				return err
			}
			value = dto.Name
		} else {
			var dto struct {
				Email string `json:"email"`
			}
			if err := decode(w, r, &dto); err != nil {
				return err
			}
			value = dto.Email
		}
		options, err := h.service.BeginPasskey(r.Context(), s, peer(r), kind, value)
		if err != nil {
			return err
		}
		write(w, 200, options)
		return nil
	}
}
func (h *Handler) finishPasskey(kind string) endpoint {
	return func(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
		// Preserve the standard WebAuthn credential JSON for the library parser;
		// the shared decoder still bounds it and rejects ambiguous top-level keys.
		var body json.RawMessage
		if err := decode(w, r, &body); err != nil {
			return err
		}
		result, err := h.service.FinishPasskey(r.Context(), s, peer(r), kind, body)
		if err != nil {
			return err
		}
		if kind == "login" {
			h.cookie(w, result)
			write(w, 200, result)
		} else {
			write(w, 200, map[string]string{"message": "Passkey registered."})
		}
		return nil
	}
}
func (h *Handler) security(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	result, err := h.service.Security(r.Context(), s)
	if err != nil {
		return err
	}
	write(w, 200, result)
	return nil
}
func (h *Handler) removePasskey(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	if err := h.service.RemovePasskey(r.Context(), s, r.PathValue("id")); err != nil {
		return err
	}
	write(w, 200, map[string]string{"message": "Passkey removed."})
	return nil
}
