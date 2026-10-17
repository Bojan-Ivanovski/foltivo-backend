package authhttp

import (
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
	"net/http"
)

func (h *Handler) requestEmail(purpose string) endpoint {
	return func(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
		var dto struct {
			Email string `json:"email"`
		}
		if err := decode(w, r, &dto); err != nil {
			return err
		}
		if err := h.service.RequestEmail(r.Context(), h.peer(r), dto.Email, purpose); err != nil {
			return err
		}
		write(w, 202, map[string]string{"message": "If the account is eligible, an email has been queued. Please check your inbox shortly."})
		return nil
	}
}
func (h *Handler) consumeEmail(purpose string) endpoint {
	return func(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
		var dto struct {
			Token    string `json:"token"`
			Password string `json:"password,omitempty"`
		}
		if err := decode(w, r, &dto); err != nil {
			return err
		}
		if err := h.service.LimitEmailConsumption(r.Context(), h.peer(r)); err != nil {
			return err
		}
		if err := h.service.ConsumeEmail(r.Context(), dto.Token, purpose, dto.Password); err != nil {
			return err
		}
		write(w, 200, map[string]string{"message": "Account request completed. Continue to sign in."})
		return nil
	}
}
func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	var dto struct {
		CurrentPassword string `json:"currentPassword"`
		Password        string `json:"password"`
		Code            string `json:"code,omitempty"`
	}
	if err := decode(w, r, &dto); err != nil {
		return err
	}
	if err := h.service.ChangePassword(r.Context(), s, h.peer(r), dto.CurrentPassword, dto.Password, dto.Code); err != nil {
		return err
	}
	write(w, 200, map[string]string{"message": "Password changed. Sign in again."})
	return nil
}
