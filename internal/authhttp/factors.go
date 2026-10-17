package authhttp

import (
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
	"net/http"
)

func (h *Handler) enrollTOTP(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	var dto struct{}
	if err := decode(w, r, &dto); err != nil {
		return err
	}
	result, err := h.service.EnrollTOTP(r.Context(), s)
	if err != nil {
		return err
	}
	write(w, 200, result)
	return nil
}
func (h *Handler) confirmTOTP(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	var dto struct {
		Code string `json:"code"`
	}
	if err := decode(w, r, &dto); err != nil {
		return err
	}
	codes, err := h.service.ConfirmTOTP(r.Context(), s, peer(r), dto.Code)
	if err != nil {
		return err
	}
	write(w, 200, map[string]any{"recoveryCodes": codes})
	return nil
}
func (h *Handler) challenge(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	var dto struct {
		Code         string `json:"code,omitempty"`
		RecoveryCode string `json:"recoveryCode,omitempty"`
	}
	if err := decode(w, r, &dto); err != nil {
		return err
	}
	result, err := h.service.Challenge(r.Context(), s, peer(r), dto.Code, dto.RecoveryCode)
	if err != nil {
		return err
	}
	h.cookie(w, result)
	write(w, 200, result)
	return nil
}
func (h *Handler) modifyTOTP(remove bool) endpoint {
	return func(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
		var dto struct {
			Password string `json:"password"`
			Code     string `json:"code"`
		}
		if err := decode(w, r, &dto); err != nil {
			return err
		}
		codes, err := h.service.ModifyTOTP(r.Context(), s, peer(r), dto.Password, dto.Code, remove)
		if err != nil {
			return err
		}
		if remove {
			write(w, 200, map[string]string{"message": "Authenticator removed."})
		} else {
			write(w, 200, map[string]any{"recoveryCodes": codes})
		}
		return nil
	}
}
