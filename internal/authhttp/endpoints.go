package authhttp

import (
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
	"net/http"
)

func (h *Handler) register(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	if err := anonymous(s); err != nil {
		return err
	}
	var dto struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &dto); err != nil {
		return err
	}
	if err := h.service.Register(r.Context(), peer(r), dto.Name, dto.Email, dto.Password); err != nil {
		return err
	}
	write(w, 202, map[string]string{"message": "If this address can be registered, check your email to continue."})
	return nil
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	if err := anonymous(s); err != nil {
		return err
	}
	var dto struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &dto); err != nil {
		return err
	}
	next, err := h.service.Login(r.Context(), s, peer(r), dto.Email, dto.Password)
	if err != nil {
		return err
	}
	h.cookie(w, next)
	write(w, 200, next)
	return nil
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	if err := decode(w, r, &struct{}{}); err != nil {
		return err
	}
	next, err := h.service.Logout(r.Context(), s)
	if err != nil {
		return err
	}
	h.cookie(w, next)
	write(w, 200, next)
	return nil
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	if err := s.RequireAuthenticated(); err != nil {
		return err
	}
	write(w, 200, map[string]any{"user": s.User})
	return nil
}

func (h *Handler) profile(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	var dto struct {
		Name string `json:"name"`
	}
	if err := decode(w, r, &dto); err != nil {
		return err
	}
	u, err := h.service.Profile(r.Context(), s, dto.Name)
	if err != nil {
		return err
	}
	write(w, 200, map[string]any{"user": u})
	return nil
}

func (h *Handler) sessions(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	items, err := h.service.Sessions(r.Context(), s)
	if err != nil {
		return err
	}
	write(w, 200, map[string]any{"sessions": items})
	return nil
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	if err := h.service.Revoke(r.Context(), s, r.PathValue("id")); err != nil {
		return err
	}
	if s.ID == r.PathValue("id") {
		http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: "", Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	}
	write(w, 200, map[string]string{"message": "Session revoked."})
	return nil
}

func (h *Handler) reauthenticate(w http.ResponseWriter, r *http.Request, s *auth.Session) error {
	var dto struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decode(w, r, &dto); err != nil {
		return err
	}
	if err := h.service.Reauthenticate(r.Context(), s, peer(r), dto.Password, dto.Code); err != nil {
		return err
	}
	write(w, 200, map[string]string{"message": "Identity confirmed."})
	return nil
}
