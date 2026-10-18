package authhttp

import (
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
	"net/http"
)

func (h *Handler) registerAccountManagementRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/auth/email-change", h.wrap(h.pendingEmailChange, false))
	mux.HandleFunc("POST /api/v1/auth/email-change", h.wrap(h.requestEmailChange, true))
	mux.HandleFunc("DELETE /api/v1/auth/email-change", h.wrap(h.cancelEmailChange, true))
	mux.HandleFunc("POST /api/v1/auth/email-change/confirm", h.wrap(h.confirmEmailChange, true))
	mux.HandleFunc("DELETE /api/v1/auth/sessions/others", h.wrap(h.revokeOtherSessions, true))
	mux.HandleFunc("GET /api/v1/auth/account-closure", h.wrap(h.accountClosure, false))
	mux.HandleFunc("POST /api/v1/auth/account-closure", h.wrap(h.scheduleClosure, true))
	mux.HandleFunc("POST /api/v1/auth/account-closure/recovery/request", h.wrap(h.requestClosureRecovery, true))
	mux.HandleFunc("POST /api/v1/auth/account-closure/recovery/confirm", h.wrap(h.confirmClosureRecovery, true))
}
func (h *Handler) pendingEmailChange(w http.ResponseWriter, r *http.Request, current *auth.Session) error {
	pending, err := h.service.PendingEmail(r.Context(), current)
	if err != nil {
		return err
	}
	write(w, 200, map[string]any{"pending": pending})
	return nil
}
func (h *Handler) requestEmailChange(w http.ResponseWriter, r *http.Request, current *auth.Session) error {
	var body struct {
		Email string `json:"email"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if err := h.service.RequestEmailChange(r.Context(), current, h.peer(r), body.Email); err != nil {
		return err
	}
	write(w, 202, map[string]string{"message": "If this address is available, check its inbox to confirm the change. Your current email remains active until confirmation."})
	return nil
}
func (h *Handler) cancelEmailChange(w http.ResponseWriter, r *http.Request, current *auth.Session) error {
	if err := h.service.CancelEmailChange(r.Context(), current); err != nil {
		return err
	}
	write(w, 200, map[string]string{"message": "Pending email change canceled."})
	return nil
}
func (h *Handler) confirmEmailChange(w http.ResponseWriter, r *http.Request, current *auth.Session) error {
	var body struct {
		Token string `json:"token"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if err := h.service.ConfirmEmailChange(r.Context(), current, h.peer(r), body.Token); err != nil {
		return err
	}
	h.clearSessionCookie(w)
	write(w, 200, map[string]string{"message": "Email changed. Sign in again with your new address."})
	return nil
}
func (h *Handler) revokeOtherSessions(w http.ResponseWriter, r *http.Request, current *auth.Session) error {
	count, err := h.service.RevokeOtherSessions(r.Context(), current)
	if err != nil {
		return err
	}
	write(w, 200, map[string]any{"revokedCount": count})
	return nil
}
func (h *Handler) accountClosure(w http.ResponseWriter, r *http.Request, current *auth.Session) error {
	status, err := h.service.AccountClosure(r.Context(), current)
	if err != nil {
		return err
	}
	write(w, 200, status)
	return nil
}
func (h *Handler) scheduleClosure(w http.ResponseWriter, r *http.Request, current *auth.Session) error {
	if err := decode(w, r, &struct{}{}); err != nil {
		return err
	}
	expiry, err := h.service.ScheduleClosure(r.Context(), current)
	if err != nil {
		return err
	}
	h.clearSessionCookie(w)
	write(w, 202, map[string]any{"message": "Account closed. You can recover it within 30 days using your email, password and enrolled authentication factor.", "expiresAt": expiry})
	return nil
}
func (h *Handler) requestClosureRecovery(w http.ResponseWriter, r *http.Request, current *auth.Session) error {
	if err := anonymous(current); err != nil {
		return err
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if err := h.service.RequestClosureRecovery(r.Context(), h.peer(r), body.Email); err != nil {
		return err
	}
	write(w, 202, map[string]string{"message": "If this account is eligible for recovery, check your inbox for a recovery link."})
	return nil
}
func (h *Handler) confirmClosureRecovery(w http.ResponseWriter, r *http.Request, current *auth.Session) error {
	if err := anonymous(current); err != nil {
		return err
	}
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if err := h.service.ConfirmClosureRecovery(r.Context(), h.peer(r), body.Token, body.Password, body.Code); err != nil {
		return err
	}
	write(w, 200, map[string]string{"message": "Account recovered. Sign in to continue."})
	return nil
}
func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: "", Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
