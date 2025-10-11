package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/services"
)

type PasswordResetHandler struct {
	Service *services.PasswordResetService
}

func NewPasswordResetHandler(s *services.PasswordResetService) *PasswordResetHandler {
	return &PasswordResetHandler{Service: s}
}

// Forgot Password
func (h *PasswordResetHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := h.Service.RequestPasswordReset(req.Email); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset link sent to your registered email",
	})
}

// Reset Password
func (h *PasswordResetHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" || req.NewPassword == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := h.Service.ResetPassword(req.Token, req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset successful",
	})
}
