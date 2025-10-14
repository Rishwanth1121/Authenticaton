package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/services"
)

type LogoutHandler struct {
	LogoutService *services.LogoutService
}

func NewLogoutHandler(service *services.LogoutService) *LogoutHandler {
	return &LogoutHandler{LogoutService: service}
}

func (h *LogoutHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token := strings.TrimSpace(req.RefreshToken)
	if token == "" {
		http.Error(w, "Missing refresh_token", http.StatusBadRequest)
		return
	}

	if err := h.LogoutService.Logout(token); err != nil {
		http.Error(w, "Logout failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}
