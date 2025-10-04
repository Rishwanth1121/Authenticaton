package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Rishwanth1121/Authenticaton/auth_service/auth"
	"github.com/Rishwanth1121/Authenticaton/auth_service/pkg/database"
)

type AuthHandler struct {
	db *sql.DB
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{
		db: database.GetDB(),
	}
}

// LoginRequest represents first-time login with temp password
type LoginRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	NewPassword string `json:"new_password,omitempty"` // For first-time login
}

type LoginResponse struct {
	Success               bool   `json:"success"`
	Message               string `json:"message"`
	Token                 string `json:"token,omitempty"`
	RefreshToken          string `json:"refresh_token,omitempty"`
	RequiresPasswordSetup bool   `json:"requires_password_setup,omitempty"`
}

// FirstLogin handles first-time login with temporary password
func (h *AuthHandler) FirstLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" || req.NewPassword == "" {
		http.Error(w, "Email, password, and new password are required", http.StatusBadRequest)
		return
	}

	// Call the auth flow
	token, refreshToken, err := auth.FirstLogin(h.db, req.Email, req.Password, req.NewPassword)
	if err != nil {
		response := LoginResponse{
			Success: false,
			Message: err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := LoginResponse{
		Success:      true,
		Message:      "Password set successfully. Please login with your new password.",
		Token:        token,
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Login handles regular login with permanent password
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Call the auth flow
	token, refreshToken, err := auth.Login(h.db, req.Email, req.Password)
	if err != nil {
		response := LoginResponse{
			Success: false,
			Message: err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := LoginResponse{
		Success:      true,
		Message:      "Login successful",
		Token:        token,
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CheckAuth checks if a token is valid
// CheckAuth checks if a token is valid
func (h *AuthHandler) CheckAuth(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Authorization header required",
		})
		return
	}

	// Remove "Bearer " prefix if present
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	// Verify the token using auth package
	claims, err := auth.VerifyToken(token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Invalid token: %s", err.Error()),
		})
		return
	}

	// Return user information from valid token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Token is valid",
		"user": map[string]interface{}{
			"user_id": claims.UserID,
			"email":   claims.Email,
			"role":    claims.Role,
		},
	})
}

// Health check endpoint
func (h *AuthHandler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "auth_service",
	})
}
