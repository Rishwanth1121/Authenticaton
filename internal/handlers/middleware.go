package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Rishwanth1121/Authenticaton/auth_service/auth"
)

// AuthMiddleware verifies JWT token for protected routes
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

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
		if len(token) > 7 && strings.HasPrefix(token, "Bearer ") {
			token = token[7:]
		}

		// Verify the token
		claims, err := auth.VerifyToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Invalid token: %s", err.Error()),
			})
			return
		}

		// Add user info to request context for use in handlers
		// You can store claims in context if needed by subsequent handlers
		_ = claims // Using claims to avoid unused variable warning

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}

// CORSMiddleware handles CORS headers
func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}

// LoggingMiddleware logs all requests
func LoggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[%s] %s %s\n", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	}
}

// AdminMiddleware checks if user has admin role
func AdminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

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
		if len(token) > 7 && strings.HasPrefix(token, "Bearer ") {
			token = token[7:]
		}

		// Verify the token and check role
		claims, err := auth.VerifyToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Invalid token: %s", err.Error()),
			})
			return
		}

		// Check if user has admin role
		if claims.Role != "admin" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Admin access required",
			})
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}

// ContentTypeMiddleware ensures JSON content type for requests
func ContentTypeMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// For POST, PUT, PATCH requests, check Content-Type
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"message": "Content-Type must be application/json",
				})
				return
			}
		}

		// Set response content type to JSON
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	}
}
