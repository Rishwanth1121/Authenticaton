package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"

	"github.com/Rishwanth1121/Authenticaton/auth_service/auth"
	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/config"
	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/handlers"
	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/repositories"
	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/services"
	"github.com/Rishwanth1121/Authenticaton/auth_service/pkg/database"
)

func main() {
	// Load config
	cfg := config.LoadConfig()

	// Connect to DB
	db := database.ConnectPostgres()
	defer db.Close()

	// Initialize JWT
	auth.InitializeJWTManager("your-super-secret-key-here", 24*time.Hour)
	fmt.Println("✅ Database connected")
	fmt.Println("✅ JWT initialized")

	// Initialize handlers
	authHandler := handlers.NewAuthHandler()
	emailSender := services.NewEmailSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SenderEmail, cfg.SenderUser, cfg.SenderPass)
	resetService := services.NewPasswordResetService(db, emailSender)
	resetHandler := handlers.NewPasswordResetHandler(resetService)

	// Logout handler
	tokenRepo := repositories.NewTokenRepository(db)
	logoutService := services.NewLogoutService(tokenRepo)
	logoutHandler := handlers.NewLogoutHandler(logoutService)

	// Setup router
	r := mux.NewRouter()

	// --- Auth routes ---
	r.HandleFunc("/api/first-login", handlers.LoggingMiddleware(authHandler.FirstLogin)).Methods("POST")
	r.HandleFunc("/api/login", handlers.LoggingMiddleware(authHandler.Login)).Methods("POST")
	r.HandleFunc("/api/check-auth", handlers.LoggingMiddleware(handlers.AuthMiddleware(authHandler.CheckAuth))).Methods("GET")
	r.HandleFunc("/api/refresh-token", handlers.LoggingMiddleware(authHandler.RefreshToken)).Methods("POST")
	r.HandleFunc("/api/health", handlers.LoggingMiddleware(authHandler.Health)).Methods("GET")
	r.HandleFunc("/api/auth/logout", logoutHandler.Logout).Methods("POST")

	// --- Password reset routes ---
	r.HandleFunc("/api/auth/forgot-password", handlers.LoggingMiddleware(resetHandler.ForgotPassword)).Methods("POST")
	r.HandleFunc("/api/auth/reset-password", handlers.LoggingMiddleware(resetHandler.ResetPassword)).Methods("POST")

	// Serve frontend static files
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./frontend")))

	// Log routes
	r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		log.Printf("Route registered: %v %v", methods, path)
		return nil
	})

	port := cfg.Port
	if port == "" {
		port = "8080"
	}
	log.Printf("🚀 Auth service running on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), r))
}
