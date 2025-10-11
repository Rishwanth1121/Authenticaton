package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/config"
	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/handlers"
	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/services"
	"github.com/Rishwanth1121/Authenticaton/auth-service/pkg/database"
)

func main() {
	//  Load configuration (includes .env)
	cfg := config.LoadConfig()

	//  Connect to PostgreSQL
	db := database.Connect(cfg.DBConnString)
	defer db.Close()

	//  Initialize email sender
	emailSender := services.NewEmailSender(
		cfg.SMTPHost,
		cfg.SMTPPort,
		cfg.SenderEmail,
		cfg.SenderUser,
		cfg.SenderPass,
	)

	//  Initialize password reset service + handler
	resetService := services.NewPasswordResetService(db, emailSender)
	resetHandler := handlers.NewPasswordResetHandler(resetService)

	// Register routes
	http.HandleFunc("/api/auth/forgot-password", resetHandler.ForgotPassword)
	http.HandleFunc("/api/auth/reset-password", resetHandler.ResetPassword)

	//  Start the HTTP Server
	port := cfg.Port
	if port == "" {
		port = "8080"
	}
	log.Printf(" Auth Service running on http://localhost:%s", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
		log.Fatal(" Server failed:", err)
	}
}
