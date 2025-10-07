package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/config"
	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/handlers"
	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/services"
)

func main() {
	//  Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal(" Failed to load .env file — make sure it exists in the project root")
	}

	//  Load configuration from environment
	cfg := config.LoadConfig()

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", cfg.DBConnString)
	if err != nil {
		log.Fatal(" DB connection failed:", err)
	}
	defer db.Close()

	//  Initialize Email Sender
	emailSender := services.NewEmailSender(
		cfg.SMTPHost,
		cfg.SMTPPort,
		cfg.SenderEmail,
		cfg.SenderUser,
		cfg.SenderPass,
	)

	//  Initialize Password Reset Service + Handler
	resetService := services.NewPasswordResetService(db, emailSender)
	resetHandler := handlers.NewPasswordResetHandler(resetService)

	//  Register Routes
	http.HandleFunc("/api/auth/forgot-password", resetHandler.ForgotPassword)
	http.HandleFunc("/api/auth/reset-password", resetHandler.ResetPassword)

	//  Start the HTTP Server
	log.Println(" Auth Service running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(" Server failed:", err)
	}
}
