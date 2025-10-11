package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DBConnString string
	SMTPHost     string
	SMTPPort     string
	SenderEmail  string
	SenderUser   string
	SenderPass   string
	Port         string
}

// LoadConfig loads from .env file and system environment variables
func LoadConfig() *Config {
	// Try loading .env file
	if err := godotenv.Load(); err != nil {
		log.Println("  .env file not found, using system environment variables")
	}

	cfg := &Config{
		DBConnString: os.Getenv("DB_CONN_STRING"),
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     os.Getenv("SMTP_PORT"),
		SenderEmail:  os.Getenv("SENDER_EMAIL"),
		SenderUser:   os.Getenv("SENDER_USER"),
		SenderPass:   os.Getenv("SENDGRID_API_KEY"),
		Port:         os.Getenv("PORT"),
	}

	// Validate required fields
	if cfg.DBConnString == "" {
		log.Fatal(" Missing DB_CONN_STRING in environment")
	}

	log.Println(" Configuration loaded successfully")
	return cfg
}
