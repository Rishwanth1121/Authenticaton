package config

import (
	"log"
	"os"
)

type Config struct {
	DBConnString string
	SMTPHost     string
	SMTPPort     string
	SenderEmail  string
	SenderUser   string
	SenderPass   string
}

// LoadConfig loads strictly from environment variables
func LoadConfig() *Config {
	cfg := &Config{
		DBConnString: os.Getenv("DB_CONN_STRING"),
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     os.Getenv("SMTP_PORT"),
		SenderEmail:  os.Getenv("SENDER_EMAIL"),
		SenderUser:   os.Getenv("SENDER_USER"),
		SenderPass:   os.Getenv("SENDGRID_API_KEY"), // SendGrid key stored here
	}

	// Stop execution if any required value is missing
	if cfg.DBConnString == "" ||
		cfg.SMTPHost == "" ||
		cfg.SMTPPort == "" ||
		cfg.SenderEmail == "" ||
		cfg.SenderUser == "" ||
		cfg.SenderPass == "" {
		log.Fatal("Missing required configuration values in environment (.env)")
	}

	log.Println(" Configuration loaded successfully from .env")
	return cfg
}
