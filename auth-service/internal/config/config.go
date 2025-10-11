package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DBConnString string
}

// LoadConfig loads .env variables
func LoadConfig() *Config {
	// Load the .env file automatically
	err := godotenv.Load()
	if err != nil {
		log.Println("  Could not load .env file, trying system env variables")
	}

	dbConn := os.Getenv("DB_CONN_STRING")
	if dbConn == "" {
		log.Fatal(" Missing DB_CONN_STRING in environment")
	}

	return &Config{DBConnString: dbConn}
}
