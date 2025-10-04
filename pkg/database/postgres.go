package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

// Global database connection
var db *sql.DB

func ConnectPostgres() *sql.DB {
	// Get database connection details from environment variables or use defaults
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "postgres")
	password := getEnv("DB_PASSWORD", "Rishwa@1121")
	dbname := getEnv("DB_NAME", "college_auth")
	sslmode := getEnv("DB_SSLMODE", "disable")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to open database connection:", err)
	}

	// Test the connection
	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	fmt.Println("✅ Connected to PostgreSQL successfully!")
	return db
}

// GetDB returns the database connection
func GetDB() *sql.DB {
	if db == nil {
		log.Fatal("Database not connected. Call ConnectPostgres() first.")
	}
	return db
}

// Helper function to get environment variables with fallback
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
