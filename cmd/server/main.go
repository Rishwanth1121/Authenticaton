package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Rishwanth1121/Authenticaton/auth_service/auth"
	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/handlers"
	"github.com/Rishwanth1121/Authenticaton/auth_service/pkg/database"
)

func main() {
	// Connect to PostgreSQL
	db := database.ConnectPostgres()
	defer db.Close()

	// Initialize JWT Manager
	auth.InitializeJWTManager("your-super-secret-key-here-make-it-very-long-and-secure-2024", 24*time.Hour)

	fmt.Println("✅ Database connected successfully")
	fmt.Println("✅ JWT Manager initialized")

	// Initialize handlers
	authHandler := handlers.NewAuthHandler()

	// Setup routes with middleware
	http.HandleFunc("/api/first-login", handlers.CORSMiddleware(handlers.LoggingMiddleware(authHandler.FirstLogin)))
	http.HandleFunc("/api/login", handlers.CORSMiddleware(handlers.LoggingMiddleware(authHandler.Login)))
	http.HandleFunc("/api/check-auth", handlers.CORSMiddleware(handlers.LoggingMiddleware(handlers.AuthMiddleware(authHandler.CheckAuth))))
	http.HandleFunc("/api/health", handlers.CORSMiddleware(handlers.LoggingMiddleware(authHandler.Health)))

	// Test the auth flow
	testAuthFlow(db)

	fmt.Println("🚀 Auth Service running on http://localhost:8080")

	// Start server
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func testAuthFlow(db *sql.DB) {
	fmt.Println("\n🧪 Testing Auth Flow...")

	// Test database connection
	var version string
	err := db.QueryRow("SELECT version()").Scan(&version)
	if err != nil {
		log.Printf("❌ Database test failed: %v", err)
	} else {
		fmt.Printf("✅ Database version: %s\n", version)
	}

	// Test if users table exists
	var tableExists bool
	err = db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_name = 'users'
		)
	`).Scan(&tableExists)

	if err != nil {
		log.Printf("❌ Table check failed: %v", err)
	} else if tableExists {
		fmt.Println("✅ Users table exists")

		// Count users
		var userCount int
		err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
		if err == nil {
			fmt.Printf("✅ Total users: %d\n", userCount)
		}
	} else {
		fmt.Println("❌ Users table does not exist")
	}

	fmt.Println("✅ Auth system ready")
	fmt.Println("📝 Available endpoints:")
	fmt.Println("   POST /api/first-login - First time login with temp password")
	fmt.Println("   POST /api/login - Regular login with permanent password")
	fmt.Println("   GET  /api/check-auth - Verify token (protected)")
	fmt.Println("   GET  /api/health - Health check")
}
