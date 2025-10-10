package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"

	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/config"
	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/handlers"
	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/repositories"
	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/services"
)

func main() {
	cfg := config.LoadConfig()

	db, err := sql.Open("postgres", cfg.DBConnString)
	if err != nil {
		log.Fatal("Failed to connect DB:", err)
	}
	defer db.Close()

	// --- setup dependencies ---
	tokenRepo := repositories.NewTokenRepository(db)
	logoutService := services.NewLogoutService(tokenRepo)
	logoutHandler := handlers.NewLogoutHandler(logoutService)

	// --- setup router ---
	r := mux.NewRouter()

	//  make sure this route is added
	r.HandleFunc("/api/auth/logout", logoutHandler.Logout).Methods("POST")

	log.Println(" Auth service running on port 8080")
	http.ListenAndServe(":8080", r)
}
