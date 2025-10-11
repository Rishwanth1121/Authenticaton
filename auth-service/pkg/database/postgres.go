package database

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

// Connect initializes and verifies a PostgreSQL connection
func Connect(connString string) *sql.DB {
	db, err := sql.Open("postgres", connString)
	if err != nil {
		log.Fatal(" Failed to open DB connection:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal(" Database ping failed:", err)
	}

	log.Println(" Database connected successfully")
	return db
}
