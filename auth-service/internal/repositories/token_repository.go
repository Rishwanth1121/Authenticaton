package repositories

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
)

type TokenRepository struct {
	DB *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{DB: db}
}

// Exists checks if the refresh token exists in DB
func (r *TokenRepository) Exists(token string) (bool, error) {
	token = strings.TrimSpace(token)

	var dbToken string
	query := `SELECT token_hash FROM refresh_token WHERE token_hash = $1`
	err := r.DB.QueryRow(query, token).Scan(&dbToken)
	if err == sql.ErrNoRows {
		fmt.Printf(" Token not found in DB. Sent=[%s]\n", token)
		return false, nil
	} else if err != nil {
		return false, err
	}

	fmt.Printf("Token matched! Sent=[%s] DB=[%s]\n", token, dbToken)
	return true, nil
}

// RevokeToken deletes the token if it exists
func (r *TokenRepository) RevokeToken(token string) error {
	exists, err := r.Exists(token)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("invalid or expired refresh token")
	}

	query := `DELETE FROM refresh_token WHERE token_hash = $1`
	result, err := r.DB.Exec(query, token)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("no token deleted")
	}

	log.Printf(" Refresh token revoked: %s", token)
	return nil
}
