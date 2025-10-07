package repositories

import (
	"database/sql"
	"time"
)

type TokenRepository struct {
	DB *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{DB: db}
}

//  Insert a reset token
func (r *TokenRepository) InsertResetToken(userID int64, tokenHash string, expires time.Time) error {
	_, err := r.DB.Exec(`
		INSERT INTO refresh_token (user_id, token_hash, created_at, expires_at)
		VALUES ($1, $2, NOW(), $3)
	`, userID, tokenHash, expires)
	return err
}

//  Validate reset token
func (r *TokenRepository) ValidateResetToken(tokenHash string) (int64, error) {
	var userID int64
	err := r.DB.QueryRow(`
		SELECT user_id FROM refresh_token
		WHERE token_hash=$1 AND expires_at > NOW()
	`, tokenHash).Scan(&userID)
	return userID, err
}

//  Delete token
func (r *TokenRepository) DeleteToken(tokenHash string) error {
	_, err := r.DB.Exec(`
		DELETE FROM refresh_token WHERE token_hash=$1
	`, tokenHash)
	return err
}
