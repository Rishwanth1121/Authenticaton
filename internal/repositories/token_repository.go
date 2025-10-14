package repositories

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/models"
)

type TokenRepository struct {
	db *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

//
// =====================
// Refresh Token Methods
// =====================
//

// CreateRefreshToken stores a new refresh token
func (r *TokenRepository) CreateRefreshToken(token *models.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) 
	          VALUES ($1, $2, $3) RETURNING id, created_at`

	return r.db.QueryRow(query, token.UserID, token.TokenHash, token.ExpiresAt).Scan(
		&token.ID, &token.CreatedAt,
	)
}

// GetRefreshToken finds a refresh token by hash
func (r *TokenRepository) GetRefreshToken(tokenHash string) (*models.RefreshToken, error) {
	query := `SELECT id, user_id, token_hash, expires_at, created_at 
	          FROM refresh_tokens WHERE token_hash = $1`

	token := &models.RefreshToken{}
	err := r.db.QueryRow(query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return token, nil
}

// DeleteRefreshToken removes a refresh token
func (r *TokenRepository) DeleteRefreshToken(tokenHash string) error {
	query := `DELETE FROM refresh_tokens WHERE token_hash = $1`
	_, err := r.db.Exec(query, tokenHash)
	return err
}

// DeleteExpiredTokens cleans up expired tokens
func (r *TokenRepository) DeleteExpiredTokens() error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < $1`
	_, err := r.db.Exec(query, time.Now())
	return err
}

//
// =====================
// Password Reset Methods
// =====================
//

// InsertResetToken stores a password reset token
func (r *TokenRepository) InsertResetToken(userID int64, tokenHash string, expires time.Time) error {
	_, err := r.db.Exec(`
		INSERT INTO reset_tokens (user_id, token_hash, created_at, expires_at)
		VALUES ($1, $2, NOW(), $3)
	`, userID, tokenHash, expires)
	return err
}

// ValidateResetToken validates a password reset token
func (r *TokenRepository) ValidateResetToken(tokenHash string) (int64, error) {
	var userID int64
	err := r.db.QueryRow(`
		SELECT user_id FROM reset_tokens
		WHERE token_hash=$1 AND expires_at > NOW()
	`, tokenHash).Scan(&userID)
	return userID, err
}

// DeleteResetToken deletes a password reset token
func (r *TokenRepository) DeleteResetToken(tokenHash string) error {
	_, err := r.db.Exec(`
		DELETE FROM reset_tokens WHERE token_hash=$1
	`, tokenHash)
	return err
}

//
// =====================
// Logout Support Methods
// =====================
//

// Exists checks if the refresh token exists
func (r *TokenRepository) Exists(token string) (bool, error) {
	token = strings.TrimSpace(token)

	var dbToken string
	query := `SELECT token_hash FROM refresh_tokens WHERE token_hash = $1`
	err := r.db.QueryRow(query, token).Scan(&dbToken)
	if err == sql.ErrNoRows {
		fmt.Printf("❌ Token not found in DB. Sent=[%s]\n", token)
		return false, nil
	} else if err != nil {
		return false, err
	}

	fmt.Printf("✅ Token matched! Sent=[%s] DB=[%s]\n", token, dbToken)
	return true, nil
}

// RevokeToken deletes the refresh token if valid
func (r *TokenRepository) RevokeToken(token string) error {
	exists, err := r.Exists(token)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("invalid or expired refresh token")
	}

	query := `DELETE FROM refresh_tokens WHERE token_hash = $1`
	result, err := r.db.Exec(query, token)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("no token deleted")
	}

	log.Printf("🔒 Refresh token revoked: %s", token)
	return nil
}
