package repositories

import (
	"database/sql"
	"time"

	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/models"
)

type TokenRepository struct {
	db *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

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
