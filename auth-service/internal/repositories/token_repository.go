package repositories

import (
	"database/sql"
)

type TokenRepository struct {
	DB *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{DB: db}
}

// Mark a refresh token as revoked
func (r *TokenRepository) RevokeToken(tokenHash string) error {
	query := `DELETE FROM refresh_token WHERE token_hash = $1`

	_, err := r.DB.Exec(query, tokenHash)
	return err
}
