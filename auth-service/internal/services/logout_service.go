package services

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/repositories"
)

type LogoutService struct {
	TokenRepo *repositories.TokenRepository
}

func NewLogoutService(tokenRepo *repositories.TokenRepository) *LogoutService {
	return &LogoutService{TokenRepo: tokenRepo}
}

// Logout revokes the given refresh token
func (s *LogoutService) Logout(refreshToken string) error {
	if refreshToken == "" {
		return errors.New("refresh token is required")
	}

	// hash the token before comparing with DB value
	hash := sha256.Sum256([]byte(refreshToken))
	tokenHash := hex.EncodeToString(hash[:])

	return s.TokenRepo.RevokeToken(tokenHash)
}
