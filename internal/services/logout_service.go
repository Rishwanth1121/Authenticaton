package services

import (
	"errors"

	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/repositories"
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

	// No hashing! Just validate directly.
	return s.TokenRepo.RevokeToken(refreshToken)
}
