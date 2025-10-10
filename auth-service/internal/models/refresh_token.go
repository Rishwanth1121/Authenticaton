package models

import "time"

type RefreshTokenModel struct {
	ID        int
	UserID    int
	TokenHash string
	IsRevoked bool
	ExpiresAt time.Time
	CreatedAt time.Time
}
