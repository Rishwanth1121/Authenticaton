package models

import (
	"time"
)

type User struct {
	ID                  int       `json:"id" db:"id"`
	Email               string    `json:"email" db:"email"`
	InitialPasswordHash string    `json:"-" db:"initial_password_hash"`
	PasswordHash        *string   `json:"-" db:"password_hash"`
	Role                string    `json:"role" db:"role"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`
}

// HasSetPassword checks if user has set their permanent password
func (u *User) HasSetPassword() bool {
	return u.PasswordHash != nil && *u.PasswordHash != ""
}
