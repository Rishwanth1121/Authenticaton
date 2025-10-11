package services

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rishwanth1121/Authenticaton/auth-service/internal/repositories"
	"golang.org/x/crypto/bcrypt"
)

// Interface for sending email
type EmailService interface {
	SendEmail(to, subject, body string) error
}

// Service for handling password resets
type PasswordResetService struct {
	DB          *sql.DB
	TokenRepo   *repositories.TokenRepository
	EmailSender EmailService
}

// Constructor
func NewPasswordResetService(db *sql.DB, emailSender EmailService) *PasswordResetService {
	return &PasswordResetService{
		DB:          db,
		TokenRepo:   repositories.NewTokenRepository(db),
		EmailSender: emailSender,
	}
}

// Helper to hash token
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// Helper to generate token
func generateRandomToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b)[:length], nil
}

// Step 1: Forgot Password
func (s *PasswordResetService) RequestPasswordReset(email string) error {
	email = strings.TrimSpace(email) // remove spaces

	var userID int64
	err := s.DB.QueryRow(`
		SELECT id FROM users WHERE LOWER(email) = LOWER($1)
	`, email).Scan(&userID)

	if err == sql.ErrNoRows {
		return errors.New("user not found")
	} else if err != nil {
		return fmt.Errorf("query error: %v", err)
	}

	resetToken, err := generateRandomToken(32)
	if err != nil {
		return err
	}

	hashed := hashToken(resetToken)
	expires := time.Now().Add(15 * time.Minute)

	if err := s.TokenRepo.InsertResetToken(userID, hashed, expires); err != nil {
		return fmt.Errorf("insert reset token failed: %w", err)
	}

	resetLink := fmt.Sprintf("http://localhost:4444/reset-password?token=%s", resetToken)
	subject := "Password Reset Request"
	body := fmt.Sprintf(`
		Hi,<br><br>
		You requested to reset your password.<br><br>
		Click the link below to reset it:<br>
		<a href="%s">%s</a><br><br>
		If you didn't request this, please ignore this email.<br><br>
		Best,<br>
		Auth Service Team
	`, resetLink, resetLink)

	if err := s.EmailSender.SendEmail(email, subject, body); err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

// Step 2: Reset Password
func (s *PasswordResetService) ResetPassword(token, newPassword string) error {
	hashed := hashToken(token)
	userID, err := s.TokenRepo.ValidateResetToken(hashed)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = s.DB.Exec(`UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2`, hashedPass, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	_ = s.TokenRepo.DeleteToken(hashed)
	return nil
}
