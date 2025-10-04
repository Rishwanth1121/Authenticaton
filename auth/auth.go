package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/models"
	"github.com/Rishwanth1121/Authenticaton/auth_service/pkg/jwt"
	"golang.org/x/crypto/bcrypt"
)

// JWT manager instance
var jwtManager *jwt.JWTManager

// InitializeJWTManager sets up the JWT manager (call this from main.go)
func InitializeJWTManager(secretKey string, tokenDuration time.Duration) {
	jwtManager = jwt.NewJWTManager(secretKey, tokenDuration)
}

// VerifyToken verifies a JWT token and returns claims
func VerifyToken(tokenString string) (*jwt.Claims, error) {
	if jwtManager == nil {
		return nil, fmt.Errorf("JWT manager not initialized")
	}
	return jwtManager.Verify(tokenString)
}

// Check first-time login temp password
func CheckInitialPassword(db *sql.DB, email, password string) (*models.User, bool) {
	var user models.User
	err := db.QueryRow(
		"SELECT id, email, initial_password_hash, password_hash, role FROM users WHERE email=$1",
		email,
	).Scan(&user.ID, &user.Email, &user.InitialPasswordHash, &user.PasswordHash, &user.Role)

	if err != nil {
		return nil, false
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.InitialPasswordHash), []byte(password))
	if err != nil {
		return nil, false
	}

	return &user, true
}

// Set new password after first login
func SetNewPassword(db *sql.DB, userID int, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Exec(
		"UPDATE users SET password_hash=$1, initial_password_hash='', updated_at=NOW() WHERE id=$2",
		string(hash),
		userID,
	)
	return err
}

// Generate and hash refresh token
func GenerateRefreshToken() (string, string) {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)

	hash, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return token, string(hash)
}

// Store refresh token in DB
func StoreRefreshToken(db *sql.DB, userID int, tokenHash string, expiresAt time.Time) error {
	_, err := db.Exec(
		"INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
		userID, tokenHash, expiresAt,
	)
	return err
}

// Get user by ID for JWT generation
func GetUserByID(db *sql.DB, userID int) (*models.User, error) {
	var user models.User
	err := db.QueryRow(
		"SELECT id, email, role FROM users WHERE id=$1",
		userID,
	).Scan(&user.ID, &user.Email, &user.Role)

	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Full first-login flow
func FirstLogin(db *sql.DB, email, tempPassword, newPassword string) (string, string, error) {
	// Check temporary password
	user, ok := CheckInitialPassword(db, email, tempPassword)
	if !ok {
		return "", "", fmt.Errorf("invalid temporary password")
	}

	// Set new permanent password
	err := SetNewPassword(db, user.ID, newPassword)
	if err != nil {
		return "", "", fmt.Errorf("failed to set new password: %v", err)
	}

	// Get updated user info
	updatedUser, err := GetUserByID(db, user.ID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get user: %v", err)
	}

	// Generate JWT token
	jwtToken, err := jwtManager.Generate(updatedUser)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate token: %v", err)
	}

	// Generate refresh token
	refreshToken, refreshHash := GenerateRefreshToken()
	err = StoreRefreshToken(db, user.ID, refreshHash, time.Now().Add(7*24*time.Hour))
	if err != nil {
		return "", "", fmt.Errorf("failed to store refresh token: %v", err)
	}

	return jwtToken, refreshToken, nil
}

// Regular login with permanent password
func Login(db *sql.DB, email, password string) (string, string, error) {
	var user models.User
	err := db.QueryRow(
		"SELECT id, email, password_hash, role FROM users WHERE email=$1",
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role)

	if err != nil {
		return "", "", fmt.Errorf("user not found")
	}

	// Check if password is set
	if user.PasswordHash == nil || *user.PasswordHash == "" {
		return "", "", fmt.Errorf("password not set, please use first-time login")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(password))
	if err != nil {
		return "", "", fmt.Errorf("invalid password")
	}

	// Generate JWT token
	jwtToken, err := jwtManager.Generate(&user)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate token: %v", err)
	}

	// Generate refresh token
	refreshToken, refreshHash := GenerateRefreshToken()
	err = StoreRefreshToken(db, user.ID, refreshHash, time.Now().Add(7*24*time.Hour))
	if err != nil {
		return "", "", fmt.Errorf("failed to store refresh token: %v", err)
	}

	return jwtToken, refreshToken, nil
}
