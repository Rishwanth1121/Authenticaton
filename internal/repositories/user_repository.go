package repositories

import (
	"database/sql"
	"time"

	"github.com/Rishwanth1121/Authenticaton/auth_service/internal/models"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// GetUserByEmail finds a user by email
func (r *UserRepository) GetUserByEmail(email string) (*models.User, error) {
	query := `SELECT id, email, initial_password_hash, password_hash, role, created_at, updated_at 
	          FROM users WHERE email = $1`

	user := &models.User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.InitialPasswordHash,
		&user.PasswordHash,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

// UpdatePassword updates user's password and clears initial password
func (r *UserRepository) UpdatePassword(userID int, newPasswordHash string) error {
	query := `UPDATE users 
	          SET password_hash = $1, initial_password_hash = '', updated_at = $2 
	          WHERE id = $3`

	_, err := r.db.Exec(query, newPasswordHash, time.Now(), userID)
	return err
}

// CreateUser creates a new user (for admin to add users initially)
func (r *UserRepository) CreateUser(user *models.User) error {
	query := `INSERT INTO users (email, initial_password_hash, role) 
	          VALUES ($1, $2, $3) RETURNING id, created_at, updated_at`

	return r.db.QueryRow(query, user.Email, user.InitialPasswordHash, user.Role).Scan(
		&user.ID, &user.CreatedAt, &user.UpdatedAt,
	)
}
