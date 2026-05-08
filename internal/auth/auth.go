package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	RoleAdmin       = "admin"
	minPasswordSize = 12
	tokenBytes      = 32
	bcryptCost      = 12
)

var (
	ErrUserExists      = errors.New("user already exists")
	ErrUserNotFound    = errors.New("user not found")
	ErrSessionNotFound = errors.New("session not found")
)

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

type NewUser struct {
	Username     string
	PasswordHash string
	Role         string
}

type Session struct {
	TokenHash string
	UserID    int64
	CSRFToken string
	ExpiresAt time.Time
}

type NewSession struct {
	TokenHash string
	UserID    int64
	CSRFToken string
	ExpiresAt time.Time
}

func NormalizeUsername(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func ValidateUsername(value string) error {
	if len(value) < 3 || len(value) > 64 {
		return errors.New("username must be between 3 and 64 characters")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return errors.New("username may only contain lowercase letters, numbers, hyphens, underscores, and periods")
	}
	return nil
}

func ValidatePassword(value string) error {
	if len(value) < minPasswordSize {
		return errors.New("password must be at least 12 characters")
	}
	if len(value) > 1024 {
		return errors.New("password must be 1024 characters or fewer")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPassword(passwordHash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) == nil
}

func NewSessionToken() (string, error) {
	return randomToken()
}

func NewCSRFToken() (string, error) {
	return randomToken()
}

func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	bytes := make([]byte, tokenBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
