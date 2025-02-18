package tokens

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/recovery-flow/roles"
)

type TokenManager interface {
	GenerateJWT(
		iss string,
		sub string,
		ttl time.Duration,
		aud []string,
		role *string,
		deviceID *string,
	) (string, error)

	ExtractJWT(ctx context.Context) (string, error)
	VerifyJWT(ctx context.Context, tokenString string) (userData *CustomClaims, err error)
	AuthMdl(ctx context.Context) func(http.Handler) http.Handler
	RoleMdl(ctx context.Context, roles ...string) func(http.Handler) http.Handler
}

type tokenManager struct {
	SecretKey string
}

func NewTokenManager(sk string) TokenManager {
	return &tokenManager{
		SecretKey: sk,
	}
}

func (t *tokenManager) ExtractJWT(ctx context.Context) (string, error) {
	req, ok := ctx.Value("userID").(*http.Request)
	if !ok || req == nil {
		return "", fmt.Errorf("failed to retrieve HTTP request from context")
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

// VerifyJWT validates a JWT token and extracts relevant claims.
func (t *tokenManager) VerifyJWT(ctx context.Context, tokenString string) (userData *CustomClaims, err error) {
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(t.SecretKey), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}

type CustomClaims struct {
	jwt.RegisteredClaims
	Role      *string `json:"role,omitempty"`
	SessionID *string `json:"session_id,omitempty"`
}

func (t *tokenManager) GenerateJWT(
	iss string,
	sub string,
	ttl time.Duration,
	aud []string,
	role *string,
	deviceID *string,
) (string, error) {
	expirationTime := time.Now().Add(ttl * time.Second)
	claims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		Role:      role,
		SessionID: deviceID,
	}
	if role != nil {
		_, err := roles.StringToRoleUser(*role)
		if err != nil {
			return "", fmt.Errorf("invalid role: %w", err)
		}
		claims.Role = role
	}
	if deviceID != nil {
		_, err := uuid.Parse(*deviceID)
		if err != nil {
			return "", fmt.Errorf("invalid device id: %w", err)
		}
		claims.SessionID = deviceID
	}
	if aud != nil {
		claims.Audience = aud
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(t.SecretKey))
}
