package tokens

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/recovery-flow/roles"
)

type TokenManager interface {
	VerifyJWT(ctx context.Context, tokenString string) (userData *CustomClaims, err error)
	AuthMdl(ctx context.Context) func(http.Handler) http.Handler
	RoleMdl(ctx context.Context, roles ...string) func(http.Handler) http.Handler
}

// VerifyJWT validates a JWT token and extracts relevant claims.
func VerifyJWT(ctx context.Context, tokenString, sk string) (userData *CustomClaims, err error) {
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sk), nil
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

func GenerateJWT(
	iss string,
	sub string,
	ttl time.Duration,
	aud []string,
	role *string,
	deviceID *string,
	sk string,
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
		_, err := roles.ParseUserRole(*role)
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
	return token.SignedString([]byte(sk))
}

func GetAccountData(ctx context.Context) (*uuid.UUID, *uuid.UUID, *roles.UserRole, error) {
	initiatorID, ok := ctx.Value(UserIDKey).(uuid.UUID)
	if !ok {
		return nil, nil, nil, fmt.Errorf("user not authenticated")
	}

	sessionID, ok := ctx.Value(SessionIDKey).(uuid.UUID)
	if !ok {
		return nil, nil, nil, fmt.Errorf("sessions not authenticated")
	}

	InitiatorRole, ok := ctx.Value(RoleKey).(roles.UserRole)
	if !ok {
		return nil, nil, nil, fmt.Errorf("role not authenticated")
	}

	return &initiatorID, &sessionID, &InitiatorRole, nil
}
