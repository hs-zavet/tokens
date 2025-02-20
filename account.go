package tokens

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/recovery-flow/roles"
)

// VerifyJWT validates a JWT token and extracts relevant claims.
func VerifyJWT(ctx context.Context, tokenString, sk string) (userData *AccountClaims, err error) {
	claims := &AccountClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sk), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}

type AccountClaims struct {
	jwt.RegisteredClaims
	Role      roles.UserRole `json:"role,omitempty"`
	SessionID uuid.UUID      `json:"session_id,omitempty"`
}

func GenerateAccountJWT(
	iss string, // who issued the token
	sub string, // who is the subject of the token
	aud []string, // claim identifies the recipients that the JWT is intended for
	ttl time.Duration, // time life
	role roles.UserRole, // user role
	sessionID uuid.UUID, // session id
	sk string, // secret key
) (string, error) {
	expirationTime := time.Now().Add(ttl * time.Second)
	claims := &AccountClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		Role:      role,
		SessionID: sessionID,
	}
	if aud != nil {
		claims.RegisteredClaims.Audience = aud
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
