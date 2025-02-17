package manager

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// VerifyJWT validates a JWT token and extracts relevant claims.
func (t *tokenManager) VerifyJWT(ctx context.Context, tokenString string) (userData *CustomClaims, err error) {
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(t.SecretKey), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, err
	}

	deviceId := claims.DeviceID

	if tokenString == "" || t.SecretKey == "" {
		return nil, jwt.ErrTokenMalformed
	}

	cond, err := t.Bin.GetAccess(ctx, userID.String(), *deviceId)
	if err != nil {
		return nil, err
	}
	if !cond {
		return nil, jwt.ErrTokenUnverifiable
	}

	return claims, nil
}
