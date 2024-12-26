package tokens

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserData struct {
	ID           uuid.UUID
	deviceId     uuid.UUID
	tokenVersion int
	role         string
}

// VerifyJWTAndExtractClaims validates a JWT token and extracts relevant claims.
func (m *TokenManager) VerifyJWTAndExtractClaims(tokenString string, secretKey string) (userData *UserData, err error) {
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, err
	}

	tokenVersion := claims.TokenVersion
	role := claims.Role
	deviceId := claims.DeviceID

	cond, err := m.Bin.GetAccess(userID.String(), tokenString)
	if err != nil {
		return nil, err
	}
	if !cond {
		return nil, jwt.ErrTokenUnverifiable
	}

	return &UserData{
		ID:           userID,
		deviceId:     deviceId,
		tokenVersion: tokenVersion,
		role:         role,
	}, nil
}
