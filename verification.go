package tokens

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserData struct {
	ID           uuid.UUID
	DevID        uuid.UUID
	TokenVersion int
	Role         string
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

	role := claims.Role
	deviceId := claims.DeviceID

	if tokenString == "" || secretKey == "" {
		return nil, jwt.ErrTokenMalformed
	}

	cond, err := m.Bin.GetAccess(userID.String(), deviceId.String())
	if err != nil {
		return nil, err
	}
	if !cond {
		return nil, jwt.ErrTokenUnverifiable
	}

	return &UserData{
		ID:    userID,
		DevID: deviceId,
		Role:  role,
	}, nil
}
