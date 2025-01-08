package tokens

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type UserData struct {
	ID    uuid.UUID
	DevID uuid.UUID
	Role  string
}

// VerifyJWTAndExtractClaims validates a JWT token and extracts relevant claims.
func (m *tokenManager) VerifyJWTAndExtractClaims(tokenString string, secretKey string) (userData *UserData, err error) {
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

func (m *tokenManager) VerifyServiceJWT(tokenString, secretKey string) (*ServiceClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &ServiceClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*ServiceClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid service token")
	}

	return claims, nil
}
