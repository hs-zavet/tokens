package tokens

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type CustomClaims struct {
	jwt.RegisteredClaims
	Role         string    `json:"role"`
	TokenVersion int       `json:"token_version"`
	DeviceID     uuid.UUID `json:"device_id"`
}

func (m *TokenManager) GenerateJWT(userID uuid.UUID, deviceID uuid.UUID, role string, tokenVersion int, tlt time.Duration, sk string) (string, error) {
	expirationTime := time.Now().Add(tlt * time.Second)
	claims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		Role:         role,
		TokenVersion: tokenVersion,
		DeviceID:     deviceID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}
