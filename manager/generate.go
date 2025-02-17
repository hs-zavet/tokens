package manager

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/recovery-flow/roles"
)

type CustomClaims struct {
	jwt.RegisteredClaims
	Role     *string `json:"Role,omitempty"`
	DeviceID *string `json:"device_id,omitempty"`
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
		Role:     role,
		DeviceID: deviceID,
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
		claims.DeviceID = deviceID
	}
	if aud != nil {
		claims.Audience = aud
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(t.SecretKey))
}
