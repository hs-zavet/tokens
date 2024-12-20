package cifrajwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type CustomClaims struct {
	jwt.RegisteredClaims
	Role         string `json:"role"`
	TokenVersion int    `json:"token_version"`
}

func GenerateJWT(userID uuid.UUID, role string, tokenVersion int, tlt time.Duration, sk string) (string, error) {
	expirationTime := time.Now().Add(tlt)
	claims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		Role:         role,
		TokenVersion: tokenVersion,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}
