package tokens

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ServerKey   contextKey = "server"
	AudienceKey contextKey = "audience"
)

type ServiceClaims struct {
	jwt.RegisteredClaims
}

func VerifyServerJWT(ctx context.Context, tokenString, sk string) (ServiceClaims, error) {
	claims := ServiceClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sk), nil
	})

	if err != nil || !token.Valid {
		return ServiceClaims{}, err
	}

	return claims, nil
}

type GenerateServiceJwtRequest struct {
	Issuer   string        `json:"iss,omitempty"`
	Subject  string        `json:"sub,omitempty"`
	Audience []string      `json:"aud,omitempty"`
	Ttl      time.Duration `json:"ttl,omitempty"`
}

func GenerateServiceJWT(
	request GenerateServiceJwtRequest,
	sk string,
) (string, error) {
	expirationTime := time.Now().Add(request.Ttl * time.Second)
	claims := &ServiceClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    request.Issuer,
			Subject:   request.Subject,
			Audience:  jwt.ClaimStrings(request.Audience),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}
