package tokens

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ServiceClaims struct {
	jwt.RegisteredClaims
	ID string `json:"id"`
}

func GenerateServiceJWT(
	iss string, // who issued the token
	sub string, // who is the subject of the token
	aud []string, // claim identifies the recipients that the JWT is intended for
	ttl time.Duration, // time to live
	id string, // service id
	sk string, // secret key
) (string, error) {
	expirationTime := time.Now().Add(ttl * time.Second)
	claims := &ServiceClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		ID: id,
	}
	if aud != nil {
		claims.RegisteredClaims.Audience = aud
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}
