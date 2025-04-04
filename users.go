package tokens

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/hs-zavet/tokens/users"
)

type contextKey string

const (
	RoleKey         contextKey = "role"
	SubjectIDKey    contextKey = "subject"
	SessionIDKey    contextKey = "session"
	SubscriptionKey contextKey = "subscription"
)

type UserClaims struct {
	jwt.RegisteredClaims
	Role         users.Role `json:"role"`
	Session      uuid.UUID  `json:"session_id,omitempty"`
	Subscription uuid.UUID  `json:"subscription_type,omitempty"`
}

func verifyUserJWT(ctx context.Context, tokenString, sk string) (UserClaims, error) {
	claims := UserClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sk), nil
	})

	if err != nil || !token.Valid {
		return UserClaims{}, err
	}

	return claims, nil
}

type GenerateUserJwtRequest struct {
	Issuer       string           `json:"iss,omitempty"`
	Account      uuid.UUID        `json:"sub,omitempty"`
	Session      uuid.UUID        `json:"session_id,omitempty"`
	Subscription uuid.UUID        `json:"subscription_type,omitempty"`
	Role         users.Role       `json:"i,omitempty"`
	Audience     jwt.ClaimStrings `json:"aud,omitempty"`
	Ttl          time.Duration    `json:"ttl,omitempty"`
}

func GenerateUserJWT(
	request GenerateUserJwtRequest,
	sk string,
) (string, error) {
	expirationTime := time.Now().Add(request.Ttl * time.Second)
	claims := &UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    request.Issuer,
			Subject:   request.Account.String(),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		Session:      request.Session,
		Subscription: request.Subscription,
		Role:         request.Role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}
