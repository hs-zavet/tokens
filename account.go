package tokens

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/recovery-flow/tokens/identity"
)

type contextKey string

const (
	ServerKey    contextKey = "server"
	AccountIDKey contextKey = "accountID"
	IdentityKey  contextKey = "identity"
	SessionIDKey contextKey = "sessionID"
)

// VerifyJWT validates a JWT token and extracts relevant claims.
func VerifyJWT(ctx context.Context, tokenString, sk string) (userData *StandardClaims, err error) {
	claims := &StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sk), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}

type StandardClaims struct {
	jwt.RegisteredClaims
	Identity  identity.IdnType `json:"role"`
	SessionID *uuid.UUID       `json:"session_id,omitempty"`
	AccountID *uuid.UUID       `json:"account_id,omitempty"`
}

func GenerateJWT(
	iss string,           // who issued the token
	sub string,           // account id (subject)
	aud []string,         // claim identifies the recipients that the JWT is intended for
	ttl time.Duration,    // time life
	idn identity.IdnType, // user role
	sessionID *uuid.UUID, // session id
	accountID *uuid.UUID, // account id
	sk string,            // secret key
) (string, error) {
	expirationTime := time.Now().Add(ttl * time.Second)
	claims := &StandardClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		Identity:  idn,
		SessionID: sessionID,
		AccountID: accountID,
	}
	if aud != nil {
		claims.RegisteredClaims.Audience = aud
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}

func GetAccountData(ctx context.Context) (*uuid.UUID, *uuid.UUID, *identity.IdnType, *string, error) {
	initiatorID, ok := ctx.Value(AccountIDKey).(*uuid.UUID)
	if !ok {
		return nil, nil, nil, nil, fmt.Errorf("user not authenticated")
	}

	sessionID, ok := ctx.Value(SessionIDKey).(*uuid.UUID)
	if !ok {
		return nil, nil, nil, nil, fmt.Errorf("sessions not authenticated")
	}

	InitiatorRole, ok := ctx.Value(IdentityKey).(*identity.IdnType)
	if !ok {
		return nil, nil, nil, nil, fmt.Errorf("role not authenticated")
	}

	server, ok := ctx.Value(ServerKey).(*string)
	if !ok {
		return nil, nil, nil, nil, fmt.Errorf("server not authenticated")
	}

	return initiatorID, sessionID, InitiatorRole, server, nil
}
