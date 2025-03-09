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
	ServerKey       contextKey = "server"
	AccountIDKey    contextKey = "account_id"
	IdentityKey     contextKey = "identity"
	SessionIDKey    contextKey = "session_id"
	SubscriptionKey contextKey = "subscription_type"
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
	SubTypeID *uuid.UUID       `json:"subscription_type,omitempty"`
}

func GenerateJWT(
	iss string, // who issued the token
	sub string, // account id (subject)
	aud []string, // claim identifies the recipients that the JWT is intended for
	ttl time.Duration, // time life
	idn identity.IdnType, // user role
	sessionID *uuid.UUID, // session id
	accountID *uuid.UUID, // account id
	subTypeID *uuid.UUID, // subscription type id
	sk string, // secret key
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
		SubTypeID: subTypeID,
	}
	if aud != nil {
		claims.RegisteredClaims.Audience = aud
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}

func GetAccountData(ctx context.Context) (
	initiatorID *uuid.UUID,
	sessionID *uuid.UUID,
	subTypeID *uuid.UUID,
	InitiatorRole *identity.IdnType,
	server *string,
	err error,
) {
	var ok bool
	initiatorID, ok = ctx.Value(AccountIDKey).(*uuid.UUID)
	if !ok {
		return nil, nil, nil, nil, nil, fmt.Errorf("user not authenticated")
	}

	sessionID, ok = ctx.Value(SessionIDKey).(*uuid.UUID)
	if !ok {
		return nil, nil, nil, nil, nil, fmt.Errorf("sessions not authenticated")
	}

	InitiatorRole, ok = ctx.Value(IdentityKey).(*identity.IdnType)
	if !ok {
		return nil, nil, nil, nil, nil, fmt.Errorf("role not authenticated")
	}

	subTypeID, ok = ctx.Value(SubscriptionKey).(*uuid.UUID)
	if !ok {
		return nil, nil, nil, nil, nil, fmt.Errorf("subscription type not authenticated")
	}

	if *InitiatorRole == identity.Service {
		server, ok := ctx.Value(ServerKey).(string)
		if !ok {
			return nil, nil, nil, nil, nil, fmt.Errorf("server not authenticated")
		}

		return initiatorID, sessionID, nil, InitiatorRole, &server, nil
	}

	return initiatorID, sessionID, subTypeID, InitiatorRole, nil, nil
}
