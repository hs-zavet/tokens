package tokens

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/hs-zavet/tokens/roles"
)

type contextKey string

const (
	RoleKey         contextKey = "role"
	SubjectIDKey    contextKey = "subject"
	SessionIDKey    contextKey = "session"
	SubscriptionKey contextKey = "subscription"
)

type AccountClaims struct {
	jwt.RegisteredClaims
	Role         roles.Role `json:"role"`
	Session      uuid.UUID  `json:"session_id,omitempty"`
	Subscription uuid.UUID  `json:"subscription_type,omitempty"`
}

func VerifyAccountsJWT(ctx context.Context, tokenString, sk string) (AccountClaims, error) {
	claims := AccountClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sk), nil
	})
	if err != nil || !token.Valid {
		return AccountClaims{}, err
	}
	return claims, nil
}

type GenerateUserJwtRequest struct {
	Issuer       string           `json:"iss,omitempty"`
	Account      uuid.UUID        `json:"sub,omitempty"`
	Session      uuid.UUID        `json:"session_id,omitempty"`
	Subscription uuid.UUID        `json:"subscription_type,omitempty"`
	Role         roles.Role       `json:"i,omitempty"`
	Audience     jwt.ClaimStrings `json:"aud,omitempty"`
	Ttl          time.Duration    `json:"ttl,omitempty"`
}

func GenerateUserJWT(
	request GenerateUserJwtRequest,
	sk string,
) (string, error) {
	expirationTime := time.Now().Add(request.Ttl * time.Second)
	claims := &AccountClaims{
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

type AccountData struct {
	AccountID uuid.UUID  `json:"account_id,omitempty"`
	SessionID uuid.UUID  `json:"session_id,omitempty"`
	SubTypeID uuid.UUID  `json:"subscription_type,omitempty"`
	Role      roles.Role `json:"role"`
}

func GetTokenData(ctx context.Context) (
	data AccountData,
	err error,
) {
	account, ok := ctx.Value(SubjectIDKey).(string)
	if !ok {
		return AccountData{}, fmt.Errorf("user not authenticated")
	}
	accountID, err := uuid.Parse(account)
	if err != nil {
		return AccountData{}, fmt.Errorf("user not authenticated")
	}

	session, ok := ctx.Value(SessionIDKey).(uuid.UUID)
	if !ok {
		return AccountData{}, fmt.Errorf("sessions not authenticated")
	}

	role, ok := ctx.Value(RoleKey).(roles.Role)
	if !ok {
		return AccountData{}, fmt.Errorf("role not authenticated")
	}

	sub, ok := ctx.Value(SubscriptionKey).(uuid.UUID)
	if !ok {
		return AccountData{}, fmt.Errorf("subscription type not authenticated")
	}

	return AccountData{
		AccountID: accountID,
		SessionID: session,
		SubTypeID: sub,
		Role:      role,
	}, nil
}
