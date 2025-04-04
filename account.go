package tokens

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/hs-zavet/tokens/identity"
)

type contextKey string

const (
	SubjectIDKey    contextKey = "subject"
	RoleKey         contextKey = "role"
	SessionIDKey    contextKey = "session"
	SubscriptionKey contextKey = "subscription"
)

// VerifyJWT validates a JWT token and extracts relevant claims.
func VerifyJWT(ctx context.Context, tokenString, sk string) (userData StandardClaims, err error) {
	claims := StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sk), nil
	})

	if err != nil || !token.Valid {
		return StandardClaims{}, err
	}

	return claims, nil
}

type StandardClaims struct {
	jwt.RegisteredClaims
	Role      identity.Role `json:"role"`
	AccountID uuid.UUID     `json:"account_id"`
	SessionID uuid.UUID     `json:"session_id,omitempty"`
	SubID     uuid.UUID     `json:"subscription_type,omitempty"`
}

type GenerateJwtRequest struct {
	Issuer    string           `json:"iss,omitempty"`
	Subject   string           `json:"sub,omitempty"`
	SessionID uuid.UUID        `json:"session_id,omitempty"`
	SubsID    uuid.UUID        `json:"subscription_type,omitempty"`
	AccountID uuid.UUID        `json:"account_id,omitempty"`
	Role      identity.Role    `json:"i,omitempty"`
	Audience  jwt.ClaimStrings `json:"aud,omitempty"`
	Ttl       time.Duration    `json:"ttl,omitempty"`
}

func GenerateJWT(
	request GenerateJwtRequest,
	sk string,
) (string, error) {
	expirationTime := time.Now().Add(request.Ttl * time.Second)
	claims := &StandardClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    request.Issuer,
			Subject:   request.Subject,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		AccountID: request.AccountID,
		SessionID: request.SessionID,
		SubID:     request.SubsID,
		Role:      request.Role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}

type AccountData struct {
	AccountID uuid.UUID     `json:"account_id,omitempty"`
	SessionID uuid.UUID     `json:"session_id,omitempty"`
	SubTypeID uuid.UUID     `json:"subscription_type,omitempty"`
	Role      identity.Role `json:"role"`
}

func GetAccountData(ctx context.Context) (
	data AccountData,
	err error,
) {
	var ok bool
	account, ok := ctx.Value(SubjectIDKey).(uuid.UUID)
	if !ok {
		return AccountData{}, fmt.Errorf("user not authenticated")
	}

	session, ok := ctx.Value(SessionIDKey).(uuid.UUID)
	if !ok {
		return AccountData{}, fmt.Errorf("sessions not authenticated")
	}

	role, ok := ctx.Value(RoleKey).(identity.Role)
	if !ok {
		return AccountData{}, fmt.Errorf("role not authenticated")
	}

	sub, ok := ctx.Value(SubscriptionKey).(uuid.UUID)
	if !ok {
		return AccountData{}, fmt.Errorf("subscription type not authenticated")
	}

	return AccountData{
		AccountID: account,
		SessionID: session,
		SubTypeID: sub,
		Role:      role,
	}, nil
}
