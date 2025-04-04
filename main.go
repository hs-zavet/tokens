package tokens

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/hs-zavet/tokens/users"
)

type TokenData struct {
	AccountID uuid.UUID  `json:"account_id,omitempty"`
	SessionID uuid.UUID  `json:"session_id,omitempty"`
	SubTypeID uuid.UUID  `json:"subscription_type,omitempty"`
	Role      users.Role `json:"role"`
	Subject   string
	Audience  []string
}

func GetAccountData(ctx context.Context) (
	data TokenData,
	err error,
) {
	var ok bool
	account, ok := ctx.Value(SubjectIDKey).(uuid.UUID)
	if !ok {
		return TokenData{}, fmt.Errorf("user not authenticated")
	}

	session, ok := ctx.Value(SessionIDKey).(uuid.UUID)
	if !ok {
		return TokenData{}, fmt.Errorf("sessions not authenticated")
	}

	role, ok := ctx.Value(RoleKey).(users.Role)
	if !ok {
		return TokenData{}, fmt.Errorf("role not authenticated")
	}

	sub, ok := ctx.Value(SubscriptionKey).(uuid.UUID)
	if !ok {
		return TokenData{}, fmt.Errorf("subscription type not authenticated")
	}

	if data.Subject, ok = ctx.Value(ServerKey).(string); !ok {
		return TokenData{}, fmt.Errorf("service not found")
	}

	if data.Audience, ok = ctx.Value(AudienceKey).([]string); !ok {
		return TokenData{}, fmt.Errorf("aurdiance not found")
	}

	return TokenData{
		AccountID: account,
		SessionID: session,
		SubTypeID: sub,
		Role:      role,
		Subject:   data.Subject,
		Audience:  data.Audience,
	}, nil
}
