package tokens

import (
	"context"
	"net/http"
	"time"

	"github.com/cifra-city/tokens/bin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type tokenManager interface {
	ExtractJWT(ctx context.Context) (string, error)
	GenerateJWT(userID uuid.UUID, deviceID uuid.UUID, role string, tokenVersion int, tlt time.Duration, sk string) (string, error)
	JWTMiddleware(secretKey string, log *logrus.Logger) func(http.Handler) http.Handler
	VerifyJWTAndExtractClaims(
		ctx context.Context,
		tokenString,
		secretKey string,
		log *logrus.Logger) (
		userId uuid.UUID,
		deviceId uuid.UUID,
		tokenVersion int,
		role string,
		err error,
	)
}

type TokenManager struct {
	Bin *bin.UsersBin
}

func NewTokenManager(redisAddr, redisPassword string, db int, ttl time.Duration) *TokenManager {
	return &TokenManager{
		Bin: bin.NewUsersBin(redisAddr, redisPassword, db, ttl),
	}
}
