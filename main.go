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
	GenerateJWT(userID uuid.UUID, deviceID uuid.UUID, role string, tlt time.Duration, sk string) (string, error)
	Middleware(secretKey string) func(http.Handler) http.Handler
	VerifyJWTAndExtractClaims(tokenString string, secretKey string) (userData *UserData, err error)
}

type TokenManager struct {
	Bin *bin.UsersBin
	log *logrus.Logger
}

func NewTokenManager(redisAddr, redisPassword string, dbNumRedis int, log *logrus.Logger, tlt time.Duration) *TokenManager {
	return &TokenManager{
		Bin: bin.NewUsersBin(redisAddr, redisPassword, dbNumRedis, tlt*time.Second),
		log: log,
	}
}
