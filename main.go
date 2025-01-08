package tokens

import (
	"context"
	"net/http"
	"time"

	"github.com/cifra-city/tokens/bin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type TokenManager interface {
	GenerateJWT(userID uuid.UUID, deviceID uuid.UUID, role string, tlt time.Duration, sk string) (string, error)
	ExtractJWT(ctx context.Context) (string, error)
	VerifyJWTAndExtractClaims(tokenString string, secretKey string) (userData *UserData, err error)

	GenerateServiceJWT(serviceName string, tlt time.Duration, sk string) (string, error)
	VerifyServiceJWT(tokenString, secretKey string) (*ServiceClaims, error)

	AuthMdl(secretKey string) func(http.Handler) http.Handler
	RoleGrant(secretKey string, roles ...string) func(http.Handler) http.Handler
}

type tokenManager struct {
	Bin *bin.UsersBin
	log *logrus.Logger
}

func NewTokenManager(redisAddr, redisPassword string, dbNumRedis int, log *logrus.Logger, tlt time.Duration) TokenManager {
	return &tokenManager{
		Bin: bin.NewUsersBin(redisAddr, redisPassword, dbNumRedis, tlt*time.Second),
		log: log,
	}
}
