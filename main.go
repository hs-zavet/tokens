package tokens

import (
	"time"

	"github.com/cifra-city/tokens/bin"
	"github.com/sirupsen/logrus"
)

type TokenManager struct {
	Bin *bin.UsersBin
	log *logrus.Logger
}

func NewTokenManager(redisAddr, redisPassword string, dbNumRedis int, log *logrus.Logger, tlt time.Duration) TokenManager {
	return TokenManager{
		Bin: bin.NewUsersBin(redisAddr, redisPassword, dbNumRedis, tlt*time.Second),
		log: log,
	}
}
