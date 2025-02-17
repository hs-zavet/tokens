package manager

import (
	"context"
	"net/http"
	"time"

	"github.com/recovery-flow/tokens/bin"
)

type TokenManager interface {
	GenerateJWT(
		iss string,
		sub string,
		ttl time.Duration,
		aud []string,
		role *string,
		deviceID *string,
	) (string, error)

	ExtractJWT(ctx context.Context) (string, error)
	VerifyJWT(ctx context.Context, tokenString string) (userData *CustomClaims, err error)

	AuthMdl(ctx context.Context) func(http.Handler) http.Handler
	RoleMdl(ctx context.Context, roles ...string) func(http.Handler) http.Handler
}

type tokenManager struct {
	Bin       *bin.UsersBin
	SecretKey string
}

func NewTokenManager(bin *bin.UsersBin, sk string) TokenManager {
	return &tokenManager{
		Bin:       bin,
		SecretKey: sk,
	}
}
