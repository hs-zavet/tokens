package tokens

import (
	"context"
	"net/http"
	"strings"

	"github.com/recovery-flow/comtools/httpkit"
	"github.com/recovery-flow/comtools/httpkit/problems"
	"github.com/recovery-flow/tokens/identity"
)

func AuthMdl(ctx context.Context, sk string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpkit.RenderErr(w, problems.Unauthorized("Missing Authorization header"))
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				httpkit.RenderErr(w, problems.Unauthorized("Invalid Authorization header"))
				return
			}

			tokenString := parts[1]

			tokenData, err := VerifyJWT(ctx, tokenString, sk)
			if err != nil {
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}
			if tokenData == nil {
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}

			ctx = context.WithValue(ctx, UserIDKey, tokenData.ID)
			ctx = context.WithValue(ctx, IdentityKey, tokenData.Identity)
			ctx = context.WithValue(ctx, SessionIDKey, tokenData.SessionID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func IdentityMdl(ctx context.Context, sk string, roles ...identity.IdnType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpkit.RenderErr(w, problems.Unauthorized("Missing Authorization header"))
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				httpkit.RenderErr(w, problems.Unauthorized("Invalid Authorization header"))
				return
			}

			tokenString := parts[1]

			tokenData, err := VerifyJWT(ctx, tokenString, sk)
			if err != nil {
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}

			roleAllowed := false
			for _, role := range roles {
				if tokenData.Identity == role || tokenData.Identity == identity.Service {
					roleAllowed = true
					break
				}
			}
			if !roleAllowed {
				httpkit.RenderErr(w, problems.Unauthorized("Role not allowed"))
				return
			}

			ctx = context.WithValue(ctx, UserIDKey, tokenData.ID)
			ctx = context.WithValue(ctx, IdentityKey, tokenData.Identity)
			ctx = context.WithValue(ctx, SessionIDKey, tokenData.SessionID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
