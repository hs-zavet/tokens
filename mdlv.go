package tokens

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/hs-zavet/comtools/httpkit"
	"github.com/hs-zavet/comtools/httpkit/problems"
	"github.com/hs-zavet/tokens/identity"
)

func AuthMdl(sk string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

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

			tokenData, err := VerifyJWT(r.Context(), tokenString, sk)
			if err != nil {
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}
			if tokenData == nil {
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}

			ctx = context.WithValue(ctx, AccountIDKey, tokenData.AccountID)
			ctx = context.WithValue(ctx, SessionIDKey, tokenData.SessionID)
			ctx = context.WithValue(ctx, SubscriptionKey, tokenData.SubTypeID)
			ctx = context.WithValue(ctx, IdentityKey, &tokenData.Identity)
			if tokenData.Identity == identity.Service {
				ctx = context.WithValue(ctx, ServerKey, tokenData.ID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func IdentityMdl(sk string, roles ...identity.IdnType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

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

			ctx = context.WithValue(ctx, AccountIDKey, tokenData.AccountID)
			ctx = context.WithValue(ctx, SessionIDKey, tokenData.SessionID)
			ctx = context.WithValue(ctx, SubscriptionKey, tokenData.SubTypeID)
			ctx = context.WithValue(ctx, IdentityKey, &tokenData.Identity)
			if tokenData.Identity == identity.Service {
				ctx = context.WithValue(ctx, ServerKey, tokenData.ID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func EachSubMdl(sk string, sub ...uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

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

			subAllowed := false
			for _, s := range sub {
				if *tokenData.SubTypeID == s || tokenData.Identity == identity.Service {
					subAllowed = true
					break
				}
			}
			if !subAllowed {
				httpkit.RenderErr(w, problems.Unauthorized("Not allowed for this subscription"))
				return
			}

			ctx = context.WithValue(ctx, AccountIDKey, tokenData.AccountID)
			ctx = context.WithValue(ctx, SessionIDKey, tokenData.SessionID)
			ctx = context.WithValue(ctx, SubscriptionKey, tokenData.SubTypeID)
			ctx = context.WithValue(ctx, IdentityKey, &tokenData.Identity)
			if tokenData.Identity == identity.Service {
				ctx = context.WithValue(ctx, ServerKey, tokenData.ID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func SubMdl(sk string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

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

			if tokenData.SubTypeID == nil && tokenData.Identity != identity.Service {
				httpkit.RenderErr(w, problems.Unauthorized("Not allowed for this subscription"))
				return
			}

			ctx = context.WithValue(ctx, AccountIDKey, tokenData.AccountID)
			ctx = context.WithValue(ctx, SessionIDKey, tokenData.SessionID)
			ctx = context.WithValue(ctx, SubscriptionKey, tokenData.SubTypeID)
			ctx = context.WithValue(ctx, IdentityKey, &tokenData.Identity)
			if tokenData.Identity == identity.Service {
				ctx = context.WithValue(ctx, ServerKey, tokenData.ID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
