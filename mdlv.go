package tokens

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/hs-zavet/comtools/httpkit"
	"github.com/hs-zavet/comtools/httpkit/problems"
	"github.com/hs-zavet/tokens/users"
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

			serviceData, err := verifyServerJWT(ctx, tokenString, sk)
			if err == nil {
				ctx = context.WithValue(ctx, ServerKey, serviceData.Subject)
				ctx = context.WithValue(ctx, AudienceKey, serviceData.Audience)

				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			userData, err := verifyUserJWT(r.Context(), tokenString, sk)
			if err != nil {
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}

			ctx = context.WithValue(ctx, SubjectIDKey, userData.Subject)
			ctx = context.WithValue(ctx, SessionIDKey, userData.Session)
			ctx = context.WithValue(ctx, SubscriptionKey, userData.Subscription)
			ctx = context.WithValue(ctx, RoleKey, userData.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AccessGrant(sk string, roles ...users.Role) func(http.Handler) http.Handler {
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

			serviceData, err := verifyServerJWT(ctx, tokenString, sk)
			if err == nil {
				ctx = context.WithValue(ctx, ServerKey, serviceData.Subject)
				ctx = context.WithValue(ctx, AudienceKey, serviceData.Audience)

				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			userData, err := verifyUserJWT(ctx, tokenString, sk)
			if err != nil {
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}

			roleAllowed := false
			for _, role := range roles {
				if userData.Role == role {
					roleAllowed = true
					break
				}
			}
			if !roleAllowed {
				httpkit.RenderErr(w, problems.Unauthorized("Role not allowed"))
				return
			}

			ctx = context.WithValue(ctx, SubjectIDKey, userData.Subject)
			ctx = context.WithValue(ctx, SessionIDKey, userData.Session)
			ctx = context.WithValue(ctx, SubscriptionKey, userData.Subscription)
			ctx = context.WithValue(ctx, RoleKey, userData.Role)

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

			serviceData, err := verifyServerJWT(ctx, tokenString, sk)
			if err == nil {
				ctx = context.WithValue(ctx, ServerKey, serviceData.Subject)
				ctx = context.WithValue(ctx, AudienceKey, serviceData.Audience)

				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			tokenData, err := verifyUserJWT(ctx, tokenString, sk)
			if err != nil {
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}

			if tokenData.Subscription == uuid.Nil {
				httpkit.RenderErr(w, problems.Unauthorized("Not allowed for this subscription"))
				return
			}

			ctx = context.WithValue(ctx, SubjectIDKey, tokenData.Subject)
			ctx = context.WithValue(ctx, SessionIDKey, tokenData.Session)
			ctx = context.WithValue(ctx, SubscriptionKey, tokenData.Subscription)
			ctx = context.WithValue(ctx, RoleKey, tokenData.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
