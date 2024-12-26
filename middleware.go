package tokens

import (
	"context"
	"net/http"
	"strings"

	"github.com/cifra-city/httpkit"
	"github.com/cifra-city/httpkit/problems"
	"github.com/sirupsen/logrus"
)

type contextKey string

const (
	UserIDKey       contextKey = "userID"
	TokenVersionKey contextKey = "TokenVersion"
	RoleKey         contextKey = "Role"
	DeviceIDKey     contextKey = "deviceID"
)

// Middleware validates the JWT token and injects user data into the request context.
func (m *TokenManager) Middleware(secretKey string, log *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpkit.RenderErr(w, problems.Unauthorized("Missing Authorization header"))
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				log.Debugf("Invalid Authorization header format")
				httpkit.RenderErr(w, problems.Unauthorized("Invalid Authorization header"))
				return
			}

			tokenString := parts[1]

			log.Debugf("Token received: %s", tokenString)

			userData, err := m.VerifyJWTAndExtractClaims(tokenString, secretKey)
			if err != nil {
				log.Debugf("Token validation failed: %v", err)
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}
			if userData == nil {
				log.Debugf("Token validation failed")
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
			}

			log.Debugf("Authenticated user: %s, Token Version: %d, Role: %s", userData.ID, userData.TokenVersion, userData.Role)

			// Add user ID, token version, and Role to the context
			ctx := context.WithValue(r.Context(), UserIDKey, userData.ID)
			ctx = context.WithValue(ctx, TokenVersionKey, userData.TokenVersion)
			ctx = context.WithValue(ctx, RoleKey, userData.Role)
			ctx = context.WithValue(ctx, DeviceIDKey, userData.ID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
