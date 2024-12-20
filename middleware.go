package cifrajwt

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
	TokenVersionKey contextKey = "tokenVersion"
	RoleKey         contextKey = "role"
)

// JWTMiddleware validates the JWT token and injects user data into the request context.
func JWTMiddleware(secretKey string, log *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpkit.RenderErr(w, problems.Unauthorized("Missing Authorization header"))
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				log.Warn("Invalid Authorization header format")
				httpkit.RenderErr(w, problems.Unauthorized("Invalid Authorization header"))
				return
			}

			tokenString := parts[1]

			log.Debugf("Token received: %s", tokenString)

			userID, tokenVersion, role, err := VerifyJWTAndExtractClaims(r.Context(), tokenString, secretKey, log)
			if err != nil {
				log.Warnf("Token validation failed: %v", err)
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}

			log.Infof("Authenticated user: %s, Token Version: %d, Role: %s", userID, tokenVersion, role)

			// Add user ID, token version, and role to the context
			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			ctx = context.WithValue(ctx, TokenVersionKey, tokenVersion)
			ctx = context.WithValue(ctx, RoleKey, role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

//sample to use middleware
//userID, ok := r.Context().Value(middleware.UserIDKey).(uuid.UUID)
//if !ok {
//log.Warn("UserID not found in context")
//httpresp.RenderErr(w, problems.Unauthorized("User not authenticated"))
//return
//}
//logrus.Infof("userID: %v", userID)
