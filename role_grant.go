package tokens

import (
	"context"
	"net/http"
	"strings"

	"github.com/cifra-city/comtools/httpkit"
	"github.com/cifra-city/comtools/httpkit/problems"
)

// RoleGrant validates the JWT token by roles and injects user data into the request context.
func (m *tokenManager) RoleGrant(secretKey string, roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				m.log.Debugf("Missing Authorization header")
				httpkit.RenderErr(w, problems.Unauthorized("Missing Authorization header"))
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				m.log.Debugf("Invalid Authorization header format")
				httpkit.RenderErr(w, problems.Unauthorized("Invalid Authorization header"))
				return
			}

			tokenString := parts[1]

			m.log.Debugf("Token received: %s", tokenString)

			userData, err := m.VerifyJWTAndExtractClaims(tokenString, secretKey)
			if err != nil {
				m.log.Debugf("Token validation failed: %v", err)
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}
			if userData == nil || userData.Role == "" {
				m.log.Debugf("Token validation failed: invalid user data")
				httpkit.RenderErr(w, problems.Unauthorized("Token validation failed"))
				return
			}

			// Check if user role matches any of the allowed roles
			roleAllowed := false
			for _, role := range roles {
				if userData.Role == role {
					roleAllowed = true
					break
				}
			}
			if !roleAllowed {
				m.log.Debugf("Token validation failed: role not allowed")
				httpkit.RenderErr(w, problems.Unauthorized("Role not allowed"))
				return
			}

			m.log.Debugf("Authenticated user: %s, Role: %s", userData.ID, userData.Role)

			ctx := context.WithValue(r.Context(), UserIDKey, userData.ID)
			ctx = context.WithValue(ctx, RoleKey, userData.Role)
			ctx = context.WithValue(ctx, DeviceIDKey, userData.DevID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
