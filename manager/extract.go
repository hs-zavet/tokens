package manager

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

func (t *tokenManager) ExtractJWT(ctx context.Context) (string, error) {
	req, ok := ctx.Value("userID").(*http.Request)
	if !ok || req == nil {
		return "", fmt.Errorf("failed to retrieve HTTP request from context")
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}
