package tokens

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

func (m *TokenManager) ExtractJWT(ctx context.Context) (string, error) {
	req, ok := ctx.Value("userID").(*http.Request)
	if !ok || req == nil {
		return "", errors.New("failed to retrieve HTTP request from context")
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("invalid authorization header format")
	}

	return parts[1], nil
}
