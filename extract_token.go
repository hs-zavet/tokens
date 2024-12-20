package cifrajwt

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// ExtractToken extracts the JWT token from the Authorization header of an HTTP request.
func ExtractToken(ctx context.Context) (string, error) {
	// Извлекаем HTTP-запрос из контекста
	req, ok := ctx.Value("userID").(*http.Request)
	if !ok || req == nil {
		return "", errors.New("failed to retrieve HTTP request from context")
	}

	// Извлекаем заголовок Authorization
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	// Проверяем формат: "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("invalid authorization header format")
	}

	return parts[1], nil
}
