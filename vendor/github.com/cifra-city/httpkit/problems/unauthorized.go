package problems

import (
	"fmt"
	"net/http"

	"github.com/google/jsonapi"
)

// Unauthorized 401 (Unauthorized).
func Unauthorized(message ...string) *jsonapi.ErrorObject {
	defaultMessage := "Unauthorized access"
	errorMessage := getMessageOrDefault(message, defaultMessage)

	return &jsonapi.ErrorObject{
		Title:  http.StatusText(http.StatusUnauthorized),
		Status: fmt.Sprintf("%d", http.StatusUnauthorized),
		Detail: errorMessage,
	}
}
