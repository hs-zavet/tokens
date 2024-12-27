package problems

import (
	"fmt"
	"net/http"

	"github.com/google/jsonapi"
)

// InternalError 500 (Internal Server Error).
func InternalError(message ...string) *jsonapi.ErrorObject {
	defaultMessage := "An unexpected error occurred"
	errorMessage := getMessageOrDefault(message, defaultMessage)

	return &jsonapi.ErrorObject{
		Title:  http.StatusText(http.StatusInternalServerError),
		Status: fmt.Sprintf("%d", http.StatusInternalServerError),
		Detail: errorMessage,
	}
}
