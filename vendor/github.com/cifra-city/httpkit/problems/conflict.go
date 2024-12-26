package problems

import (
	"fmt"
	"net/http"

	"github.com/google/jsonapi"
)

// Conflict 409 (Conflict).
func Conflict(message ...string) *jsonapi.ErrorObject {
	defaultMessage := "Resource conflict"

	errorMessage := defaultMessage
	if len(message) > 0 && message[0] != "" {
		errorMessage = message[0]
	}

	return &jsonapi.ErrorObject{
		Title:  http.StatusText(http.StatusConflict),
		Status: fmt.Sprintf("%d", http.StatusConflict),
		Detail: errorMessage,
	}
}
