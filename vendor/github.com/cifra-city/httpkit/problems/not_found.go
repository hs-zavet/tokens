package problems

import (
	"fmt"
	"net/http"

	"github.com/google/jsonapi"
)

// NotFound 404 (Not Found).
func NotFound(message ...string) *jsonapi.ErrorObject {
	defaultMessage := "Resource not found"
	errorMessage := getMessageOrDefault(message, defaultMessage)

	return &jsonapi.ErrorObject{
		Title:  http.StatusText(http.StatusNotFound),
		Status: fmt.Sprintf("%d", http.StatusNotFound),
		Detail: errorMessage,
	}
}
