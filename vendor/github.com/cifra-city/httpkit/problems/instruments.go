package problems

import (
	"fmt"
	"net/http"

	"github.com/google/jsonapi"
)

// getMessageOrDefault
func getMessageOrDefault(message []string, defaultMessage string) string {
	if len(message) > 0 && message[0] != "" {
		return message[0]
	}
	return defaultMessage
}

func toJsonapiErrors(m map[string]error) []*jsonapi.ErrorObject {
	errs := make([]*jsonapi.ErrorObject, 0, len(m))
	for key, value := range m {
		errs = append(errs, &jsonapi.ErrorObject{
			Title:  http.StatusText(http.StatusBadRequest),
			Status: fmt.Sprintf("%d", http.StatusBadRequest),
			Meta: &map[string]interface{}{
				"field": key,
				"error": value.Error(),
			},
		})
	}
	return errs
}
