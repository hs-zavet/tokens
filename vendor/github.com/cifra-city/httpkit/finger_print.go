package httpkit

import (
	"crypto/sha256"
	"fmt"
	"net/http"
)

func GenerateFingerprint(r *http.Request) string {
	data := r.RemoteAddr + r.Header.Get("User-Agent") + r.Header.Get("Accept-Language")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}
