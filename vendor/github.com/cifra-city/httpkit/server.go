package httpkit

import (
	"context"
	"errors"
	"net/http"

	"github.com/sirupsen/logrus"
)

// StartServer starts an HTTP server in a separate goroutine and returns a pointer to the server.
func StartServer(ctx context.Context, addr string, router http.Handler, log *logrus.Logger) *http.Server {
	server := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	go func() {
		log.Infof("Starting server on port %s", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	return server
}

// StopServer ends the server when the context is canceled.
func StopServer(ctx context.Context, server *http.Server, log *logrus.Logger) {
	log.Info("Shutting down server...")
	if err := server.Shutdown(ctx); err != nil {
		logrus.Errorf("Server shutdown failed: %v", err)
	}
}
