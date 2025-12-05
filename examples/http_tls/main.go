package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/AmmannChristian/go-authx/httpserver"
)

func main() {
	// Create OAuth2 validator
	validator, err := httpserver.NewValidatorBuilder(
		"https://auth.example.com",
		"my-api",
	).WithLogger(log.Default()).Build()
	if err != nil {
		log.Fatalf("Failed to create validator: %v", err)
	}

	// Create HTTP mux
	mux := http.NewServeMux()

	// Protected endpoint
	mux.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
		// Extract token claims from context
		claims, ok := httpserver.TokenClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "Hello %s (subject: %s)\n", claims.PreferredUsername, claims.Subject)
	})

	// Public endpoint (exempt from authentication)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "OK")
	})

	// Wrap with authentication middleware
	authHandler := httpserver.Middleware(
		validator,
		httpserver.WithExemptPaths("/health", "/metrics"),
		httpserver.WithMiddlewareLogger(log.Default()),
	)(mux)

	// Configure TLS with mTLS (mutual TLS)
	tlsConfig := &httpserver.TLSConfig{
		CertFile:   "/path/to/server.crt",
		KeyFile:    "/path/to/server.key",
		CAFile:     "/path/to/ca.crt", // Optional: for client certificate verification
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	// Create HTTP server
	server := &http.Server{
		Addr:    ":8443",
		Handler: authHandler,
	}

	// Configure TLS
	if err := httpserver.ConfigureServer(server, tlsConfig); err != nil {
		log.Fatalf("Failed to configure TLS: %v", err)
	}

	log.Println("HTTPS server with mTLS listening on :8443")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
