//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AmmannChristian/go-authx/httpserver"
)

func main() {
	// Configuration from environment variables or use defaults
	issuerURL := getEnv("ISSUER_URL", "https://your-auth-server.com")
	audience := getEnv("AUDIENCE", "my-api")
	port := getEnv("PORT", "8080")

	// Create token validator using the fluent builder
	validator, err := httpserver.NewValidatorBuilder(issuerURL, audience).
		WithCacheTTL(30 * time.Minute). // Cache JWKS for 30 minutes
		WithLogger(log.Default()).      // Enable logging
		Build()
	if err != nil {
		log.Fatalf("Failed to create validator: %v", err)
	}
	defer func() {
		if v, ok := validator.(*httpserver.JWTTokenValidator); ok {
			v.Close()
		}
	}()

	// Create HTTP server with routes
	mux := http.NewServeMux()

	// Public endpoints (no authentication required)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/public/info", publicInfoHandler)

	// Protected endpoints (authentication required)
	mux.HandleFunc("/api/users", getUsersHandler)
	mux.HandleFunc("/api/profile", getProfileHandler)
	mux.HandleFunc("/api/admin", adminOnlyHandler)

	// Wrap with authentication middleware
	authMiddleware := httpserver.Middleware(
		validator,
		httpserver.WithExemptPaths("/health"),          // Health check doesn't need auth
		httpserver.WithExemptPathPrefixes("/public/"),  // All public paths are exempt
		httpserver.WithMiddlewareLogger(log.Default()), // Log authentication events
	)

	// Apply middleware
	handler := authMiddleware(mux)

	// Create HTTP server
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting HTTP server on port %s", port)
		log.Printf("Issuer: %s", issuerURL)
		log.Printf("Audience: %s", audience)
		log.Println("\nEndpoints:")
		log.Println("  Public:")
		log.Println("    GET /health - Health check (no auth)")
		log.Println("    GET /public/info - Public information (no auth)")
		log.Println("  Protected:")
		log.Println("    GET /api/users - List users (requires auth)")
		log.Println("    GET /api/profile - Get user profile (requires auth)")
		log.Println("    GET /api/admin - Admin only (requires auth + admin scope)")
		log.Println()

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}

// healthHandler handles health check requests (no authentication required)
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// publicInfoHandler provides public information (no authentication required)
func publicInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "This is public information",
		"version": "1.0.0",
	})
}

// getUsersHandler returns a list of users (authentication required)
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Extract token claims from context
	claims, ok := httpserver.TokenClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	// Log the authenticated user
	log.Printf("User %s (email: %s) requested user list", claims.Subject, claims.Email)

	// Return mock user list
	users := []map[string]string{
		{"id": "1", "name": "Alice"},
		{"id": "2", "name": "Bob"},
		{"id": "3", "name": "Charlie"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users":        users,
		"requested_by": claims.Subject,
	})
}

// getProfileHandler returns the authenticated user's profile
func getProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Use MustTokenClaimsFromContext since auth middleware guarantees claims are present
	claims := httpserver.MustTokenClaimsFromContext(r.Context())

	// Return user profile
	profile := map[string]interface{}{
		"user_id": claims.Subject,
		"email":   claims.Email,
		"scopes":  claims.Scopes,
		"issuer":  claims.Issuer,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

// adminOnlyHandler demonstrates scope-based authorization
func adminOnlyHandler(w http.ResponseWriter, r *http.Request) {
	claims := httpserver.MustTokenClaimsFromContext(r.Context())

	// Check if user has admin scope
	if !hasScope(claims.Scopes, "admin") {
		http.Error(w, "admin scope required", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Welcome, admin!",
		"user_id": claims.Subject,
	})
}

// hasScope checks if a specific scope is present in the scopes list
func hasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

/* Example Usage:

1. Start the server:
   go run examples/http_server_with_oauth2.go

2. Test public endpoints (no authentication):
   curl http://localhost:8080/health
   curl http://localhost:8080/public/info

3. Test protected endpoints (with valid OAuth2 token):
   curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" http://localhost:8080/api/users
   curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" http://localhost:8080/api/profile

4. Test admin endpoint (requires admin scope):
   curl -H "Authorization: Bearer YOUR_ADMIN_TOKEN" http://localhost:8080/api/admin

5. Test with invalid/missing token:
   curl http://localhost:8080/api/users
   # Returns 401 Unauthorized

Environment Variables:
  ISSUER_URL   - OAuth2/OIDC issuer URL (default: https://your-auth-server.com)
  AUDIENCE     - Expected token audience (default: my-api)
  PORT         - Server port (default: 8080)

Example with environment variables:
  ISSUER_URL=https://auth.example.com AUDIENCE=my-api PORT=8080 go run examples/http_server_with_oauth2.go
*/
