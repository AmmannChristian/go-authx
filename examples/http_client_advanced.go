// Example: Advanced HTTP client with OAuth2, TLS/mTLS, and custom configuration
//
//go:build ignore

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/AmmannChristian/go-authx/httpclient"
)

func main() {
	// Configuration
	tokenURL := os.Getenv("OAUTH2_TOKEN_URL")
	clientID := os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")
	scopes := os.Getenv("OAUTH2_SCOPES")
	apiURL := os.Getenv("API_URL")

	// TLS configuration (optional)
	tlsCAFile := os.Getenv("TLS_CA_FILE")     // CA certificate for server verification
	tlsCertFile := os.Getenv("TLS_CERT_FILE") // Client certificate for mTLS
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")   // Client private key for mTLS

	if tokenURL == "" || clientID == "" || clientSecret == "" || apiURL == "" {
		log.Fatal("Missing required environment variables")
	}

	ctx := context.Background()

	// Build HTTP client with advanced configuration
	client, err := httpclient.NewBuilder().
		WithOAuth2(ctx, tokenURL, clientID, clientSecret, scopes).
		WithTLS(tlsCAFile, tlsCertFile, tlsKeyFile).
		WithTimeout(60 * time.Second).
		Build()
	if err != nil {
		log.Fatalf("Failed to build HTTP client: %v", err)
	}

	// Make authenticated request
	resp, err := client.Get(apiURL)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Headers: %v\n", resp.Header)
	fmt.Printf("Body: %s\n", body)
}
