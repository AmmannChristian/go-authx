// Example: Simple HTTP client with OAuth2 authentication
//
//go:build ignore

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/AmmannChristian/go-authx/httpclient"
	"github.com/AmmannChristian/go-authx/oauth2client"
)

func main() {
	// Configuration from environment
	tokenURL := os.Getenv("OAUTH2_TOKEN_URL")
	clientID := os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")
	scopes := os.Getenv("OAUTH2_SCOPES") // e.g., "openid profile email"
	apiURL := os.Getenv("API_URL")       // e.g., "https://api.example.com/users"

	if tokenURL == "" || clientID == "" || clientSecret == "" || apiURL == "" {
		log.Fatal("Missing required environment variables")
	}

	// Create token manager
	ctx := context.Background()
	tm := oauth2client.NewTokenManager(ctx, tokenURL, clientID, clientSecret, scopes)

	// Create HTTP client with OAuth2 authentication
	client := httpclient.NewHTTPClient(tm)

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
	fmt.Printf("Body: %s\n", body)
}
