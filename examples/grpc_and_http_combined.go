// Example: Using both gRPC and HTTP clients with shared OAuth2 TokenManager
//
//go:build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/AmmannChristian/go-authx/grpcclient"
	"github.com/AmmannChristian/go-authx/httpclient"
	"github.com/AmmannChristian/go-authx/oauth2client"
)

func main() {
	// OAuth2 configuration (shared between gRPC and HTTP)
	tokenURL := os.Getenv("OAUTH2_TOKEN_URL")
	clientID := os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")
	scopes := os.Getenv("OAUTH2_SCOPES")

	grpcAddr := os.Getenv("GRPC_SERVER_ADDR") // e.g., "grpc.example.com:9090"
	restURL := os.Getenv("REST_API_URL")      // e.g., "https://api.example.com/data"

	if tokenURL == "" || clientID == "" || clientSecret == "" {
		log.Fatal("Missing OAuth2 configuration")
	}

	ctx := context.Background()

	// Create shared token manager - tokens are reused across both clients
	tm := oauth2client.NewTokenManager(ctx, tokenURL, clientID, clientSecret, scopes)

	// Example 1: Create gRPC client
	if grpcAddr != "" {
		grpcConn, err := grpcclient.NewBuilder().
			WithAddress(grpcAddr).
			WithOAuth2(tokenURL, clientID, clientSecret, scopes).
			Build(ctx)
		if err != nil {
			log.Fatalf("Failed to create gRPC client: %v", err)
		}
		defer grpcConn.Close()

		fmt.Println("gRPC client connected successfully")
		// Use grpcConn with your generated protobuf clients
	}

	// Example 2: Create HTTP client (shares the same TokenManager)
	if restURL != "" {
		httpClient := httpclient.NewHTTPClient(tm)

		resp, err := httpClient.Get(restURL)
		if err != nil {
			log.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()

		fmt.Printf("HTTP request status: %s\n", resp.Status)
	}

	// The TokenManager automatically handles token refresh for both clients,
	// so you only fetch tokens when needed and reuse them efficiently.
}
