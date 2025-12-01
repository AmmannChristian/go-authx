package httpclient_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/AmmannChristian/go-authx/httpclient"
	"github.com/AmmannChristian/go-authx/oauth2client"
)

// Example demonstrates basic HTTP client usage with OAuth2.
func Example() {
	ctx := context.Background()

	// Create token manager
	tm := oauth2client.NewTokenManager(
		ctx,
		"https://auth.example.com/oauth/v2/token",
		"client-id",
		"client-secret",
		"openid profile",
	)

	// Create HTTP client
	client := httpclient.NewHTTPClient(tm)

	fmt.Printf("HTTP client created with timeout: %v\n", client.Timeout)
	// Output: HTTP client created with timeout: 30s
}

// ExampleNewHTTPClient demonstrates the simple way to create an HTTP client.
func ExampleNewHTTPClient() {
	ctx := context.Background()

	tm := oauth2client.NewTokenManager(
		ctx,
		"https://auth.example.com/oauth/v2/token",
		"client-id",
		"client-secret",
		"openid",
	)

	client := httpclient.NewHTTPClient(tm)

	fmt.Printf("Client timeout: %v\n", client.Timeout)
	// Output: Client timeout: 30s
}

// ExampleNewBuilder demonstrates using the builder pattern for HTTP clients.
func ExampleNewBuilder() {
	ctx := context.Background()

	client, err := httpclient.NewBuilder().
		WithOAuth2(ctx, "https://auth.example.com/oauth/v2/token", "client-id", "secret", "openid").
		WithTimeout(60 * time.Second).
		Build()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Client configured with timeout: %v\n", client.Timeout)
	// Output: Client configured with timeout: 1m0s
}

// ExampleBuilder_WithOAuth2 demonstrates OAuth2 configuration.
func ExampleBuilder_WithOAuth2() {
	ctx := context.Background()

	client, err := httpclient.NewBuilder().
		WithOAuth2(
			ctx,
			"https://auth.example.com/oauth/v2/token",
			"my-client-id",
			"my-client-secret",
			"openid profile email",
		).
		Build()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("OAuth2 authentication configured")
	_ = client
	// Output: OAuth2 authentication configured
}

// ExampleBuilder_WithTLS demonstrates TLS configuration.
func ExampleBuilder_WithTLS() {
	ctx := context.Background()

	client, err := httpclient.NewBuilder().
		WithOAuth2(ctx, "https://auth.example.com/oauth/v2/token", "client-id", "secret", "openid").
		WithTLS(
			"/path/to/ca.crt",     // CA certificate
			"/path/to/client.crt", // Client certificate (optional)
			"/path/to/client.key", // Client key (optional)
		).
		Build()
	if err != nil {
		// In this example, files don't exist, so we expect an error
		fmt.Println("TLS configuration attempted")
		return
	}

	fmt.Println("TLS configured")
	_ = client
	// Output: TLS configuration attempted
}

// ExampleBuilder_WithTimeout demonstrates timeout configuration.
func ExampleBuilder_WithTimeout() {
	ctx := context.Background()

	client, err := httpclient.NewBuilder().
		WithOAuth2(ctx, "https://auth.example.com/oauth/v2/token", "client-id", "secret", "openid").
		WithTimeout(45 * time.Second).
		Build()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Timeout: %v\n", client.Timeout)
	// Output: Timeout: 45s
}

// ExampleBuilder_WithoutRedirects demonstrates disabling redirect following.
func ExampleBuilder_WithoutRedirects() {
	ctx := context.Background()

	client, err := httpclient.NewBuilder().
		WithOAuth2(ctx, "https://auth.example.com/oauth/v2/token", "client-id", "secret", "openid").
		WithoutRedirects().
		Build()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Redirects disabled")
	_ = client
	// Output: Redirects disabled
}

// ExampleNewOAuth2Transport demonstrates creating a custom transport.
func ExampleNewOAuth2Transport() {
	ctx := context.Background()

	tm := oauth2client.NewTokenManager(
		ctx,
		"https://auth.example.com/oauth/v2/token",
		"client-id",
		"client-secret",
		"openid",
	)

	transport := httpclient.NewOAuth2Transport(tm, nil)

	fmt.Printf("Transport type: OAuth2Transport\n")
	_ = transport
	// Output: Transport type: OAuth2Transport
}
