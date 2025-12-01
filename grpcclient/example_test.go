package grpcclient_test

import (
	"context"
	"fmt"
	"log"

	"github.com/AmmannChristian/go-authx/grpcclient"
)

// Example demonstrates basic gRPC client builder usage.
func Example() {
	ctx := context.Background()

	conn, err := grpcclient.NewBuilder().
		WithAddress("server.example.com:9090").
		WithOAuth2(
			"https://auth.example.com/oauth/v2/token",
			"client-id",
			"client-secret",
			"openid profile",
		).
		Build(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("gRPC connection established")
	// Output: gRPC connection established
}

// ExampleNewBuilder demonstrates creating a new builder.
func ExampleNewBuilder() {
	builder := grpcclient.NewBuilder()

	fmt.Println("Builder created")
	_ = builder
	// Output: Builder created
}

// ExampleBuilder_WithAddress demonstrates setting the server address.
func ExampleBuilder_WithAddress() {
	ctx := context.Background()

	conn, err := grpcclient.NewBuilder().
		WithAddress("api.example.com:9090").
		Build(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("Connected to api.example.com:9090")
	// Output: Connected to api.example.com:9090
}

// ExampleBuilder_WithOAuth2 demonstrates OAuth2 configuration.
func ExampleBuilder_WithOAuth2() {
	ctx := context.Background()

	conn, err := grpcclient.NewBuilder().
		WithAddress("secure.example.com:9090").
		WithOAuth2(
			"https://auth.example.com/oauth/v2/token",
			"my-client-id",
			"my-client-secret",
			"openid profile email",
		).
		Build(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("OAuth2 authentication enabled")
	// Output: OAuth2 authentication enabled
}

// ExampleBuilder_WithTLS demonstrates TLS configuration.
func ExampleBuilder_WithTLS() {
	ctx := context.Background()

	conn, err := grpcclient.NewBuilder().
		WithAddress("secure.example.com:9090").
		WithTLS(
			"/path/to/ca.crt",     // CA certificate
			"/path/to/client.crt", // Client certificate (optional)
			"/path/to/client.key", // Client key (optional)
			"secure.example.com",  // Server name override (optional)
		).
		Build(ctx)
	if err != nil {
		// In this example, files don't exist, so we expect an error
		fmt.Println("TLS configuration attempted")
		return
	}
	defer conn.Close()

	fmt.Println("TLS enabled")
	// Output: TLS configuration attempted
}

// ExampleBuilder_Build demonstrates the full builder pattern.
func ExampleBuilder_Build() {
	ctx := context.Background()

	// Build a fully configured gRPC client
	conn, err := grpcclient.NewBuilder().
		WithAddress("grpc.example.com:9090").
		WithOAuth2(
			"https://auth.example.com/oauth/v2/token",
			"client-id",
			"client-secret",
			"openid",
		).
		Build(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("gRPC client built successfully")
	// Output: gRPC client built successfully
}
