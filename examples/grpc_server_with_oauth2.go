package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/AmmannChristian/go-authx/grpcserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// Example gRPC server with OAuth2/OIDC authentication using go-authx.
//
// This example demonstrates:
// - Setting up a gRPC server with OAuth2 token validation
// - Protecting endpoints with authentication
// - Allowing public endpoints (health check) without authentication
// - Accessing token claims in handlers
// - Error handling for authentication failures
//
// To run this example:
// 1. Configure your OAuth2/OIDC provider settings below
// 2. Run: go run examples/grpc_server_with_oauth2.go
// 3. Test with a gRPC client that sends Bearer tokens

const (
	// OAuth2/OIDC Configuration
	// Replace these with your actual OAuth2 provider settings
	issuerURL = "https://auth.example.com" // Your OIDC issuer URL
	audience  = "my-api"                   // Your API audience

	// Server Configuration
	serverAddress = "127.0.0.1:9090"
)

// ExampleService is a sample gRPC service
type ExampleService struct {
	UnimplementedExampleServiceServer
}

// UnimplementedExampleServiceServer is a placeholder for the example
type UnimplementedExampleServiceServer struct{}

// GetUserProfile is a protected endpoint that requires authentication
func (s *ExampleService) GetUserProfile(ctx context.Context, req *GetUserProfileRequest) (*GetUserProfileResponse, error) {
	// Extract token claims from context (set by the interceptor)
	claims, ok := grpcserver.TokenClaimsFromContext(ctx)
	if !ok {
		// This should never happen if the interceptor is configured correctly
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	// Log authentication details
	log.Printf("Authenticated request from user: %s (email: %s, scopes: %v)",
		claims.Subject,
		claims.Email,
		claims.Scopes,
	)

	// Check if user has required scope
	if !hasScope(claims.Scopes, "profile:read") {
		return nil, status.Error(codes.PermissionDenied, "missing required scope: profile:read")
	}

	// Return user profile (using subject from token)
	return &GetUserProfileResponse{
		UserId:    claims.Subject,
		Email:     claims.Email,
		Scopes:    claims.Scopes,
		Issuer:    claims.Issuer,
		ExpiresAt: claims.Expiry.Unix(),
	}, nil
}

// CreateResource is another protected endpoint
func (s *ExampleService) CreateResource(ctx context.Context, req *CreateResourceRequest) (*CreateResourceResponse, error) {
	// Use MustTokenClaimsFromContext for cleaner code (will panic if claims are missing)
	claims := grpcserver.MustTokenClaimsFromContext(ctx)

	log.Printf("User %s creating resource: %s", claims.Subject, req.Name)

	// Check write scope
	if !hasScope(claims.Scopes, "resource:write") {
		return nil, status.Error(codes.PermissionDenied, "missing required scope: resource:write")
	}

	// Simulate resource creation
	return &CreateResourceResponse{
		ResourceId: "resource-123",
		CreatedBy:  claims.Subject,
	}, nil
}

// Helper function to check if a scope exists
func hasScope(scopes []string, required string) bool {
	for _, s := range scopes {
		if s == required {
			return true
		}
	}
	return false
}

func main() {
	log.Println("Starting gRPC server with OAuth2 authentication...")

	// Build token validator using the fluent builder
	validator, err := grpcserver.NewValidatorBuilder(issuerURL, audience).
		WithLogger(log.Default()).    // Enable logging for debugging
		WithCacheTTL(30 * 60 * 1000). // Cache JWKS for 30 minutes
		Build()
	if err != nil {
		log.Fatalf("Failed to create token validator: %v", err)
	}

	// Create gRPC server with authentication interceptors
	server := grpc.NewServer(
		// Unary interceptor for regular RPC calls
		grpc.UnaryInterceptor(
			grpcserver.UnaryServerInterceptor(
				validator,
				// Exempt health check from authentication
				grpcserver.WithExemptMethods(
					"/grpc.health.v1.Health/Check",
					"/grpc.health.v1.Health/Watch",
				),
				grpcserver.WithInterceptorLogger(log.Default()),
			),
		),
		// Stream interceptor for streaming RPC calls
		grpc.StreamInterceptor(
			grpcserver.StreamServerInterceptor(
				validator,
				grpcserver.WithExemptMethods(
					"/grpc.health.v1.Health/Watch",
				),
				grpcserver.WithInterceptorLogger(log.Default()),
			),
		),
	)

	// Register health check service (public endpoint)
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	log.Println("Health check endpoint registered (public, no auth required)")

	// Register example service (protected endpoints)
	exampleService := &ExampleService{}
	RegisterExampleServiceServer(server, exampleService)
	log.Println("Example service registered (requires authentication)")

	// Enable reflection for development (allows using grpcurl, grpc-cli, etc.)
	reflection.Register(server)
	log.Println("gRPC reflection enabled")

	// Start listening
	listener, err := net.Listen("tcp", serverAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", serverAddress, err)
	}

	log.Printf("Server listening on %s", serverAddress)
	log.Println("\nEndpoints:")
	log.Println("  - Public:    /grpc.health.v1.Health/Check")
	log.Println("  - Protected: /ExampleService/GetUserProfile")
	log.Println("  - Protected: /ExampleService/CreateResource")
	log.Println("\nAuthentication:")
	log.Printf("  - Issuer:   %s", issuerURL)
	log.Printf("  - Audience: %s", audience)
	log.Println("\nTo test with grpcurl:")
	log.Println("  # Health check (no auth)")
	log.Println("  grpcurl -plaintext localhost:9090 grpc.health.v1.Health/Check")
	log.Println("\n  # Protected endpoint (with auth)")
	log.Println("  grpcurl -plaintext \\")
	log.Println("    -H 'authorization: Bearer YOUR_TOKEN' \\")
	log.Println("    localhost:9090 ExampleService/GetUserProfile")

	// Start serving
	if err := server.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

// Protocol Buffer message definitions (normally generated from .proto files)

type GetUserProfileRequest struct{}

type GetUserProfileResponse struct {
	UserId    string
	Email     string
	Scopes    []string
	Issuer    string
	ExpiresAt int64
}

type CreateResourceRequest struct {
	Name string
}

type CreateResourceResponse struct {
	ResourceId string
	CreatedBy  string
}

// Service registration (normally generated from .proto files)
func RegisterExampleServiceServer(s *grpc.Server, srv *ExampleService) {
	// In a real application, this would be generated by protoc
	// For this example, we're just showing the structure
	fmt.Println("Note: This example uses placeholder service registration.")
	fmt.Println("In production, use proper .proto files and generated code.")
}
