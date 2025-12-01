// Package grpcserver provides server-side OAuth2/OIDC authentication for gRPC services.
//
// This package enables gRPC servers to validate incoming JWT Bearer tokens from OAuth2/OIDC providers,
// extract user claims, and make them available to service handlers. It follows the same design patterns
// as the rest of the go-authx library: fluent builders, secure defaults, and provider-agnostic implementation.
//
// # Features
//
//   - JWT token validation with JWKS (JSON Web Key Set)
//   - Automatic JWKS caching and refresh
//   - gRPC server interceptors for unary and streaming calls
//   - Context-based claims extraction in handlers
//   - Method exemption (e.g., for health checks)
//   - Configurable logging
//   - Thread-safe
//   - Provider-agnostic (works with any OIDC-compliant provider)
//
// # Quick Start
//
// Create a token validator and configure gRPC server interceptors:
//
//	validator, err := grpcserver.NewValidatorBuilder(
//	    "https://auth.example.com",  // OIDC issuer URL
//	    "my-api",                     // Expected audience
//	).Build()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	server := grpc.NewServer(
//	    grpc.UnaryInterceptor(grpcserver.UnaryServerInterceptor(validator)),
//	    grpc.StreamInterceptor(grpcserver.StreamServerInterceptor(validator)),
//	)
//
// # Accessing Claims in Handlers
//
// Token claims are automatically extracted and stored in the request context:
//
//	func (s *server) GetUserProfile(ctx context.Context, req *pb.Request) (*pb.Response, error) {
//	    claims, ok := grpcserver.TokenClaimsFromContext(ctx)
//	    if !ok {
//	        return nil, status.Error(codes.Unauthenticated, "not authenticated")
//	    }
//
//	    userID := claims.Subject
//	    scopes := claims.Scopes
//	    // ... use claims for authorization ...
//	}
//
// # Advanced Configuration
//
// Customize JWKS URL, cache TTL, and exempt specific methods:
//
//	validator, err := grpcserver.NewValidatorBuilder(issuerURL, audience).
//	    WithJWKSURL("https://custom-jwks-url.example.com/keys").
//	    WithCacheTTL(30 * time.Minute).
//	    WithLogger(log.Default()).
//	    Build()
//
//	interceptor := grpcserver.UnaryServerInterceptor(
//	    validator,
//	    grpcserver.WithExemptMethods(
//	        "/grpc.health.v1.Health/Check",
//	        "/grpc.health.v1.Health/Watch",
//	    ),
//	    grpcserver.WithInterceptorLogger(log.Default()),
//	)
//
// # Security Considerations
//
//   - Tokens are validated against JWKS from the OIDC provider
//   - JWT signatures are verified using RS256, RS384, RS512, ES256, ES384, or ES512
//   - Token expiry, issuer, and audience are strictly validated
//   - JWKS keys are cached securely with automatic refresh
//   - TLS 1.2+ is enforced for JWKS fetching
//
// # Provider Compatibility
//
// This package works with any OIDC-compliant provider, including:
//   - Zitadel
//   - Auth0
//   - Keycloak
//   - Okta
//   - Google Identity Platform
//   - Azure AD
//   - AWS Cognito
//
// # Thread Safety
//
// All types in this package are thread-safe and can be used concurrently from multiple goroutines.
// The JWKS cache is protected by internal locking and can safely handle concurrent token validations.
//
// # Error Handling
//
// Authentication failures return gRPC errors with codes.Unauthenticated by default.
// You can customize the error code using WithUnauthorizedCode:
//
//	interceptor := grpcserver.UnaryServerInterceptor(
//	    validator,
//	    grpcserver.WithUnauthorizedCode(codes.PermissionDenied),
//	)
package grpcserver
