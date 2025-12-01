package grpcserver

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// InterceptorConfig holds configuration for authentication interceptors.
type InterceptorConfig struct {
	validator        TokenValidator
	exemptMethods    map[string]bool // Methods that don't require authentication
	logger           Logger          // optional logger
	tokenExtractor   TokenExtractor  // custom token extraction logic (optional)
	unauthorizedCode codes.Code      // gRPC code to return on auth failure (default: Unauthenticated)
}

// InterceptorOption is a functional option for configuring interceptors.
type InterceptorOption func(*InterceptorConfig)

// WithExemptMethods specifies gRPC methods that don't require authentication.
// Method names should be in the format "/package.Service/Method".
//
// Example:
//
//	WithExemptMethods("/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Watch")
func WithExemptMethods(methods ...string) InterceptorOption {
	return func(c *InterceptorConfig) {
		if c.exemptMethods == nil {
			c.exemptMethods = make(map[string]bool)
		}
		for _, method := range methods {
			c.exemptMethods[method] = true
		}
	}
}

// WithInterceptorLogger sets a logger for the interceptor.
func WithInterceptorLogger(logger Logger) InterceptorOption {
	return func(c *InterceptorConfig) {
		c.logger = logger
	}
}

// TokenExtractor is a function that extracts a token from gRPC metadata.
// It returns the token string and a boolean indicating whether extraction succeeded.
type TokenExtractor func(md metadata.MD) (string, bool)

// WithTokenExtractor sets a custom token extraction function.
// By default, tokens are extracted from the "authorization" header as "Bearer <token>".
func WithTokenExtractor(extractor TokenExtractor) InterceptorOption {
	return func(c *InterceptorConfig) {
		c.tokenExtractor = extractor
	}
}

// WithUnauthorizedCode sets the gRPC status code to return on authentication failures.
// Default is codes.Unauthenticated.
func WithUnauthorizedCode(code codes.Code) InterceptorOption {
	return func(c *InterceptorConfig) {
		c.unauthorizedCode = code
	}
}

// UnaryServerInterceptor returns a gRPC unary server interceptor that validates
// OAuth2/OIDC Bearer tokens on incoming requests.
//
// The interceptor:
// - Extracts the Bearer token from the "authorization" metadata header
// - Validates the token using the provided TokenValidator
// - Stores the TokenClaims in the request context (accessible via TokenClaimsFromContext)
// - Returns codes.Unauthenticated if authentication fails
// - Optionally exempts specific methods from authentication
//
// Usage:
//
//	validator, _ := grpcserver.NewValidatorBuilder(issuerURL, audience).Build()
//	server := grpc.NewServer(
//	    grpc.UnaryInterceptor(grpcserver.UnaryServerInterceptor(validator)),
//	)
func UnaryServerInterceptor(validator TokenValidator, opts ...InterceptorOption) grpc.UnaryServerInterceptor {
	config := &InterceptorConfig{
		validator:        validator,
		exemptMethods:    make(map[string]bool),
		unauthorizedCode: codes.Unauthenticated,
	}

	for _, opt := range opts {
		opt(config)
	}

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check if method is exempt from authentication
		if config.exemptMethods[info.FullMethod] {
			if config.logger != nil {
				config.logger.Printf("grpcserver: method %s is exempt from authentication", info.FullMethod)
			}
			return handler(ctx, req)
		}

		// Extract and validate token
		claims, err := extractAndValidateToken(ctx, config)
		if err != nil {
			if config.logger != nil {
				config.logger.Printf("grpcserver: authentication failed for %s: %v", info.FullMethod, err)
			}
			return nil, status.Error(config.unauthorizedCode, err.Error())
		}

		// Add claims to context
		ctx = WithTokenClaims(ctx, claims)

		if config.logger != nil {
			config.logger.Printf("grpcserver: authenticated request for %s (subject: %s)", info.FullMethod, claims.Subject)
		}

		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor that validates
// OAuth2/OIDC Bearer tokens on incoming stream requests.
//
// The interceptor:
// - Extracts the Bearer token from the "authorization" metadata header
// - Validates the token using the provided TokenValidator
// - Stores the TokenClaims in the stream context (accessible via TokenClaimsFromContext)
// - Returns codes.Unauthenticated if authentication fails
// - Optionally exempts specific methods from authentication
//
// Usage:
//
//	validator, _ := grpcserver.NewValidatorBuilder(issuerURL, audience).Build()
//	server := grpc.NewServer(
//	    grpc.StreamInterceptor(grpcserver.StreamServerInterceptor(validator)),
//	)
func StreamServerInterceptor(validator TokenValidator, opts ...InterceptorOption) grpc.StreamServerInterceptor {
	config := &InterceptorConfig{
		validator:        validator,
		exemptMethods:    make(map[string]bool),
		unauthorizedCode: codes.Unauthenticated,
	}

	for _, opt := range opts {
		opt(config)
	}

	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Check if method is exempt from authentication
		if config.exemptMethods[info.FullMethod] {
			if config.logger != nil {
				config.logger.Printf("grpcserver: stream method %s is exempt from authentication", info.FullMethod)
			}
			return handler(srv, ss)
		}

		// Extract and validate token
		claims, err := extractAndValidateToken(ss.Context(), config)
		if err != nil {
			if config.logger != nil {
				config.logger.Printf("grpcserver: authentication failed for stream %s: %v", info.FullMethod, err)
			}
			return status.Error(config.unauthorizedCode, err.Error())
		}

		if config.logger != nil {
			config.logger.Printf("grpcserver: authenticated stream for %s (subject: %s)", info.FullMethod, claims.Subject)
		}

		// Wrap the stream with a context that includes the claims
		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          WithTokenClaims(ss.Context(), claims),
		}

		return handler(srv, wrappedStream)
	}
}

// extractAndValidateToken extracts the Bearer token from metadata and validates it.
func extractAndValidateToken(ctx context.Context, config *InterceptorConfig) (*TokenClaims, error) {
	// Extract metadata from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "grpcserver: missing metadata")
	}

	// Extract token using custom extractor or default logic
	var token string
	if config.tokenExtractor != nil {
		var extracted bool
		token, extracted = config.tokenExtractor(md)
		if !extracted {
			return nil, status.Error(codes.Unauthenticated, "grpcserver: missing or invalid authorization token")
		}
	} else {
		// Default extraction: "authorization: Bearer <token>"
		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return nil, status.Error(codes.Unauthenticated, "grpcserver: missing authorization header")
		}

		authHeader := authHeaders[0]
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return nil, status.Error(codes.Unauthenticated, "grpcserver: invalid authorization header format")
		}

		token = strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "grpcserver: missing token in authorization header")
		}
	}

	// Validate token
	claims, err := config.validator.ValidateToken(ctx, token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "grpcserver: token validation failed: %v", err)
	}

	return claims, nil
}

// wrappedServerStream wraps a grpc.ServerStream to override the context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context with token claims.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
