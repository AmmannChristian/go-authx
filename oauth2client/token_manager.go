package oauth2client

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Logger is an interface for optional logging in TokenManager.
// Implementations can log token refresh events if desired.
type Logger interface {
	Printf(format string, args ...any)
}

// TokenManager manages OAuth2 tokens with automatic refresh.
// It uses the client credentials flow and is safe for concurrent access.
type TokenManager struct {
	config       *clientcredentials.Config
	token        *oauth2.Token
	mu           sync.RWMutex
	ctx          context.Context // fallback context for backward compatibility
	expiryLeeway time.Duration
	logger       Logger // optional logger
}

// Option is a functional option for configuring TokenManager.
type Option func(*TokenManager)

// WithLogger sets a custom logger for token refresh events.
// If not set, no logging will occur.
func WithLogger(logger Logger) Option {
	return func(tm *TokenManager) {
		tm.logger = logger
	}
}

// WithLoggingEnabled enables logging using the default Go log package.
// This is a convenience option that sets the logger to log.Default().
func WithLoggingEnabled() Option {
	return func(tm *TokenManager) {
		tm.logger = log.Default()
	}
}

// NewTokenManager creates a new OAuth2 token manager using client credentials flow.
//
// Parameters:
//   - ctx: Context for token requests (used as fallback for backward compatibility)
//   - tokenURL: OAuth2 token endpoint (e.g., "https://auth.example.com/oauth/v2/token")
//   - clientID: OAuth2 client identifier
//   - clientSecret: OAuth2 client secret
//   - scopes: Space-separated list of OAuth2 scopes (e.g., "openid profile email")
//   - opts: Optional configuration options (WithLogger, WithLoggingEnabled)
func NewTokenManager(ctx context.Context, tokenURL, clientID, clientSecret, scopes string, opts ...Option) *TokenManager {
	// Split scopes by whitespace to avoid sending a single concatenated scope.
	scopesList := strings.Fields(scopes)

	// Keep token requests independent from caller cancellations while preserving values.
	// This context is used as a fallback for backward compatibility with GetToken().
	if ctx == nil {
		ctx = context.Background()
	} else {
		ctx = context.WithoutCancel(ctx)
	}

	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		Scopes:       scopesList,
	}

	tm := &TokenManager{
		config:       config,
		ctx:          ctx,
		expiryLeeway: time.Minute, // refresh a bit before expiry to avoid near-expiry races
	}

	// Apply options
	for _, opt := range opts {
		opt(tm)
	}

	return tm
}

// GetTokenWithContext returns a valid access token, fetching or refreshing if necessary.
// This method respects the provided context's cancellation and deadline.
// This method is thread-safe and uses double-checked locking to minimize lock contention.
//
// Parameters:
//   - ctx: Context for the token request (used for cancellation and deadlines)
//
// Returns:
//   - string: Valid access token
//   - error: Error if token fetch/refresh fails or context is cancelled
func (tm *TokenManager) GetTokenWithContext(ctx context.Context) (string, error) {
	// Use background context if nil
	if ctx == nil {
		ctx = context.Background()
	}

	// Fast path: check if we have a valid token without write lock
	tm.mu.RLock()
	if tm.tokenValid() {
		token := tm.token.AccessToken
		tm.mu.RUnlock()
		return token, nil
	}
	tm.mu.RUnlock()

	// Token is invalid or missing, fetch a new one
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine might have refreshed)
	if tm.tokenValid() {
		return tm.token.AccessToken, nil
	}

	// Fetch new token using the provided context
	token, err := tm.config.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("oauth2: failed to fetch token: %w", err)
	}

	tm.token = token

	// Log only if logger is configured
	if tm.logger != nil {
		tm.logger.Printf("oauth2: obtained new access token (expires: %s)", token.Expiry.Format(time.RFC3339))
	}

	return token.AccessToken, nil
}

// GetToken returns a valid access token, fetching or refreshing if necessary.
// This method is thread-safe and uses double-checked locking to minimize lock contention.
//
// Deprecated: Use GetTokenWithContext instead to properly handle context cancellation and deadlines.
// This method uses a background context and cannot be cancelled by the caller.
//
// Returns:
//   - string: Valid access token
//   - error: Error if token fetch/refresh fails
func (tm *TokenManager) GetToken() (string, error) {
	// Delegate to GetTokenWithContext with the fallback context
	return tm.GetTokenWithContext(tm.ctx)
}

// tokenValid reports whether the cached token is still usable with a small safety window.
func (tm *TokenManager) tokenValid() bool {
	if tm.token == nil {
		return false
	}
	// If expiry is known, consider the leeway window.
	if !tm.token.Expiry.IsZero() {
		if time.Until(tm.token.Expiry) <= tm.expiryLeeway {
			return false
		}
	}
	return tm.token.Valid()
}

// UnaryClientInterceptor returns a gRPC unary client interceptor that automatically
// adds OAuth2 Bearer tokens to request metadata.
//
// The interceptor adds the token as "authorization: Bearer <token>" to the outgoing
// request context metadata. If token fetch fails, the RPC call is aborted with an error.
// The interceptor respects the RPC context's cancellation and deadline.
//
// Usage:
//
//	conn, err := grpc.NewClient(
//	    "server:9090",
//	    grpc.WithUnaryInterceptor(tokenManager.UnaryClientInterceptor()),
//	)
func (tm *TokenManager) UnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		// Use the RPC context for token fetching to respect cancellation and deadlines
		token, err := tm.GetTokenWithContext(ctx)
		if err != nil {
			return fmt.Errorf("oauth2: failed to get token: %w", err)
		}

		// Add token to request metadata
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// StreamClientInterceptor returns a gRPC stream client interceptor that automatically
// adds OAuth2 Bearer tokens to request metadata.
//
// The interceptor adds the token as "authorization: Bearer <token>" to the outgoing
// request context metadata. If token fetch fails, stream creation is aborted with an error.
// The interceptor respects the RPC context's cancellation and deadline.
//
// Usage:
//
//	conn, err := grpc.NewClient(
//	    "server:9090",
//	    grpc.WithStreamInterceptor(tokenManager.StreamClientInterceptor()),
//	)
func (tm *TokenManager) StreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		// Use the RPC context for token fetching to respect cancellation and deadlines
		token, err := tm.GetTokenWithContext(ctx)
		if err != nil {
			return nil, fmt.Errorf("oauth2: failed to get token: %w", err)
		}

		// Add token to request metadata
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

		return streamer(ctx, desc, cc, method, opts...)
	}
}
