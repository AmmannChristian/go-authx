// Package oauth2client provides an OAuth2 client-credentials token manager for gRPC and HTTP clients.
//
// It caches bearer tokens, refreshes them before expiry, and offers gRPC client interceptors to inject
// Authorization headers automatically. Token fetches honor contexts for cancellation, are thread-safe,
// and can log refresh events via optional Logger interfaces.
//
// # Features
//
//   - Client-credentials flow with automatic caching and early refresh
//   - Context-aware token fetching with cancellation and deadline support
//   - gRPC unary and stream client interceptors that inject Bearer tokens
//   - Optional logging (WithLogger, WithLoggingEnabled)
//   - Shareable token manager across multiple gRPC and HTTP clients
//
// # Quick Start
//
//	tm := oauth2client.NewTokenManager(
//	    ctx,
//	    "https://auth.example.com/oauth/v2/token",
//	    "client-id",
//	    "client-secret",
//	    "openid profile email",
//	    oauth2client.WithLoggingEnabled(),
//	)
//
//	conn, err := grpc.NewClient(
//	    "server:9090",
//	    grpc.WithUnaryInterceptor(tm.UnaryClientInterceptor()),
//	    grpc.WithStreamInterceptor(tm.StreamClientInterceptor()),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	client := http.Client{Transport: httpclient.NewOAuth2Transport(tm, nil)}
//
// # Notes
//
//   - GetTokenWithContext is preferred; GetToken is kept for backward compatibility.
//   - TokenManager is safe for concurrent use and uses double-checked locking.
package oauth2client
