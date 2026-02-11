# Go OAuth2 Client Library

[![CI](https://github.com/AmmannChristian/go-authx/actions/workflows/ci.yml/badge.svg)](https://github.com/AmmannChristian/go-authx/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/AmmannChristian/go-authx)](https://goreportcard.com/report/github.com/AmmannChristian/go-authx)
[![GoDoc](https://pkg.go.dev/badge/github.com/AmmannChristian/go-authx)](https://pkg.go.dev/github.com/AmmannChristian/go-authx)
[![codecov](https://codecov.io/gh/AmmannChristian/go-authx/branch/main/graph/badge.svg)](https://codecov.io/gh/AmmannChristian/go-authx)
[![License](https://img.shields.io/github/license/AmmannChristian/go-authx)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/AmmannChristian/go-authx)](go.mod)

Reusable Go library for OAuth2/OIDC authentication with support for both **client-side** (gRPC/HTTP clients) and **server-side** (gRPC servers) authentication.

## Features

### Client-Side Authentication
- **OAuth2 Token Management**: Client-credentials flow with early refresh and scope parsing
- **Context-Aware Token Fetching**: Respects cancellation and deadlines via `GetTokenWithContext()`
- **Optional Logging**: Configurable token refresh logging with custom logger support
- **gRPC Client Support**: Automatic Bearer injection via interceptors for unary and streaming calls
- **HTTP/REST Client Support**: OAuth2-enabled `http.Client` with custom `RoundTripper`
- **Token Reuse**: Single `TokenManager` can be shared across multiple gRPC and HTTP clients

### Server-Side Authentication
- **JWT Token Validation**: Validates OAuth2/OIDC Bearer tokens with JWKS
- **Opaque Token Validation**: Supports RFC 7662 token introspection for opaque access tokens
- **gRPC Server Interceptors**: Automatic token validation for incoming requests
- **Claims Extraction**: Access user identity, scopes, and custom claims in handlers
- **Method Exemption**: Exempt specific endpoints (e.g., health checks) from authentication
- **JWKS Caching**: Automatic caching and refresh of public keys from OIDC providers

### Common Features
- **Thread-Safe**: Concurrent reads and writes with double-checked locking
- **TLS/mTLS**: Secure-by-default (TLS 1.2+, system root CAs) with optional custom CA and client certs
- **Provider-Agnostic**: Works with any OAuth2/OIDC provider (tested with Zitadel)

## Packages

### oauth2client

OAuth2 client-credentials token manager with gRPC interceptors.

```go
import "github.com/AmmannChristian/go-authx/oauth2client"

// Create token manager (without logging)
tm := oauth2client.NewTokenManager(
    ctx,
    "https://auth.example.com/oauth/v2/token",
    "client-id",
    "client-secret",
    "openid profile email",
)

// Or with logging enabled
tm := oauth2client.NewTokenManager(
    ctx,
    "https://auth.example.com/oauth/v2/token",
    "client-id",
    "client-secret",
    "openid profile email",
    oauth2client.WithLoggingEnabled(), // Enables default logging
)

// Or with custom logger
tm := oauth2client.NewTokenManager(
    ctx,
    tokenURL,
    clientID,
    clientSecret,
    scopes,
    oauth2client.WithLogger(customLogger), // Your custom logger
)

// Use with gRPC
conn, err := grpc.NewClient(
    "server:9090",
    grpc.WithUnaryInterceptor(tm.UnaryClientInterceptor()),
    grpc.WithStreamInterceptor(tm.StreamClientInterceptor()),
)
```

### grpcclient

Generic gRPC client builder with OAuth2 and TLS/mTLS support. Uses TLS with system root CAs by default; call `WithTLS` for custom CA or mTLS.

```go
import "github.com/AmmannChristian/go-authx/grpcclient"

// Create client builder
builder := grpcclient.NewBuilder().
    WithAddress("server.example.com:9090").
    WithOAuth2(
        "https://auth.example.com/oauth/v2/token",
        "client-id",
        "client-secret",
        "openid profile",
    ).
    WithTLS(
        "/path/to/ca.crt",  // CA certificate
        "/path/to/client.crt", // Client cert (optional for mTLS)
        "/path/to/client.key", // Client key (optional for mTLS)
        "server.example.com", // Server name override (optional)
    )

// Build connection
conn, err := builder.Build(ctx)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

// Use with any gRPC service
client := pb.NewYourServiceClient(conn)
```

### httpclient

Generic HTTP client builder with OAuth2 and TLS/mTLS support. Perfect for calling REST APIs with automatic token injection.

#### Simple Usage

```go
import "github.com/AmmannChristian/go-authx/httpclient"
import "github.com/AmmannChristian/go-authx/oauth2client"

// Create token manager
tm := oauth2client.NewTokenManager(
    ctx,
    "https://auth.example.com/oauth/v2/token",
    "client-id",
    "client-secret",
    "openid profile",
)

// Create HTTP client with OAuth2 authentication
client := httpclient.NewHTTPClient(tm)

// Make authenticated requests
resp, err := client.Get("https://api.example.com/users")
```

#### Advanced Usage with Builder

```go
import "github.com/AmmannChristian/go-authx/httpclient"

// Build HTTP client with advanced configuration
client, err := httpclient.NewBuilder().
    WithOAuth2(ctx, tokenURL, clientID, clientSecret, scopes).
    WithTLS(
        "/path/to/ca.crt",     // CA certificate (optional)
        "/path/to/client.crt", // Client cert for mTLS (optional)
        "/path/to/client.key", // Client key for mTLS (optional)
    ).
    WithTimeout(60 * time.Second).
    Build()

if err != nil {
    log.Fatal(err)
}

// Use standard http.Client methods
resp, err := client.Get("https://api.example.com/data")
resp, err := client.Post("https://api.example.com/data", "application/json", body)
```

### grpcserver

Server-side OAuth2/OIDC authentication for gRPC servers with TLS/mTLS support. Validates incoming Bearer tokens and makes claims available in handlers.

#### Basic Usage

```go
import "github.com/AmmannChristian/go-authx/grpcserver"

// Create token validator using the fluent builder
validator, err := grpcserver.NewValidatorBuilder(
    "https://auth.example.com",  // Issuer URL
    "my-api",                     // Expected audience
).Build()
if err != nil {
    log.Fatal(err)
}

// Create gRPC server with authentication interceptors
server := grpc.NewServer(
    grpc.UnaryInterceptor(
        grpcserver.UnaryServerInterceptor(validator),
    ),
    grpc.StreamInterceptor(
        grpcserver.StreamServerInterceptor(validator),
    ),
)

// Register your services
pb.RegisterYourServiceServer(server, &yourService{})

// Start serving
listener, _ := net.Listen("tcp", ":9090")
server.Serve(listener)
```

#### TLS/mTLS Configuration

Secure your gRPC server with TLS or mutual TLS (mTLS):

```go
import (
    "crypto/tls"
    "github.com/AmmannChristian/go-authx/grpcserver"
    "google.golang.org/grpc"
)

// Configure TLS with server certificates
tlsConfig := &grpcserver.TLSConfig{
    CertFile:   "/path/to/server.crt",
    KeyFile:    "/path/to/server.key",
    MinVersion: tls.VersionTLS12,
}

// For mTLS (mutual TLS), add CA and require client certificates
tlsConfig := &grpcserver.TLSConfig{
    CertFile:   "/path/to/server.crt",
    KeyFile:    "/path/to/server.key",
    CAFile:     "/path/to/ca.crt",
    ClientAuth: tls.RequireAndVerifyClientCert,
    MinVersion: tls.VersionTLS12,
}

// Create server option
tlsOpt, err := grpcserver.ServerOption(tlsConfig)
if err != nil {
    log.Fatal(err)
}

// Create gRPC server with TLS and authentication
server := grpc.NewServer(
    tlsOpt,
    grpc.UnaryInterceptor(grpcserver.UnaryServerInterceptor(validator)),
)
```

**Automatic Certificate Reload**: Certificates are automatically reloaded on each TLS handshake, enabling zero-downtime certificate rotation. This is perfect for environments using tools like Vault Agent or cert-manager that automatically renew certificates.

#### Advanced Configuration

```go
// Build validator with custom settings
validator, err := grpcserver.NewValidatorBuilder(issuerURL, audience).
    WithJWKSURL("https://auth.example.com/.well-known/jwks.json").
    WithCacheTTL(30 * time.Minute).
    WithLogger(log.Default()).
    Build()

// Or build validator for opaque tokens via introspection
opaqueValidator, err := grpcserver.NewValidatorBuilder(issuerURL, audience).
    WithOpaqueTokenIntrospection(
        "https://auth.example.com/oauth2/introspect",
        "introspection-client-id",
        "introspection-client-secret",
    ).
    Build()

// Configure interceptor with exempt methods
interceptor := grpcserver.UnaryServerInterceptor(
    validator,
    grpcserver.WithExemptMethods(
        "/grpc.health.v1.Health/Check",  // Health check doesn't require auth
        "/grpc.health.v1.Health/Watch",
    ),
    grpcserver.WithInterceptorLogger(log.Default()),
)

server := grpc.NewServer(grpc.UnaryInterceptor(interceptor))
```

#### Accessing Claims in Handlers

```go
func (s *server) GetUserProfile(ctx context.Context, req *pb.Request) (*pb.Response, error) {
    // Extract token claims from context
    claims, ok := grpcserver.TokenClaimsFromContext(ctx)
    if !ok {
        return nil, status.Error(codes.Unauthenticated, "not authenticated")
    }

    // Access user information
    userID := claims.Subject
    email := claims.Email
    scopes := claims.Scopes

    // Check required scope
    if !hasScope(claims.Scopes, "profile:read") {
        return nil, status.Error(codes.PermissionDenied, "missing scope")
    }

    // ... your business logic ...
}
```

#### Token Claims Structure

The `TokenClaims` struct contains standard OIDC claims:

```go
type TokenClaims struct {
    Subject  string    // User identifier (sub claim)
    Issuer   string    // Token issuer (iss claim)
    Audience []string  // Intended recipients (aud claim)
    Expiry   time.Time // Expiration time (exp claim)
    IssuedAt time.Time // Issued at time (iat claim)
    Scopes   []string  // OAuth2 scopes (scope/scp claim)
    Email    string    // User email (optional)
}
```

### httpserver

Server-side OAuth2/OIDC authentication middleware for HTTP servers with TLS/mTLS support.

#### Basic Usage

```go
import "github.com/AmmannChristian/go-authx/httpserver"

// Create token validator
validator, err := httpserver.NewValidatorBuilder(
    "https://auth.example.com",
    "my-api",
).Build()
if err != nil {
    log.Fatal(err)
}

// Create HTTP handler
mux := http.NewServeMux()
mux.HandleFunc("/api/protected", protectedHandler)

// Wrap with authentication middleware
authHandler := httpserver.Middleware(validator)(mux)

// Start server
http.ListenAndServe(":8080", authHandler)
```

#### TLS/mTLS Configuration

Secure your HTTP server with TLS or mutual TLS (mTLS):

```go
import (
    "crypto/tls"
    "net/http"
    "github.com/AmmannChristian/go-authx/httpserver"
)

// Configure TLS with server certificates
tlsConfig := &httpserver.TLSConfig{
    CertFile:   "/path/to/server.crt",
    KeyFile:    "/path/to/server.key",
    MinVersion: tls.VersionTLS12,
}

// For mTLS (mutual TLS), add CA and require client certificates
tlsConfig := &httpserver.TLSConfig{
    CertFile:   "/path/to/server.crt",
    KeyFile:    "/path/to/server.key",
    CAFile:     "/path/to/ca.crt",
    ClientAuth: tls.RequireAndVerifyClientCert,
    MinVersion: tls.VersionTLS12,
}

// Create server and configure TLS
server := &http.Server{
    Addr:    ":8443",
    Handler: authHandler,
}

if err := httpserver.ConfigureServer(server, tlsConfig); err != nil {
    log.Fatal(err)
}

// Start HTTPS server
server.ListenAndServeTLS("", "")
```

#### Advanced Middleware Configuration

```go
// Build validator with custom settings
validator, err := httpserver.NewValidatorBuilder(issuerURL, audience).
    WithJWKSURL("https://auth.example.com/.well-known/jwks.json").
    WithCacheTTL(30 * time.Minute).
    WithLogger(log.Default()).
    Build()

// Or build validator for opaque tokens via introspection
opaqueValidator, err := httpserver.NewValidatorBuilder(issuerURL, audience).
    WithOpaqueTokenIntrospection(
        "https://auth.example.com/oauth2/introspect",
        "introspection-client-id",
        "introspection-client-secret",
    ).
    Build()

// Configure middleware with exempt paths
middleware := httpserver.Middleware(
    validator,
    httpserver.WithExemptPaths("/health", "/metrics"),
    httpserver.WithExemptPathPrefixes("/public/", "/static/"),
    httpserver.WithMiddlewareLogger(log.Default()),
)

authHandler := middleware(mux)
```

#### Accessing Claims in Handlers

```go
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    // Extract token claims from context
    claims, ok := httpserver.TokenClaimsFromContext(r.Context())
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Access user information
    userID := claims.Subject
    email := claims.Email
    scopes := claims.Scopes

    // Check required scope
    if !hasScope(claims.Scopes, "profile:read") {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // ... your business logic ...
}
```

## Installation

```bash
go get github.com/AmmannChristian/go-authx
```

## Requirements

- Go 1.25.7 or higher
- golang.org/x/oauth2
- google.golang.org/grpc

## Usage Examples

### Shared Token Manager (gRPC + HTTP)

You can share a single `TokenManager` across multiple clients to reuse tokens efficiently:

```go
import (
    "github.com/AmmannChristian/go-authx/oauth2client"
    "github.com/AmmannChristian/go-authx/grpcclient"
    "github.com/AmmannChristian/go-authx/httpclient"
)

// Create shared token manager
tm := oauth2client.NewTokenManager(ctx, tokenURL, clientID, clientSecret, scopes)

// Create gRPC client using the token manager
grpcConn, _ := grpcclient.NewBuilder().
    WithAddress("grpc.example.com:9090").
    WithOAuth2(tokenURL, clientID, clientSecret, scopes).
    Build(ctx)

// Create HTTP client using the same token manager
httpClient := httpclient.NewHTTPClient(tm)

// Both clients will reuse the same OAuth2 tokens
```

### Examples Directory

Check the `examples/` directory for complete working examples:

- `http_client_simple.go` - Simple HTTP client with OAuth2
- `http_client_advanced.go` - Advanced HTTP client with TLS/mTLS
- `grpc_and_http_combined.go` - Using both gRPC and HTTP with shared tokens
- `grpc_server_with_oauth2.go` - gRPC server with OAuth2/OIDC token validation

## Architecture

```
go-authx/
├── oauth2client/          # Core OAuth2 token management
│   └── token_manager.go   # TokenManager for client credentials flow
├── grpcclient/            # gRPC client utilities
│   └── builder.go         # Fluent builder for gRPC client connections
├── grpcserver/            # gRPC server authentication
│   ├── validator.go       # JWT token validation with JWKS
│   ├── interceptor.go     # Server-side authentication interceptors
│   ├── builder.go         # Fluent builder for token validators
│   ├── context.go         # Context helpers for token claims
│   └── tls.go             # TLS/mTLS configuration for gRPC servers
├── httpclient/            # HTTP client utilities
│   ├── transport.go       # OAuth2Transport (http.RoundTripper)
│   └── builder.go         # Fluent builder for HTTP clients
├── httpserver/            # HTTP server authentication
│   ├── validator.go       # JWT token validation with JWKS
│   ├── middleware.go      # Server-side authentication middleware
│   ├── builder.go         # Fluent builder for token validators
│   ├── context.go         # Context helpers for token claims
│   └── tls.go             # TLS/mTLS configuration for HTTP servers
└── examples/              # Working examples
    ├── grpc_tls/          # gRPC server with TLS/mTLS
    └── http_tls/          # HTTP server with TLS/mTLS
```

## Key Design Principles

1. **Separation of Concerns**: Core token management (`oauth2client`) is independent of transport layer (gRPC/HTTP)
2. **Reusability**: Single `TokenManager` can be shared across multiple clients and protocols
3. **Builder Pattern**: Fluent API for easy configuration without complex constructors
4. **Secure Defaults**: TLS enabled by default with system root CAs
5. **Context Awareness**: Token fetches use detached contexts to prevent premature cancellation

## Contributing

We welcome contributions! Please see:

- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community standards
- [SECURITY.md](SECURITY.md) - Security policy and reporting

## Support

Need help? Check out:

- [SUPPORT.md](SUPPORT.md) - How to get help
- [GitHub Discussions](https://github.com/AmmannChristian/go-authx/discussions) - Ask questions
- [GitHub Issues](https://github.com/AmmannChristian/go-authx/issues) - Report bugs
- [pkg.go.dev](https://pkg.go.dev/github.com/AmmannChristian/go-authx) - Full documentation

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## License

See [LICENSE](LICENSE) file.
