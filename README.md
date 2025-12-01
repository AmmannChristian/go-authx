# Go OAuth2 Client Library

[![CI](https://github.com/AmmannChristian/go-authx/actions/workflows/ci.yml/badge.svg)](https://github.com/AmmannChristian/go-authx/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/AmmannChristian/go-authx)](https://goreportcard.com/report/github.com/AmmannChristian/go-authx)
[![GoDoc](https://pkg.go.dev/badge/github.com/AmmannChristian/go-authx)](https://pkg.go.dev/github.com/AmmannChristian/go-authx)
[![codecov](https://codecov.io/gh/AmmannChristian/go-authx/branch/main/graph/badge.svg)](https://codecov.io/gh/AmmannChristian/go-authx)
[![License](https://img.shields.io/github/license/AmmannChristian/go-authx)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/AmmannChristian/go-authx)](go.mod)

Reusable Go library for OAuth2 client-credentials authentication with support for both **gRPC** and **HTTP/REST** clients.

## Features

- **OAuth2 Token Management**: Client-credentials flow with early refresh and scope parsing
- **Context-Aware Token Fetching**: Respects cancellation and deadlines via `GetTokenWithContext()`
- **Optional Logging**: Configurable token refresh logging with custom logger support
- **gRPC Support**: Automatic Bearer injection via interceptors for unary and streaming calls
- **HTTP/REST Support**: OAuth2-enabled `http.Client` with custom `RoundTripper`
- **Thread-Safe**: Concurrent reads and writes with double-checked locking
- **TLS/mTLS**: Secure-by-default (TLS 1.2+, system root CAs) with optional custom CA and client certs
- **Provider-Agnostic**: Works with any OAuth2 provider (tested with Zitadel)
- **Token Reuse**: Single `TokenManager` can be shared across multiple gRPC and HTTP clients

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

## Installation

```bash
go get github.com/AmmannChristian/go-authx
```

## Requirements

- Go 1.23 or higher
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

## Architecture

```
go-authx/
├── oauth2client/          # Core OAuth2 token management
│   └── token_manager.go   # TokenManager with gRPC interceptors
├── grpcclient/            # gRPC client utilities
│   └── builder.go         # Fluent builder for gRPC connections
├── httpclient/            # HTTP client utilities
│   ├── transport.go       # OAuth2Transport (http.RoundTripper)
│   └── builder.go         # Fluent builder for HTTP clients
└── examples/              # Working examples
```

## Key Design Principles

1. **Separation of Concerns**: Core token management (`oauth2client`) is independent of transport layer (gRPC/HTTP)
2. **Reusability**: Single `TokenManager` can be shared across multiple clients and protocols
3. **Builder Pattern**: Fluent API for easy configuration without complex constructors
4. **Secure Defaults**: TLS enabled by default with system root CAs
5. **Context Awareness**: Token fetches use detached contexts to prevent premature cancellation

## License

See LICENSE file.
