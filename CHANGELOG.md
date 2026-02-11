# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-02-11

### Added
- TLS/mTLS support for gRPC servers (`grpcserver.TLSConfig`, `grpcserver.ServerOption`)
- TLS/mTLS support for HTTP servers (`httpserver.TLSConfig`, `httpserver.ConfigureServer`)
- Support for all TLS ClientAuth modes (NoClientCert to RequireAndVerifyClientCert)
- **Automatic certificate reloading** for gRPC servers - certificates are now reloaded on each TLS handshake
- Comprehensive integration tests with generated certificates for TLS
- Integration tests for certificate reload functionality
- Examples for TLS-enabled servers (`examples/grpc_tls/`, `examples/http_tls/`)
- OAuth2 opaque token validation via RFC 7662 token introspection (`OpaqueTokenValidator`)
- Opaque token support in both server builders via `WithOpaqueTokenIntrospection(...)`
- Additional tests and docs for opaque token validation across HTTP and gRPC server packages

### Changed
- Updated README.md with comprehensive TLS configuration examples
- Improved architecture documentation with TLS components
- **Modified `grpcserver.NewServerCredentials()`** to use `GetCertificate` callback for on-demand certificate loading
- Updated module dependencies in `go.mod` and `go.sum` to latest compatible versions
- Updated minimum Go version in `go.mod` to `1.25.7`

### Security
- TLS 1.2+ enforced as minimum version for all server connections
- Secure path handling with `os.OpenInRoot` for certificate files
- Support for mutual TLS (mTLS) with client certificate verification
- **Zero-downtime certificate rotation** - services can now have certificates rotated (e.g., by Vault Agent or cert-manager) without requiring restart
- Go toolchain bump to `1.25.7` to include latest stdlib security patches (including `net/url` and `crypto/tls`)

## [0.1.3] - 2024-12-05

### Added
- Server-side OAuth2/OIDC authentication for HTTP servers (`httpserver` package)
- HTTP middleware for OAuth2/OIDC token validation (`httpserver.Middleware`)
- Path and path prefix exemption for public HTTP endpoints
- Custom unauthorized handler support for HTTP middleware
- Token claims extraction in HTTP handlers (`httpserver.TokenClaimsFromContext`)

### Changed
- Improved test coverage to 90%+
- Enhanced documentation for HTTP server authentication

## [0.1.2] - Previous Release

### Added
- gRPC server authentication with JWT/JWKS validation (`grpcserver` package)
- Server-side interceptors for gRPC authentication
- Claims extraction in gRPC handlers
- Method exemption for health checks

## [0.1.1] - Previous Release

### Added
- HTTP client builder with OAuth2 support (`httpclient` package)
- TLS/mTLS support for HTTP clients

## [0.1.0] - Initial Release

### Added
- OAuth2 client-credentials token management (`oauth2client` package)
- gRPC client builder with OAuth2 support (`grpcclient` package)
- Context-aware token fetching with cancellation support
- Automatic token refresh with early expiration detection
- Thread-safe token caching with double-checked locking
- TLS/mTLS support for gRPC clients
- JWKS caching and automatic refresh
- Fluent builder APIs for all client components
- Comprehensive test coverage
- Example implementations for common use cases

### Security
- Secure-by-default TLS configuration (TLS 1.2+, system root CAs)
- Bearer token validation with JWKS
- Support for OAuth2 scopes
- Context isolation for token claims

[Unreleased]: https://github.com/AmmannChristian/go-authx/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/AmmannChristian/go-authx/compare/v0.1.3...v1.0.0
[0.1.3]: https://github.com/AmmannChristian/go-authx/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/AmmannChristian/go-authx/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/AmmannChristian/go-authx/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AmmannChristian/go-authx/releases/tag/v0.1.0
