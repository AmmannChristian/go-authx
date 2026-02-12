# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-02-12

### Added
- Provider-agnostic authorization engine (`authz` package) for role/scope policy evaluation
- New authorization policy API: `AuthorizationPolicy`, `RoleMatchMode`, `ScopeMatchMode`
- Support for configurable role/scope claim paths with dot notation (including nested provider claims)
- Support for claim formats: space-separated `scope` strings, arrays, and object-key role maps (e.g. Zitadel role objects)
- New gRPC server option: `WithAuthorizationPolicy(...)`
- New HTTP middleware options: `WithAuthorizationPolicy(...)` and `WithForbiddenHandler(...)`
- Integration tests for authorization allow/deny flows in both gRPC and HTTP transports

### Changed
- Authorization is now evaluated after successful authentication in `grpcserver` and `httpserver` when a policy is configured
- Authorization remains disabled by default when no required roles/scopes are set (no breaking change to existing authN behavior)
- `TokenClaims` now includes `RawClaims` to enable provider-agnostic authorization evaluation
- README and package docs expanded with AuthN vs Authorization guidance, gRPC/HTTP examples, and provider-specific claim-path examples (ZITADEL, Keycloak, Auth0)

### Security
- Authorization denials are consistently mapped to `codes.PermissionDenied` (gRPC) and HTTP `403` (HTTP)
- Unknown authorization match modes are normalized fail-closed (`all`)

## [1.1.0] - 2026-02-12

### Added
- Support for OAuth2 introspection client authentication via RFC 7523 `private_key_jwt`
- New explicit introspection auth configuration type: `IntrospectionClientAuthConfig`
- New auth method and algorithm constants for server APIs (`client_secret_basic`, `private_key_jwt`, `RS256`, `ES256`)
- New builder option for HTTP and gRPC server validators: `WithOpaqueTokenIntrospectionAuth(...)`
- Support for introspection private key sources as PEM, JWK, and Zitadel key JSON envelope
- Comprehensive unit tests for private key JWT request fields, signed assertion claims, signing algorithms, and error handling

### Changed
- `WithOpaqueTokenIntrospection(...)` remains backward-compatible and defaults to `client_secret_basic`
- Introspection request generation now supports method-specific behavior (Basic Auth vs `client_assertion`)
- README and package docs expanded with JWT vs opaque token guidance and configuration examples for both auth methods

### Security
- `private_key_jwt` assertions now include short-lived `exp` (<= 60s) and unique per-request `jti`
- Validation strengthened for introspection client auth input (required fields, key parsing, algorithm/key compatibility)
- Sensitive configuration values are not logged

## [1.0.1] - 2026-02-11

### Changed
- Normalized introspection endpoint handling in `OpaqueTokenValidator`
- Added dedicated tests for introspection URL normalization and validation

### Security
- Enforced strict introspection URL requirements: absolute HTTPS URL, no userinfo/query/fragment
- Blocked local/private/link-local/multicast/unspecified IP targets for introspection requests

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

[Unreleased]: https://github.com/AmmannChristian/go-authx/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/AmmannChristian/go-authx/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/AmmannChristian/go-authx/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/AmmannChristian/go-authx/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/AmmannChristian/go-authx/compare/v0.1.3...v1.0.0
[0.1.3]: https://github.com/AmmannChristian/go-authx/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/AmmannChristian/go-authx/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/AmmannChristian/go-authx/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AmmannChristian/go-authx/releases/tag/v0.1.0
