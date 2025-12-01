# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Features

This library implements several security best practices:

### 1. Context-Aware Token Fetching
- **NEW**: Token fetches respect caller context cancellation and deadlines
- Use `GetTokenWithContext(ctx)` for explicit timeout control
- Prevents indefinite hangs in token endpoint calls

### 2. TLS Security
- **Minimum TLS Version**: TLS 1.2+ enforced by default
- **System Root CAs**: Secure defaults without configuration
- **Optional mTLS**: Client certificate authentication support
- All connections encrypted by default

### 3. Token Management
- Thread-safe token caching with double-checked locking
- Automatic token refresh before expiry
- No token storage in logs (optional logging must be explicitly enabled)
- OAuth2 Bearer tokens transmitted only in Authorization headers

### 4. Dependency Security
- Regular dependency updates via Dependabot
- Vulnerability scanning with `govulncheck`
- Static security analysis with `gosec`

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow responsible disclosure:

### Please DO:
1. **Email**: Send details to the repository maintainer (see GitHub profile)
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)
3. **Wait** for acknowledgment before public disclosure

### Please DON'T:
- Open public GitHub issues for security vulnerabilities
- Disclose the vulnerability publicly before we've had a chance to address it
- Exploit the vulnerability maliciously

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix & Disclosure**: Within 30 days (depending on severity)

## Security Best Practices for Users

When using this library:

### 1. Credential Management
```go
// ❌ DON'T hardcode credentials
tm := oauth2client.NewTokenManager(ctx, tokenURL, "hardcoded-id", "hardcoded-secret", scopes)

// ✅ DO use environment variables or secret management
clientID := os.Getenv("OAUTH2_CLIENT_ID")
clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")
tm := oauth2client.NewTokenManager(ctx, tokenURL, clientID, clientSecret, scopes)
```

### 2. Context Timeouts
```go
// ✅ Use context with timeout for token fetching
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

token, err := tm.GetTokenWithContext(ctx)
```

### 3. TLS Configuration
```go
// ✅ Always use TLS in production
builder := grpcclient.NewBuilder().
    WithAddress("server.example.com:9090").
    WithTLS("/path/to/ca.crt", "", "", "") // Minimum: CA cert
```

### 4. Logging
```go
// ✅ Only enable logging when needed (tokens may appear in logs)
tm := oauth2client.NewTokenManager(
    ctx, tokenURL, clientID, clientSecret, scopes,
    // oauth2client.WithLoggingEnabled(), // Commented out in production
)
```

### 5. Error Handling
```go
// ✅ Always check for token fetch errors
token, err := tm.GetTokenWithContext(ctx)
if err != nil {
    // Handle error - don't proceed with empty token
    return fmt.Errorf("authentication failed: %w", err)
}
```

## Known Limitations

1. **Token Storage**: Tokens are stored in memory only. No disk persistence.
2. **Refresh Window**: Default 1-minute leeway before expiry (configurable via code)
3. **OAuth2 Flow**: Only client-credentials flow supported (not authorization code flow)

## Security Audits

This library undergoes:
- Automated security scanning (gosec) on every commit
- Dependency vulnerability checks (govulncheck)
- Static analysis (staticcheck, golangci-lint)

See CI workflow results: [![CI](https://github.com/AmmannChristian/go-authx/actions/workflows/ci.yml/badge.svg)](https://github.com/AmmannChristian/go-authx/actions/workflows/ci.yml)

## Contact

For security concerns, please contact the maintainer directly via GitHub.