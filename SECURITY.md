# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

We take the security of `go-authx` seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please do NOT:

- Open a public GitHub issue
- Disclose the vulnerability publicly before it has been addressed

### Please DO:

**Report security vulnerabilities via GitHub Security Advisories:**

1. Go to https://github.com/AmmannChristian/go-authx/security/advisories
2. Click "Report a vulnerability"
3. Fill out the form with details about the vulnerability

**Or send an email to:**

- Email: [Your security contact email here]
- Include "[SECURITY]" in the subject line
- Provide detailed information about the vulnerability

### What to include in your report:

- Type of vulnerability (e.g., XSS, SQL injection, authentication bypass)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

### Response Timeline:

- **Initial Response**: Within 48 hours
- **Vulnerability Confirmation**: Within 7 days
- **Fix & Disclosure**: Coordinated with reporter, typically within 30 days

## Security Best Practices

When using `go-authx`, we recommend:

### For OAuth2/OIDC:
- Always use HTTPS endpoints for OAuth2 token URLs
- Store client secrets securely (e.g., environment variables, secret managers)
- Use short-lived tokens with appropriate refresh strategies
- Validate token issuer and audience claims
- Implement proper scope-based authorization

### For TLS/mTLS:
- Use TLS 1.3 where possible (`MinVersion: tls.VersionTLS13`)
- Keep certificates up-to-date and monitor expiration
- Use strong key lengths (minimum 2048-bit RSA or 256-bit ECDSA)
- For mTLS, use `tls.RequireAndVerifyClientCert` in production
- Store private keys securely with restricted file permissions (0600)
- Rotate certificates regularly

### For Server Authentication:
- Exempt only necessary endpoints from authentication
- Use JWKS caching with reasonable TTL (default: 1 hour)
- Implement rate limiting for public endpoints
- Log authentication failures for monitoring
- Validate scopes for authorization decisions

### For Token Management:
- Never log access tokens or secrets
- Use context cancellation appropriately
- Implement timeout policies for token fetching
- Handle token refresh failures gracefully

## Known Security Considerations

### Token Storage:
This library stores OAuth2 tokens in memory. For distributed systems, consider:
- Using a shared cache (Redis, etc.) for token synchronization
- Implementing token persistence with encryption at rest

### JWKS Caching:
JWKS keys are cached to reduce load on auth providers. This means:
- Key rotation has a delay (up to cache TTL)
- Compromised keys remain valid until cache expires
- Consider shorter TTL for high-security environments

### TLS Certificate Validation:
- The library uses system root CAs by default
- Custom CAs must be explicitly configured
- Certificate validation cannot be disabled

## Security Updates

Security updates will be:
- Released as patch versions (e.g., 0.1.3 → 0.1.4)
- Documented in CHANGELOG.md with `[SECURITY]` prefix
- Announced via GitHub Security Advisories
- Tagged with appropriate CVE identifiers when applicable

## Security Features

This library includes:
- ✅ TLS 1.2+ enforcement (configurable to TLS 1.3)
- ✅ JWT signature verification with JWKS
- ✅ Token expiration validation
- ✅ Audience and issuer claim validation
- ✅ Secure path handling with `os.OpenInRoot`
- ✅ Thread-safe token caching
- ✅ Context-aware cancellation
- ✅ No token logging in production
- ✅ mTLS support for client authentication

## Acknowledgments

We appreciate the security research community and will acknowledge security researchers who responsibly disclose vulnerabilities (unless they prefer to remain anonymous).

## Questions?

If you have questions about this security policy, please open a discussion on GitHub or contact the maintainers.