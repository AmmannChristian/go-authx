# Support

Thank you for using `go-authx`! This document provides information on how to get help and support.

## Documentation

### Official Documentation

- **Go Package Documentation**: [pkg.go.dev/github.com/AmmannChristian/go-authx](https://pkg.go.dev/github.com/AmmannChristian/go-authx)
- **README**: [README.md](README.md) - Quick start guide and examples
- **Contributing Guide**: [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute
- **Security Policy**: [SECURITY.md](SECURITY.md) - Security guidelines and reporting
- **Changelog**: [CHANGELOG.md](CHANGELOG.md) - Version history and changes

### Examples

Check the [`examples/`](examples/) directory for working code examples:

- `http_client_simple.go` - Basic HTTP client with OAuth2
- `http_client_advanced.go` - Advanced HTTP client with TLS/mTLS
- `grpc_and_http_combined.go` - Combined gRPC and HTTP usage
- `grpc_server_with_oauth2.go` - gRPC server with authentication
- `grpc_tls/` - gRPC server with TLS/mTLS
- `http_tls/` - HTTP server with TLS/mTLS

## Getting Help

### Before Asking for Help

1. **Check the documentation** - Most questions are answered in the README or pkg.go.dev docs
2. **Search existing issues** - Your question might already be answered
3. **Try the examples** - Working examples demonstrate common use cases
4. **Review test files** - Tests show how features are intended to be used

### Where to Get Help

#### 💬 GitHub Discussions (Recommended)

For questions, ideas, and general discussion:

**[Open a Discussion](https://github.com/AmmannChristian/go-authx/discussions)**

Use Discussions for:
- ❓ Questions about usage
- 💡 Ideas and suggestions
- 🤝 Community support
- 📣 Announcements and updates

#### 🐛 GitHub Issues

For bugs and feature requests:

**[Create an Issue](https://github.com/AmmannChristian/go-authx/issues/new/choose)**

Use Issues for:
- 🐛 Bug reports
- ✨ Feature requests
- 📝 Documentation improvements
- ⚡ Performance issues

**Note**: Please use the appropriate issue template and provide all requested information.

#### 🔒 Security Issues

For security vulnerabilities:

**[Report Privately](https://github.com/AmmannChristian/go-authx/security/advisories/new)**

See [SECURITY.md](SECURITY.md) for details on our security policy.

## Common Issues

### Installation Issues

**Problem**: `go get` fails or can't find the package

**Solution**:
```bash
# Ensure you're using Go 1.25.7+
go version

# Clear module cache
go clean -modcache

# Try again
go get github.com/AmmannChristian/go-authx
```

### OAuth2 Token Issues

**Problem**: Token validation fails or authentication errors

**Solution**:
- Verify issuer URL is correct and accessible
- Check that audience matches your configuration
- Ensure token is not expired
- Verify JWKS URL is reachable
- Enable logging to see detailed error messages:
  ```go
  validator, _ := grpcserver.NewValidatorBuilder(issuer, audience).
      WithLogger(log.Default()).
      Build()
  ```

### TLS/Certificate Issues

**Problem**: TLS handshake failures or certificate errors

**Solution**:
- Verify certificate paths are correct
- Check file permissions (keys should be 0600)
- Ensure certificates are in PEM format
- Verify certificates are not expired:
  ```bash
  openssl x509 -in cert.crt -noout -dates
  ```
- For mTLS, ensure CA file matches client certificates

### Performance Issues

**Problem**: Slow token validation or high latency

**Solution**:
- Check JWKS cache TTL (default: 1 hour)
- Monitor network latency to auth provider
- Consider shorter cache TTL if keys rotate frequently
- Use connection pooling for gRPC clients
- Enable keep-alive for HTTP connections

## Version Support

| Version | Support Status | End of Support |
|---------|---------------|----------------|
| 0.1.x   | ✅ Supported   | Active         |
| < 0.1.0 | ❌ Unsupported | -              |

We recommend always using the latest version for bug fixes and security updates.

## Response Times

This is an open-source project maintained by volunteers. Response times vary:

- **Critical Security Issues**: Within 48 hours
- **Bug Reports**: Within 1 week
- **Feature Requests**: Within 2 weeks
- **Questions**: Best effort, typically within a few days

## Community Guidelines

When seeking support:

✅ **Do:**
- Be respectful and patient
- Provide clear, detailed information
- Search for existing answers first
- Follow up with solutions you find
- Help others when you can

❌ **Don't:**
- Demand immediate responses
- Post duplicate questions
- Share sensitive information (tokens, secrets, etc.)
- Ask the same question in multiple places

## Commercial Support

Currently, we do not offer commercial support. For professional services or consulting:

- Consider hiring a contractor familiar with Go and OAuth2/OIDC
- Reach out via GitHub Discussions to discuss enterprise needs

## Contributing

Want to help improve `go-authx`?

- 📖 Improve documentation
- 🐛 Fix bugs
- ✨ Add features
- 🧪 Write tests
- 📝 Write tutorials or blog posts

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Stay Updated

- ⭐ Star the repository to show support
- 👀 Watch for updates and releases
- 📢 Follow announcements in Discussions

## Additional Resources

### Go OAuth2/OIDC Resources

- [OAuth 2.0 Specification](https://oauth.net/2/)
- [OpenID Connect Specification](https://openid.net/connect/)
- [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2)
- [gRPC Authentication Guide](https://grpc.io/docs/guides/auth/)

### Related Projects

- [go-oidc](https://github.com/coreos/go-oidc) - OpenID Connect client
- [grpc-go](https://github.com/grpc/grpc-go) - gRPC for Go
- [oauth2](https://github.com/golang/oauth2) - OAuth2 for Go

## License

This project is licensed under the terms specified in [LICENSE](LICENSE).

---

**Still need help?** [Open a Discussion](https://github.com/AmmannChristian/go-authx/discussions) and we'll be happy to assist! 🚀
