# Contributing to go-authx

Thank you for considering contributing to go-authx! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check existing issues to avoid duplicates
2. Use the latest version to verify the bug still exists
3. Collect relevant information (Go version, OS, error messages)

When creating a bug report, include:
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- Code samples (minimal reproducible example)
- Environment details

### Suggesting Features

Feature requests are welcome! Please:
1. Check existing issues/discussions first
2. Explain the use case clearly
3. Describe the proposed solution
4. Consider backward compatibility

### Pull Requests

#### Before You Start

1. **Open an issue first** for significant changes
2. **Check existing PRs** to avoid duplicate work
3. **Discuss architecture** for major features

#### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/go-authx.git
cd go-authx

# Install dependencies
go mod download

# Run tests
go test ./...

# Run linters
golangci-lint run
```

#### Making Changes

1. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow Go best practices
   - Add tests for new functionality
   - Update documentation as needed

3. **Write good commit messages**
   ```
   Short (50 chars or less) summary

   More detailed explanation if needed. Wrap at 72 characters.

   - Bullet points are okay
   - Use present tense ("Add feature" not "Added feature")
   - Reference issues: "Fixes #123"
   ```

4. **Ensure all checks pass**
   ```bash
   # Run tests
   go test -v -race -coverprofile=coverage.out ./...

   # Run linters
   golangci-lint run

   # Run security scanner
   gosec ./...

   # Check for vulnerabilities
   govulncheck ./...

   # Format code
   go fmt ./...
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

#### Pull Request Guidelines

- **Title**: Clear, descriptive summary
- **Description**:
  - What changes were made and why
  - Link to related issues
  - Screenshots/examples if applicable
- **Tests**: All new code must have tests
- **Documentation**: Update README.md, GoDoc comments
- **Backward Compatibility**: Avoid breaking changes when possible
- **Small PRs**: Prefer smaller, focused changes

## Development Guidelines

### Code Style

- Follow standard Go conventions
- Use `gofmt` and `goimports`
- Respect the existing code style
- Add GoDoc comments for exported types/functions

### Testing

- Write table-driven tests where appropriate
- Test both success and error cases
- Use meaningful test names
- Aim for >80% code coverage
- Use race detector: `go test -race`

Example test structure:
```go
func TestFeature(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {
            name:    "valid input",
            input:   "test",
            want:    "result",
            wantErr: false,
        },
        {
            name:    "invalid input",
            input:   "",
            want:    "",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Feature(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Feature() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("Feature() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Documentation

- Add GoDoc comments for all exported items
- Update README.md with new features
- Add examples for complex functionality
- Keep comments concise and clear

### Error Handling

- Use `fmt.Errorf` with `%w` for error wrapping
- Provide context in error messages
- Don't panic in library code

```go
// ✅ Good
if err != nil {
    return fmt.Errorf("failed to connect to %s: %w", address, err)
}

// ❌ Bad
if err != nil {
    panic(err)
}
```

### Security

- Never log sensitive data (tokens, passwords)
- Use context timeouts appropriately
- Follow the security guidelines in SECURITY.md
- Run `gosec` before submitting

## Project Structure

```
go-authx/
├── oauth2client/          # Core OAuth2 token management
│   ├── token_manager.go
│   └── token_manager_test.go
├── grpcclient/            # gRPC client builder
│   ├── builder.go
│   └── builder_test.go
├── httpclient/            # HTTP client builder
│   ├── builder.go
│   ├── transport.go
│   └── *_test.go
├── .github/workflows/     # CI/CD pipelines
├── examples/              # Usage examples
└── README.md              # Project documentation
```

## CI/CD Pipeline

All PRs must pass:
- ✅ Tests (Go 1.21, 1.22, 1.23)
- ✅ Code coverage (reported to Codecov)
- ✅ Linters (golangci-lint)
- ✅ Static analysis (staticcheck)
- ✅ Security scan (gosec)
- ✅ Vulnerability check (govulncheck)
- ✅ Go vet
- ✅ Build verification (Linux, macOS, Windows)

## Release Process

Releases are managed by maintainers:

1. Update version in documentation
2. Create and push a version tag: `git tag v1.2.3`
3. GitHub Actions automatically creates the release
4. Release notes are auto-generated from commits

## Getting Help

- 📖 Read the [README.md](README.md)
- 🔍 Search [existing issues](https://github.com/AmmannChristian/go-authx/issues)
- 💬 Open a [discussion](https://github.com/AmmannChristian/go-authx/discussions)
- 📝 Create a [new issue](https://github.com/AmmannChristian/go-authx/issues/new)

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (see LICENSE file).

## Questions?

Feel free to open an issue for any questions about contributing!