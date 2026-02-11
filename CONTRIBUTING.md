# Contributing to go-authx

Thank you for your interest in contributing to `go-authx`! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/go-authx.git
   cd go-authx
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/AmmannChristian/go-authx.git
   ```

## Development Setup

### Prerequisites

- Go 1.25.7 or higher
- Make (optional, but recommended)
- Git

### Install Dependencies

```bash
go mod download
```

### Verify Setup

Run the test suite to ensure everything is working:

```bash
make test
# or
go test ./...
```

## Making Changes

### Branch Naming

Create a descriptive branch name:
- `feature/add-xyz` - for new features
- `fix/issue-123` - for bug fixes
- `docs/improve-readme` - for documentation
- `refactor/cleanup-xyz` - for refactoring

Example:
```bash
git checkout -b feature/add-custom-claims-validation
```

### Commit Messages

Follow conventional commit format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `style`: Code style changes (formatting)
- `chore`: Build/tooling changes
- `perf`: Performance improvements

Examples:
```
feat(grpcserver): add custom claims validation

Add support for validating custom JWT claims beyond
standard OIDC claims.

Closes #123
```

```
fix(oauth2client): handle token refresh race condition

Fixes race condition when multiple goroutines request
token refresh simultaneously.

Fixes #456
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make coverage

# Run with race detector
go test -race ./...

# Run specific package tests
go test ./grpcserver/...
```

### Writing Tests

- Write tests for all new functionality
- Maintain or improve code coverage (target: 90%+)
- Use table-driven tests where appropriate
- Include both positive and negative test cases
- Add integration tests for complex features

Example test structure:
```go
func TestFeatureName(t *testing.T) {
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
            got, err := FeatureName(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("FeatureName() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("FeatureName() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Coverage Requirements

- Minimum coverage: 90%
- Check coverage: `make coverage`
- View detailed report: `make coverage-html`

## Submitting Changes

### Before Submitting

1. **Update documentation** if needed
2. **Run tests**: `make test`
3. **Check coverage**: `make coverage`
4. **Run linters**: `make lint`
5. **Format code**: `gofmt -w .`
6. **Update CHANGELOG.md** if applicable

### Pull Request Process

1. **Update your fork** with latest upstream:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create Pull Request**:
   - Go to GitHub and create a PR from your fork
   - Fill out the PR template completely
   - Link related issues (e.g., "Closes #123")
   - Add appropriate labels

4. **Code Review**:
   - Address all review comments
   - Keep the PR focused and small
   - Maintain a clean commit history

5. **After Approval**:
   - Maintainers will merge your PR
   - Delete your feature branch after merge

### Pull Request Checklist

- [ ] Tests pass locally (`make test`)
- [ ] Code coverage is maintained/improved (`make coverage`)
- [ ] Code is formatted (`gofmt -w .`)
- [ ] Linters pass (`make lint`)
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated (if applicable)
- [ ] Commit messages follow conventional format
- [ ] PR description clearly explains the changes
- [ ] Related issues are linked

## Code Style

### Go Best Practices

- Follow [Effective Go](https://golang.org/doc/effective_go)
- Follow [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` for formatting
- Run `golangci-lint` before submitting

### Specific Guidelines

1. **Error Handling**:
   ```go
   // Good
   if err != nil {
       return fmt.Errorf("operation failed: %w", err)
   }

   // Bad
   if err != nil {
       return errors.New("operation failed")
   }
   ```

2. **Context Usage**:
   ```go
   // Good
   func DoWork(ctx context.Context, input string) error {
       // Use ctx for cancellation
   }

   // Bad
   func DoWork(input string) error {
       // No context support
   }
   ```

3. **Naming**:
   - Use clear, descriptive names
   - Follow Go naming conventions
   - Avoid abbreviations unless widely known

4. **Documentation**:
   - Document all exported functions, types, and constants
   - Use complete sentences
   - Include examples for complex APIs

5. **Package Structure**:
   - Keep packages focused and cohesive
   - Avoid circular dependencies
   - Use internal packages for implementation details

## Reporting Bugs

### Before Reporting

1. Check if the bug is already reported in [Issues](https://github.com/AmmannChristian/go-authx/issues)
2. Ensure you're using the latest version
3. Verify it's not a configuration issue

### Bug Report Template

Use the bug report template when creating an issue. Include:

- **Description**: Clear description of the bug
- **Steps to Reproduce**: Detailed steps
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**:
  - Go version: `go version`
  - OS: `uname -a`
  - Library version
- **Code Sample**: Minimal reproducible example
- **Logs**: Relevant error messages or logs

## Requesting Features

### Before Requesting

1. Check if the feature is already requested
2. Ensure it aligns with project goals
3. Consider if it can be implemented as external functionality

### Feature Request Template

Use the feature request template when creating an issue. Include:

- **Problem**: What problem does this solve?
- **Proposed Solution**: How should it work?
- **Alternatives**: Other solutions considered
- **Use Case**: Real-world scenario
- **Implementation Ideas**: Technical approach (optional)

## Additional Resources

- [Project README](README.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Go Documentation](https://pkg.go.dev/github.com/AmmannChristian/go-authx)

## Questions?

- Open a [Discussion](https://github.com/AmmannChristian/go-authx/discussions) for general questions
- Check existing [Issues](https://github.com/AmmannChristian/go-authx/issues) for answers
- Read the [Documentation](https://pkg.go.dev/github.com/AmmannChristian/go-authx)

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (see [LICENSE](LICENSE)).

Thank you for contributing to go-authx! 🎉
