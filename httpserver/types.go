package httpserver

import "github.com/AmmannChristian/go-authx/internal/validator"

// TokenValidator validates OAuth2/OIDC JWT tokens.
// This is an alias for the shared validator.TokenValidator interface.
type TokenValidator = validator.TokenValidator

// TokenClaims represents the claims extracted from a validated JWT token.
// This is an alias for the shared validator.TokenClaims type.
type TokenClaims = validator.TokenClaims

// JWTTokenValidator validates JWT tokens against JWKS from an OAuth2/OIDC provider.
// This is an alias for the shared validator.JWTTokenValidator type.
type JWTTokenValidator = validator.JWTTokenValidator

// Logger is an interface for optional logging in JWTTokenValidator.
// This is an alias for the shared validator.Logger interface.
type Logger = validator.Logger
