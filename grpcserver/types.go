package grpcserver

import (
	"github.com/AmmannChristian/go-authx/authz"
	"github.com/AmmannChristian/go-authx/internal/validator"
)

// TokenValidator validates OAuth2/OIDC JWT tokens.
// This is an alias for the shared validator.TokenValidator interface.
type TokenValidator = validator.TokenValidator

// TokenClaims represents the claims extracted from a validated JWT token.
// This is an alias for the shared validator.TokenClaims type.
type TokenClaims = validator.TokenClaims

// JWTTokenValidator validates JWT tokens against JWKS from an OAuth2/OIDC provider.
// This is an alias for the shared validator.JWTTokenValidator type.
type JWTTokenValidator = validator.JWTTokenValidator

// OpaqueTokenValidator validates opaque tokens via OAuth2 token introspection.
// This is an alias for the shared validator.OpaqueTokenValidator type.
type OpaqueTokenValidator = validator.OpaqueTokenValidator

// IntrospectionClientAuthMethod defines how the service authenticates to the introspection endpoint.
type IntrospectionClientAuthMethod = validator.IntrospectionClientAuthMethod

const (
	// IntrospectionClientAuthMethodClientSecretBasic authenticates introspection calls with HTTP Basic auth.
	IntrospectionClientAuthMethodClientSecretBasic = validator.IntrospectionClientAuthMethodClientSecretBasic
	// IntrospectionClientAuthMethodPrivateKeyJWT authenticates introspection calls with RFC 7523 private_key_jwt.
	IntrospectionClientAuthMethodPrivateKeyJWT = validator.IntrospectionClientAuthMethodPrivateKeyJWT
)

const (
	// IntrospectionPrivateKeyJWTAlgorithmRS256 signs the client assertion with RS256.
	IntrospectionPrivateKeyJWTAlgorithmRS256 = validator.IntrospectionPrivateKeyJWTAlgorithmRS256
	// IntrospectionPrivateKeyJWTAlgorithmES256 signs the client assertion with ES256.
	IntrospectionPrivateKeyJWTAlgorithmES256 = validator.IntrospectionPrivateKeyJWTAlgorithmES256
)

// IntrospectionClientAuthConfig configures client authentication for introspection requests.
type IntrospectionClientAuthConfig = validator.IntrospectionClientAuthConfig

// Logger is an interface for optional logging in JWTTokenValidator.
// This is an alias for the shared validator.Logger interface.
type Logger = validator.Logger

// AuthorizationPolicy configures provider-agnostic authorization checks.
type AuthorizationPolicy = authz.AuthorizationPolicy

// RoleMatchMode defines how required roles are matched.
type RoleMatchMode = authz.RoleMatchMode

const (
	// RoleMatchModeAny allows requests when at least one required role is present.
	RoleMatchModeAny = authz.RoleMatchModeAny
	// RoleMatchModeAll allows requests only when all required roles are present.
	RoleMatchModeAll = authz.RoleMatchModeAll
)

// ScopeMatchMode defines how required scopes are matched.
type ScopeMatchMode = authz.ScopeMatchMode

const (
	// ScopeMatchModeAny allows requests when at least one required scope is present.
	ScopeMatchModeAny = authz.ScopeMatchModeAny
	// ScopeMatchModeAll allows requests only when all required scopes are present.
	ScopeMatchModeAll = authz.ScopeMatchModeAll
)
