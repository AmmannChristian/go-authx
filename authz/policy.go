package authz

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// RoleMatchMode defines how required roles are matched.
type RoleMatchMode string

const (
	// RoleMatchModeAny allows access if any required role is present.
	RoleMatchModeAny RoleMatchMode = "any"
	// RoleMatchModeAll allows access only if all required roles are present.
	RoleMatchModeAll RoleMatchMode = "all"
)

// ScopeMatchMode defines how required scopes are matched.
type ScopeMatchMode string

const (
	// ScopeMatchModeAny allows access if any required scope is present.
	ScopeMatchModeAny ScopeMatchMode = "any"
	// ScopeMatchModeAll allows access only if all required scopes are present.
	ScopeMatchModeAll ScopeMatchMode = "all"
)

var (
	defaultRoleClaimPaths  = []string{"roles"}
	defaultScopeClaimPaths = []string{"scope", "scp"}
)

// AuthorizationPolicy configures authorization checks against token claims.
//
// Authorization is disabled when both RequiredRoles and RequiredScopes are empty.
//
// Defaults:
//   - RoleMatchMode: any
//   - ScopeMatchMode: any
//   - RoleClaimPaths: ["roles"]
//   - ScopeClaimPaths: ["scope", "scp"]
//
// Unknown match modes are normalized to "all" (fail-closed).
type AuthorizationPolicy struct {
	RequiredRoles  []string
	RequiredScopes []string

	RoleMatchMode  RoleMatchMode
	ScopeMatchMode ScopeMatchMode

	RoleClaimPaths  []string
	ScopeClaimPaths []string
}

// ErrPermissionDenied indicates that authorization requirements are not satisfied.
var ErrPermissionDenied = errors.New("authorization: permission denied")

// PermissionDeniedError carries structured authorization failure details.
type PermissionDeniedError struct {
	MissingRoles  []string
	MissingScopes []string
}

// Error returns a concise authorization error message.
func (e *PermissionDeniedError) Error() string {
	hasRoles := len(e.MissingRoles) > 0
	hasScopes := len(e.MissingScopes) > 0

	switch {
	case hasRoles && hasScopes:
		return fmt.Sprintf("authorization: missing required roles %v and scopes %v", e.MissingRoles, e.MissingScopes)
	case hasRoles:
		return fmt.Sprintf("authorization: missing required roles %v", e.MissingRoles)
	case hasScopes:
		return fmt.Sprintf("authorization: missing required scopes %v", e.MissingScopes)
	default:
		return ErrPermissionDenied.Error()
	}
}

// Is enables errors.Is(err, ErrPermissionDenied).
func (e *PermissionDeniedError) Is(target error) bool {
	return target == ErrPermissionDenied
}

// Evaluator evaluates authorization policies against token claims.
type Evaluator struct {
	policy normalizedPolicy
}

type normalizedPolicy struct {
	requiredRoles  []string
	requiredScopes []string
	roleMatchMode  RoleMatchMode
	scopeMatchMode ScopeMatchMode
	rolePaths      []string
	scopePaths     []string
}

// NewEvaluator creates a policy evaluator with normalized defaults.
func NewEvaluator(policy AuthorizationPolicy) *Evaluator {
	return &Evaluator{policy: normalizePolicy(policy)}
}

// Enabled reports whether this policy performs authorization checks.
func (e *Evaluator) Enabled() bool {
	return len(e.policy.requiredRoles) > 0 || len(e.policy.requiredScopes) > 0
}

// Authorize evaluates the policy against claims.
func (e *Evaluator) Authorize(claims map[string]any) error {
	if !e.Enabled() {
		return nil
	}

	availableRoles := toSet(extractValuesFromPaths(claims, e.policy.rolePaths))
	availableScopes := toSet(extractValuesFromPaths(claims, e.policy.scopePaths))

	missingRoles := matchRequired(e.policy.requiredRoles, availableRoles, e.policy.roleMatchMode)
	missingScopes := matchRequired(e.policy.requiredScopes, availableScopes, e.policy.scopeMatchMode)
	if len(missingRoles) == 0 && len(missingScopes) == 0 {
		return nil
	}

	return &PermissionDeniedError{
		MissingRoles:  missingRoles,
		MissingScopes: missingScopes,
	}
}

// Evaluate is a convenience function for one-off authorization checks.
func Evaluate(policy AuthorizationPolicy, claims map[string]any) error {
	return NewEvaluator(policy).Authorize(claims)
}

// DefaultRoleClaimPaths returns a copy of the default role claim paths.
func DefaultRoleClaimPaths() []string {
	paths := make([]string, len(defaultRoleClaimPaths))
	copy(paths, defaultRoleClaimPaths)
	return paths
}

// DefaultScopeClaimPaths returns a copy of the default scope claim paths.
func DefaultScopeClaimPaths() []string {
	paths := make([]string, len(defaultScopeClaimPaths))
	copy(paths, defaultScopeClaimPaths)
	return paths
}

// ClaimsForEvaluation prepares claims for authorization.
//
// It preserves provided raw claims and fills standard scope claims from the
// normalized scopes slice when they are missing.
func ClaimsForEvaluation(rawClaims map[string]any, scopes []string) map[string]any {
	claims := cloneMap(rawClaims)
	if len(scopes) == 0 {
		return claims
	}

	if claims == nil {
		claims = make(map[string]any)
	}

	if _, ok := claims["scope"]; !ok {
		claims["scope"] = strings.Join(scopes, " ")
	}

	if _, ok := claims["scp"]; !ok {
		scopeValues := make([]any, 0, len(scopes))
		for _, scope := range scopes {
			scopeValues = append(scopeValues, scope)
		}
		claims["scp"] = scopeValues
	}

	return claims
}

func normalizePolicy(policy AuthorizationPolicy) normalizedPolicy {
	return normalizedPolicy{
		requiredRoles:  normalizeValues(policy.RequiredRoles),
		requiredScopes: normalizeValues(policy.RequiredScopes),
		roleMatchMode:  normalizeRoleMatchMode(policy.RoleMatchMode),
		scopeMatchMode: normalizeScopeMatchMode(policy.ScopeMatchMode),
		rolePaths:      normalizePaths(policy.RoleClaimPaths, defaultRoleClaimPaths),
		scopePaths:     normalizePaths(policy.ScopeClaimPaths, defaultScopeClaimPaths),
	}
}

func normalizeRoleMatchMode(mode RoleMatchMode) RoleMatchMode {
	normalized := strings.ToLower(strings.TrimSpace(string(mode)))
	switch normalized {
	case "", string(RoleMatchModeAny):
		return RoleMatchModeAny
	case string(RoleMatchModeAll):
		return RoleMatchModeAll
	default:
		return RoleMatchModeAll
	}
}

func normalizeScopeMatchMode(mode ScopeMatchMode) ScopeMatchMode {
	normalized := strings.ToLower(strings.TrimSpace(string(mode)))
	switch normalized {
	case "", string(ScopeMatchModeAny):
		return ScopeMatchModeAny
	case string(ScopeMatchModeAll):
		return ScopeMatchModeAll
	default:
		return ScopeMatchModeAll
	}
}

func normalizeValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

func normalizePaths(paths []string, defaults []string) []string {
	normalized := normalizeValues(paths)
	if len(normalized) > 0 {
		return normalized
	}

	result := make([]string, len(defaults))
	copy(result, defaults)
	return result
}

func extractValuesFromPaths(claims map[string]any, paths []string) []string {
	if len(claims) == 0 || len(paths) == 0 {
		return nil
	}

	values := make([]string, 0)
	for _, path := range paths {
		claim, ok := resolveClaimPath(claims, path)
		if !ok {
			continue
		}
		values = append(values, extractClaimValues(claim)...)
	}

	return normalizeValues(values)
}

func resolveClaimPath(claims map[string]any, path string) (any, bool) {
	segments := strings.Split(strings.TrimSpace(path), ".")
	if len(segments) == 0 {
		return nil, false
	}

	var current any = claims
	for _, segment := range segments {
		normalizedSegment := strings.TrimSpace(segment)
		if normalizedSegment == "" {
			return nil, false
		}

		next, ok := mapLookup(current, normalizedSegment)
		if !ok {
			return nil, false
		}
		current = next
	}

	return current, true
}

func mapLookup(value any, key string) (any, bool) {
	if typed, ok := value.(map[string]any); ok {
		found, exists := typed[key]
		return found, exists
	}

	rv := reflect.ValueOf(value)
	if !rv.IsValid() || rv.Kind() != reflect.Map {
		return nil, false
	}

	if rv.Type().Key().Kind() != reflect.String {
		return nil, false
	}

	mapValue := rv.MapIndex(reflect.ValueOf(key))
	if !mapValue.IsValid() {
		return nil, false
	}

	return mapValue.Interface(), true
}

func extractClaimValues(value any) []string {
	switch typed := value.(type) {
	case string:
		return strings.Fields(typed)
	case []string:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			result = append(result, strings.Fields(item)...)
		}
		return result
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			result = append(result, extractClaimValues(item)...)
		}
		return result
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, strings.TrimSpace(key))
		}
		sort.Strings(keys)
		return keys
	}

	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return nil
	}

	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		result := make([]string, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			result = append(result, extractClaimValues(rv.Index(i).Interface())...)
		}
		return result
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil
		}

		keys := make([]string, 0, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			key := strings.TrimSpace(iter.Key().String())
			if key != "" {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		return keys
	default:
		return nil
	}
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func matchRequired(required []string, available map[string]struct{}, matchMode fmt.Stringer) []string {
	if len(required) == 0 {
		return nil
	}

	mode := strings.ToLower(strings.TrimSpace(matchMode.String()))
	if mode == string(RoleMatchModeAny) {
		for _, value := range required {
			if _, ok := available[value]; ok {
				return nil
			}
		}
		missing := make([]string, len(required))
		copy(missing, required)
		return missing
	}

	missing := make([]string, 0, len(required))
	for _, value := range required {
		if _, ok := available[value]; !ok {
			missing = append(missing, value)
		}
	}

	return missing
}

func (m RoleMatchMode) String() string {
	return string(m)
}

func (m ScopeMatchMode) String() string {
	return string(m)
}

func cloneMap(source map[string]any) map[string]any {
	if len(source) == 0 {
		return nil
	}

	copied := make(map[string]any, len(source))
	for key, value := range source {
		copied[key] = value
	}

	return copied
}
