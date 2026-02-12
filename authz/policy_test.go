package authz

import (
	"errors"
	"reflect"
	"testing"
)

func TestEvaluator_DisabledWhenNoRequirements(t *testing.T) {
	evaluator := NewEvaluator(AuthorizationPolicy{})
	if evaluator.Enabled() {
		t.Fatal("expected evaluator to be disabled")
	}

	if err := evaluator.Authorize(nil); err != nil {
		t.Fatalf("expected nil error for disabled evaluator, got %v", err)
	}
}

func TestEvaluator_DefaultScopeStringParsing(t *testing.T) {
	evaluator := NewEvaluator(AuthorizationPolicy{
		RequiredScopes: []string{"profile:read"},
	})

	claims := map[string]any{
		"scope": "openid profile:read profile:write",
	}

	if err := evaluator.Authorize(claims); err != nil {
		t.Fatalf("expected authorization to pass, got %v", err)
	}
}

func TestEvaluator_NestedClaimPaths(t *testing.T) {
	evaluator := NewEvaluator(AuthorizationPolicy{
		RequiredRoles: []string{"admin"},
		RoleClaimPaths: []string{
			"realm_access.roles",
			"resource_access.my-client.roles",
		},
	})

	claims := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"viewer"},
		},
		"resource_access": map[string]any{
			"my-client": map[string]any{
				"roles": []any{"admin", "auditor"},
			},
		},
	}

	if err := evaluator.Authorize(claims); err != nil {
		t.Fatalf("expected authorization to pass, got %v", err)
	}
}

func TestEvaluator_ArrayParsingAcrossClaimPaths(t *testing.T) {
	evaluator := NewEvaluator(AuthorizationPolicy{
		RequiredRoles: []string{"team-admin"},
		RoleClaimPaths: []string{
			"groups",
			"permissions",
		},
		RequiredScopes: []string{"write"},
		ScopeClaimPaths: []string{
			"scp",
		},
	})

	claims := map[string]any{
		"groups":      []any{"team-admin", "viewer"},
		"permissions": []string{"feature:x"},
		"scp":         []any{"read", "write"},
	}

	if err := evaluator.Authorize(claims); err != nil {
		t.Fatalf("expected authorization to pass, got %v", err)
	}
}

func TestEvaluator_ZitadelObjectKeyRoles(t *testing.T) {
	evaluator := NewEvaluator(AuthorizationPolicy{
		RequiredRoles: []string{"sales-admin", "billing-viewer"},
		RoleMatchMode: RoleMatchModeAll,
		RoleClaimPaths: []string{
			"urn:zitadel:iam:org:project:roles",
			"urn:zitadel:iam:org:project:123456789:roles",
		},
	})

	claims := map[string]any{
		"urn:zitadel:iam:org:project:roles": map[string]any{
			"sales-admin": map[string]any{"foo": "bar"},
		},
		"urn:zitadel:iam:org:project:123456789:roles": map[string]any{
			"billing-viewer": true,
		},
	}

	if err := evaluator.Authorize(claims); err != nil {
		t.Fatalf("expected authorization to pass, got %v", err)
	}
}

func TestEvaluator_MatchModes(t *testing.T) {
	tests := []struct {
		name    string
		policy  AuthorizationPolicy
		claims  map[string]any
		wantErr bool
	}{
		{
			name: "role any allows one hit",
			policy: AuthorizationPolicy{
				RequiredRoles: []string{"admin", "editor"},
				RoleMatchMode: RoleMatchModeAny,
			},
			claims: map[string]any{"roles": []any{"editor"}},
		},
		{
			name: "role all requires every role",
			policy: AuthorizationPolicy{
				RequiredRoles: []string{"admin", "editor"},
				RoleMatchMode: RoleMatchModeAll,
			},
			claims:  map[string]any{"roles": []any{"editor"}},
			wantErr: true,
		},
		{
			name: "scope any allows one hit",
			policy: AuthorizationPolicy{
				RequiredScopes: []string{"write", "delete"},
				ScopeMatchMode: ScopeMatchModeAny,
			},
			claims: map[string]any{"scope": "read write"},
		},
		{
			name: "scope all requires every scope",
			policy: AuthorizationPolicy{
				RequiredScopes: []string{"read", "write"},
				ScopeMatchMode: ScopeMatchModeAll,
			},
			claims:  map[string]any{"scope": "read"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewEvaluator(tt.policy).Authorize(tt.claims)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}

func TestEvaluator_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		policy  AuthorizationPolicy
		claims  map[string]any
		wantErr bool
	}{
		{
			name: "missing claim",
			policy: AuthorizationPolicy{
				RequiredScopes: []string{"read"},
			},
			claims:  map[string]any{},
			wantErr: true,
		},
		{
			name: "wrong claim type",
			policy: AuthorizationPolicy{
				RequiredRoles: []string{"admin"},
			},
			claims:  map[string]any{"roles": 1234},
			wantErr: true,
		},
		{
			name: "empty required lists disables authz",
			policy: AuthorizationPolicy{
				RequiredRoles:  []string{},
				RequiredScopes: []string{},
			},
			claims: map[string]any{},
		},
		{
			name: "invalid role match mode fails closed to all",
			policy: AuthorizationPolicy{
				RequiredRoles: []string{"admin", "editor"},
				RoleMatchMode: RoleMatchMode("invalid"),
			},
			claims:  map[string]any{"roles": []any{"admin"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewEvaluator(tt.policy).Authorize(tt.claims)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}

func TestPermissionDeniedError_Is(t *testing.T) {
	err := NewEvaluator(AuthorizationPolicy{
		RequiredScopes: []string{"admin"},
	}).Authorize(map[string]any{"scope": "read"})

	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}

	var typedErr *PermissionDeniedError
	if !errors.As(err, &typedErr) {
		t.Fatalf("expected PermissionDeniedError, got %T", err)
	}
	if len(typedErr.MissingScopes) != 1 || typedErr.MissingScopes[0] != "admin" {
		t.Fatalf("unexpected missing scopes: %v", typedErr.MissingScopes)
	}
}

func TestClaimsForEvaluation(t *testing.T) {
	prepared := ClaimsForEvaluation(nil, []string{"read", "write"})
	if prepared["scope"] != "read write" {
		t.Fatalf("unexpected scope value: %#v", prepared["scope"])
	}

	raw := map[string]any{"scope": "profile"}
	prepared = ClaimsForEvaluation(raw, []string{"read"})
	if prepared["scope"] != "profile" {
		t.Fatalf("expected existing scope to be preserved, got %#v", prepared["scope"])
	}
	if !reflect.DeepEqual(raw, map[string]any{"scope": "profile"}) {
		t.Fatalf("expected raw map to remain unchanged, got %#v", raw)
	}
}

func TestDefaultClaimPathsCopies(t *testing.T) {
	roles := DefaultRoleClaimPaths()
	roles[0] = "changed"

	scopes := DefaultScopeClaimPaths()
	scopes[0] = "changed"

	if DefaultRoleClaimPaths()[0] == "changed" {
		t.Fatal("expected role defaults to be copied")
	}
	if DefaultScopeClaimPaths()[0] == "changed" {
		t.Fatal("expected scope defaults to be copied")
	}
}
