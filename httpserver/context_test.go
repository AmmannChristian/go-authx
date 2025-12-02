package httpserver

import (
	"context"
	"testing"
	"time"
)

func TestWithTokenClaims(t *testing.T) {
	ctx := context.Background()
	claims := &TokenClaims{
		Subject:  "user123",
		Issuer:   "https://auth.example.com",
		Audience: []string{"my-api"},
		Expiry:   time.Now().Add(time.Hour),
		IssuedAt: time.Now(),
		Scopes:   []string{"read", "write"},
		Email:    "user@example.com",
	}

	// Add claims to context
	ctx = WithTokenClaims(ctx, claims)

	// Verify claims can be retrieved
	retrievedClaims, ok := TokenClaimsFromContext(ctx)
	if !ok {
		t.Fatal("expected claims to be present in context")
	}

	if retrievedClaims.Subject != claims.Subject {
		t.Errorf("expected subject %s, got %s", claims.Subject, retrievedClaims.Subject)
	}
	if retrievedClaims.Issuer != claims.Issuer {
		t.Errorf("expected issuer %s, got %s", claims.Issuer, retrievedClaims.Issuer)
	}
	if retrievedClaims.Email != claims.Email {
		t.Errorf("expected email %s, got %s", claims.Email, retrievedClaims.Email)
	}
	if len(retrievedClaims.Scopes) != len(claims.Scopes) {
		t.Errorf("expected %d scopes, got %d", len(claims.Scopes), len(retrievedClaims.Scopes))
	}
}

func TestTokenClaimsFromContext_NotPresent(t *testing.T) {
	ctx := context.Background()

	// Try to retrieve claims from empty context
	claims, ok := TokenClaimsFromContext(ctx)
	if ok {
		t.Error("expected ok to be false when claims are not present")
	}
	if claims != nil {
		t.Error("expected claims to be nil when not present")
	}
}

func TestTokenClaimsFromContext_WrongType(t *testing.T) {
	ctx := context.Background()

	// Add a value of wrong type to context
	ctx = context.WithValue(ctx, tokenClaimsKey, "not a TokenClaims")

	// Try to retrieve claims
	claims, ok := TokenClaimsFromContext(ctx)
	if ok {
		t.Error("expected ok to be false when value is wrong type")
	}
	if claims != nil {
		t.Error("expected claims to be nil when value is wrong type")
	}
}

func TestMustTokenClaimsFromContext(t *testing.T) {
	ctx := context.Background()
	claims := &TokenClaims{
		Subject: "user123",
		Issuer:  "https://auth.example.com",
	}

	// Add claims to context
	ctx = WithTokenClaims(ctx, claims)

	// Retrieve claims using Must variant
	retrievedClaims := MustTokenClaimsFromContext(ctx)
	if retrievedClaims.Subject != claims.Subject {
		t.Errorf("expected subject %s, got %s", claims.Subject, retrievedClaims.Subject)
	}
}

func TestMustTokenClaimsFromContext_Panic(t *testing.T) {
	ctx := context.Background()

	// Try to retrieve claims from empty context - should panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected MustTokenClaimsFromContext to panic when claims are not present")
		}
	}()

	MustTokenClaimsFromContext(ctx)
}

func TestContextKeyIsolation(t *testing.T) {
	// Ensure our context key doesn't collide with other values
	ctx := context.Background()

	// Add a value with a string key that looks similar
	type fakeKey string
	ctx = context.WithValue(ctx, fakeKey("httpserver.token_claims"), "fake value")

	// Add real claims
	claims := &TokenClaims{Subject: "user123"}
	ctx = WithTokenClaims(ctx, claims)

	// Verify we get the real claims, not the fake value
	retrievedClaims, ok := TokenClaimsFromContext(ctx)
	if !ok {
		t.Fatal("expected claims to be present")
	}
	if retrievedClaims.Subject != "user123" {
		t.Error("context key collision detected")
	}
}
