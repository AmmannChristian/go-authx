package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func TestParseZitadelKeyEnvelope_PKCS1RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	payload := map[string]string{
		"type":     "application",
		"keyId":    "test-key-id",
		"key":      string(keyPEM),
		"clientId": "test-client-id",
		"appId":    "test-app-id",
	}
	rawJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	envelope, parsedKey, err := ParseZitadelKeyEnvelope(string(rawJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if envelope.KeyID != "test-key-id" {
		t.Errorf("expected KeyID %q, got %q", "test-key-id", envelope.KeyID)
	}
	if envelope.ClientID != "test-client-id" {
		t.Errorf("expected ClientID %q, got %q", "test-client-id", envelope.ClientID)
	}
	if envelope.AppID != "test-app-id" {
		t.Errorf("expected AppID %q, got %q", "test-app-id", envelope.AppID)
	}

	parsedRSA, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsedKey)
	}
	if parsedRSA.N.Cmp(privateKey.N) != 0 {
		t.Fatal("parsed RSA key does not match original")
	}
}

func TestParseZitadelKeyEnvelope_PKCS8RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8 key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	payload := map[string]string{
		"keyId":    "k1",
		"key":      string(keyPEM),
		"clientId": "c1",
	}
	rawJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	_, parsedKey, err := ParseZitadelKeyEnvelope(string(rawJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := parsedKey.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsedKey)
	}
}

func TestParseZitadelKeyEnvelope_InvalidJSON(t *testing.T) {
	_, _, err := ParseZitadelKeyEnvelope(`{invalid}`)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseZitadelKeyEnvelope_EmptyKey(t *testing.T) {
	_, _, err := ParseZitadelKeyEnvelope(`{"keyId":"k1","key":"","clientId":"c1"}`)
	if err == nil {
		t.Fatal("expected error for empty key field")
	}
}

func TestParseZitadelKeyEnvelope_WhitespaceTrimmingOnFields(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	payload := map[string]string{
		"keyId":    "  spaced-key-id  ",
		"key":      string(keyPEM),
		"clientId": " spaced-client-id ",
	}
	rawJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	envelope, _, err := ParseZitadelKeyEnvelope(string(rawJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if envelope.KeyID != "spaced-key-id" {
		t.Errorf("expected trimmed KeyID, got %q", envelope.KeyID)
	}
	if envelope.ClientID != "spaced-client-id" {
		t.Errorf("expected trimmed ClientID, got %q", envelope.ClientID)
	}
}
