package httpclient

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AmmannChristian/go-authx/oauth2client"
	"github.com/AmmannChristian/go-authx/testutil"
)

func newMockOAuth2ServerForBuilder(tb testing.TB) *testutil.MockOAuth2Server {
	tb.Helper()

	return testutil.NewMockOAuth2Server(tb, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/token" {
			tb.Fatalf("unexpected token path: %s", req.URL.Path)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{
			"access_token": "mock-token",
			"token_type": "Bearer",
			"expires_in": 3600
		}`)),
			Request: req,
		}, nil
	})
}

func TestNewBuilder(t *testing.T) {
	builder := NewBuilder()

	if builder == nil {
		t.Fatal("builder should not be nil")
	}

	if builder.timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", builder.timeout)
	}

	if !builder.followRedirects {
		t.Error("redirects should be enabled by default")
	}
}

func TestBuilder_WithTokenManager(t *testing.T) {
	authServer := newMockOAuth2ServerForBuilder(t)
	defer authServer.Close()

	ctx := authServer.Ctx
	tm := oauth2client.NewTokenManager(ctx, authServer.URL+"/token", "client", "secret", "openid")

	builder := NewBuilder().WithTokenManager(tm)

	if builder.tokenManager != tm {
		t.Error("TokenManager not set correctly")
	}
}

func TestBuilder_WithOAuth2(t *testing.T) {
	ctx := context.Background()

	builder := NewBuilder().
		WithOAuth2(ctx, "https://auth.example.com/token", "client-id", "secret", "openid profile")

	if builder.tokenManager == nil {
		t.Fatal("TokenManager should not be nil")
	}
}

func TestBuilder_WithTLS(t *testing.T) {
	builder := NewBuilder().
		WithTLS("/path/to/ca.crt", "/path/to/cert.crt", "/path/to/key.pem")

	if !builder.tlsEnabled {
		t.Error("TLS should be enabled")
	}

	if builder.tlsCAFile != "/path/to/ca.crt" {
		t.Errorf("unexpected CA file: %s", builder.tlsCAFile)
	}

	if builder.tlsCertFile != "/path/to/cert.crt" {
		t.Errorf("unexpected cert file: %s", builder.tlsCertFile)
	}

	if builder.tlsKeyFile != "/path/to/key.pem" {
		t.Errorf("unexpected key file: %s", builder.tlsKeyFile)
	}
}

func TestBuilder_WithInsecureSkipVerify(t *testing.T) {
	builder := NewBuilder().WithInsecureSkipVerify()

	if !builder.tlsSkipVerify {
		t.Error("InsecureSkipVerify should be enabled")
	}
}

func TestBuilder_WithTimeout(t *testing.T) {
	timeout := 45 * time.Second
	builder := NewBuilder().WithTimeout(timeout)

	if builder.timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, builder.timeout)
	}
}

func TestBuilder_WithBaseTransport(t *testing.T) {
	customTransport := &http.Transport{}
	builder := NewBuilder().WithBaseTransport(customTransport)

	if builder.baseTransport != customTransport {
		t.Error("base transport not set correctly")
	}
}

func TestBuilder_WithoutRedirects(t *testing.T) {
	builder := NewBuilder().WithoutRedirects()

	if builder.followRedirects {
		t.Error("redirects should be disabled")
	}
}

func TestBuilder_Build_Simple(t *testing.T) {
	builder := NewBuilder()

	client, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if client == nil {
		t.Fatal("client should not be nil")
	}

	if client.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", client.Timeout)
	}
}

func TestBuilder_Build_WithOAuth2(t *testing.T) {
	authServer := newMockOAuth2ServerForBuilder(t)
	defer authServer.Close()

	ctx := authServer.Ctx
	builder := NewBuilder().
		WithOAuth2(ctx, authServer.URL+"/token", "client", "secret", "openid")

	client, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if client == nil {
		t.Fatal("client should not be nil")
	}

	// Verify transport is OAuth2Transport
	_, ok := client.Transport.(*OAuth2Transport)
	if !ok {
		t.Error("transport should be OAuth2Transport")
	}
}

func TestBuilder_Build_WithTimeout(t *testing.T) {
	timeout := 60 * time.Second
	builder := NewBuilder().WithTimeout(timeout)

	client, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if client.Timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, client.Timeout)
	}
}

func TestBuilder_Build_WithoutRedirects(t *testing.T) {
	builder := NewBuilder().WithoutRedirects()

	client, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if client.CheckRedirect == nil {
		t.Error("CheckRedirect should be set")
	}

	// Test that redirects are disabled
	err = client.CheckRedirect(nil, nil)
	if err != http.ErrUseLastResponse {
		t.Errorf("expected ErrUseLastResponse, got %v", err)
	}
}

func TestBuilder_Build_WithBaseTransport(t *testing.T) {
	customTransport := &http.Transport{}
	builder := NewBuilder().WithBaseTransport(customTransport)

	client, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if client.Transport != customTransport {
		t.Error("client should use custom transport when no OAuth2")
	}
}

func TestBuilder_Build_WithBaseTransport_AndOAuth2(t *testing.T) {
	authServer := newMockOAuth2ServerForBuilder(t)
	defer authServer.Close()

	ctx := authServer.Ctx
	customTransport := &http.Transport{}

	builder := NewBuilder().
		WithBaseTransport(customTransport).
		WithOAuth2(ctx, authServer.URL+"/token", "client", "secret", "openid")

	client, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Should wrap custom transport with OAuth2Transport
	oauth2Transport, ok := client.Transport.(*OAuth2Transport)
	if !ok {
		t.Fatal("transport should be OAuth2Transport")
	}

	if oauth2Transport.Base != customTransport {
		t.Error("OAuth2Transport should wrap custom transport")
	}
}

func TestBuilder_BuildTLSConfig_Simple(t *testing.T) {
	builder := NewBuilder()
	builder.tlsEnabled = true

	tlsConfig, err := builder.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2, got %d", tlsConfig.MinVersion)
	}
}

func TestBuilder_BuildTLSConfig_WithInsecureSkipVerify(t *testing.T) {
	builder := NewBuilder()
	builder.tlsSkipVerify = true

	tlsConfig, err := builder.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}

	if !tlsConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestBuilder_BuildTLSConfig_WithCAFile(t *testing.T) {
	// Create temporary CA file
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")

	testutil.WriteTestCACert(t, caFile)

	builder := NewBuilder()
	builder.tlsEnabled = true
	builder.tlsCAFile = caFile

	tlsConfig, err := builder.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}

	if tlsConfig.RootCAs == nil {
		t.Error("RootCAs should not be nil")
	}
}

func TestBuilder_BuildTLSConfig_InvalidCAFile(t *testing.T) {
	builder := NewBuilder()
	builder.tlsEnabled = true
	builder.tlsCAFile = "/nonexistent/ca.crt"

	_, err := builder.buildTLSConfig()
	if err == nil {
		t.Error("expected error for invalid CA file")
	}
}

func TestBuilder_BuildTLSConfig_InvalidCAContent(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")

	if err := os.WriteFile(caFile, []byte("invalid cert content"), 0o600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	builder := NewBuilder()
	builder.tlsEnabled = true
	builder.tlsCAFile = caFile

	_, err := builder.buildTLSConfig()
	if err == nil {
		t.Error("expected error for invalid CA content")
	}
}

func TestBuilder_BuildTLSConfig_OnlyCert(t *testing.T) {
	builder := NewBuilder()
	builder.tlsEnabled = true
	builder.tlsCertFile = "/path/to/cert.crt"

	_, err := builder.buildTLSConfig()
	if err == nil {
		t.Error("expected error for cert without key")
	}
}

func TestBuilder_BuildTLSConfig_OnlyKey(t *testing.T) {
	builder := NewBuilder()
	builder.tlsEnabled = true
	builder.tlsKeyFile = "/path/to/key.pem"

	_, err := builder.buildTLSConfig()
	if err == nil {
		t.Error("expected error for key without cert")
	}
}

func TestBuilder_Build_WithTLS_UsesConfig(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	testutil.WriteTestCACert(t, caFile)

	client, err := NewBuilder().WithTLS(caFile, "", "").Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig should be set")
	}

	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("RootCAs should be configured from CA file")
	}
}

func TestBuilder_Build_WithMutualTLS_LoadsCertificates(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	certFile := filepath.Join(tmpDir, "client.crt")
	keyFile := filepath.Join(tmpDir, "client.key")

	testutil.WriteTestCACert(t, caFile)
	testutil.WriteTestCertAndKey(t, certFile, keyFile)

	client, err := NewBuilder().WithTLS(caFile, certFile, keyFile).Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}

	if len(transport.TLSClientConfig.Certificates) == 0 {
		t.Fatal("expected client certificates to be loaded")
	}
}

func TestBuilder_Build_WithMutualTLS_InvalidCert(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "client.crt")
	keyFile := filepath.Join(tmpDir, "client.key")

	if err := os.WriteFile(certFile, []byte("bad cert"), 0o600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("bad key"), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	_, err := NewBuilder().WithTLS("", certFile, keyFile).Build()
	if err == nil {
		t.Fatal("expected error for invalid cert/key")
	}

	if !strings.Contains(err.Error(), "load client certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuilder_Build_WithInsecureSkipVerifyOnly(t *testing.T) {
	client, err := NewBuilder().WithInsecureSkipVerify().Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}

	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to be true")
	}
}

func TestBuilder_Build_FallbackDefaultTransportWithTLS(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	testutil.WriteTestCACert(t, caFile)

	origDefault := http.DefaultTransport
	http.DefaultTransport = testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = origDefault })

	client, err := NewBuilder().WithTLS(caFile, "", "").Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	resp, err := client.Get("https://example.com")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
}

func TestBuilder_Build_WithTLS_InvalidCertPair(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "client.crt")
	keyFile := filepath.Join(tmpDir, "client.key")

	if err := os.WriteFile(certFile, []byte("bad cert"), 0o600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	testutil.WriteTestCACert(t, keyFile) // write non-key content to trigger load error

	_, err := NewBuilder().WithTLS("", certFile, keyFile).Build()
	if err == nil {
		t.Fatal("expected error for invalid cert/key pair")
	}

	if !strings.Contains(err.Error(), "load client certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuilder_Build_Integration(t *testing.T) {
	authServer := newMockOAuth2ServerForBuilder(t)
	defer authServer.Close()

	ctx := authServer.Ctx
	baseTransport := testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("missing auth")),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("success")),
			Request:    req,
		}, nil
	})

	client, err := NewBuilder().
		WithOAuth2(ctx, authServer.URL+"/token", "client", "secret", "openid").
		WithBaseTransport(baseTransport).
		WithTimeout(10 * time.Second).
		Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	resp, err := client.Get("https://api.example.com")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

// Benchmark tests
func BenchmarkBuilder_Build(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := NewBuilder().Build()
		if err != nil {
			b.Fatalf("Build failed: %v", err)
		}
		_ = client
	}
}

func BenchmarkBuilder_Build_WithOAuth2(b *testing.B) {
	authServer := newMockOAuth2ServerForBuilder(b)
	defer authServer.Close()

	ctx := authServer.Ctx

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := NewBuilder().
			WithOAuth2(ctx, authServer.URL+"/token", "client", "secret", "openid").
			Build()
		if err != nil {
			b.Fatalf("Build failed: %v", err)
		}
		_ = client
	}
}
