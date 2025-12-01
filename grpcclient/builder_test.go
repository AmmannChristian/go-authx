package grpcclient

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AmmannChristian/go-authx/internal/testutil"
	"google.golang.org/grpc"
)

// Mock OAuth2 server
func newMockOAuth2Server(tb testing.TB) *testutil.MockOAuth2Server {
	tb.Helper()

	return testutil.NewMockOAuth2Server(tb, nil)
}

func TestNewBuilder(t *testing.T) {
	builder := NewBuilder()

	if builder == nil {
		t.Fatal("builder should not be nil")
	}
}

func TestBuilder_WithAddress(t *testing.T) {
	builder := NewBuilder().WithAddress("localhost:9090")

	if builder.address != "localhost:9090" {
		t.Errorf("expected address 'localhost:9090', got '%s'", builder.address)
	}
}

func TestBuilder_WithOAuth2(t *testing.T) {
	builder := NewBuilder().
		WithOAuth2("https://auth.example.com/token", "client-id", "secret", "openid")

	if !builder.oauth2Enabled {
		t.Error("OAuth2 should be enabled")
	}

	if builder.oauth2TokenURL != "https://auth.example.com/token" {
		t.Errorf("unexpected token URL: %s", builder.oauth2TokenURL)
	}

	if builder.oauth2ClientID != "client-id" {
		t.Errorf("unexpected client ID: %s", builder.oauth2ClientID)
	}
}

func TestBuilder_WithTLS(t *testing.T) {
	builder := NewBuilder().
		WithTLS("/path/to/ca.crt", "/path/to/cert.crt", "/path/to/key.pem", "server.example.com")

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

	if builder.tlsServerName != "server.example.com" {
		t.Errorf("unexpected server name: %s", builder.tlsServerName)
	}
}

func TestBuilder_WithDialOptions(t *testing.T) {
	opt1 := grpc.WithDisableRetry()
	opt2 := grpc.WithDisableHealthCheck()

	builder := NewBuilder().WithDialOptions(opt1, opt2)

	if len(builder.dialOpts) != 2 {
		t.Errorf("expected 2 dial options, got %d", len(builder.dialOpts))
	}
}

func TestBuilder_Build_NoAddress(t *testing.T) {
	ctx := context.Background()
	builder := NewBuilder()

	_, err := builder.Build(ctx)
	if err == nil {
		t.Error("expected error when building without address")
	}

	if err.Error() != "grpcclient: server address is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBuilder_Build_WithAddress(t *testing.T) {
	ctx := context.Background()
	builder := NewBuilder().WithAddress("localhost:9090")

	conn, err := builder.Build(ctx)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	defer conn.Close()

	if conn == nil {
		t.Fatal("connection should not be nil")
	}
}

func TestBuilder_Build_WithOAuth2(t *testing.T) {
	server := newMockOAuth2Server(t)
	defer server.Close()

	ctx := server.Ctx
	builder := NewBuilder().
		WithAddress("localhost:9090").
		WithOAuth2(server.URL+"/token", "client-id", "secret", "openid")

	conn, err := builder.Build(ctx)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	defer conn.Close()

	if conn == nil {
		t.Fatal("connection should not be nil")
	}
}

func TestBuilder_ValidateOAuth2Config_MissingTokenURL(t *testing.T) {
	builder := NewBuilder()
	builder.oauth2Enabled = true
	builder.oauth2ClientID = "client-id"
	builder.oauth2ClientSecret = "secret"

	err := builder.validateOAuth2Config()
	if err == nil {
		t.Error("expected error for missing token URL")
	}
}

func TestBuilder_ValidateOAuth2Config_MissingClientID(t *testing.T) {
	builder := NewBuilder()
	builder.oauth2Enabled = true
	builder.oauth2TokenURL = "https://auth.example.com/token"
	builder.oauth2ClientSecret = "secret"

	err := builder.validateOAuth2Config()
	if err == nil {
		t.Error("expected error for missing client ID")
	}
}

func TestBuilder_ValidateOAuth2Config_MissingClientSecret(t *testing.T) {
	builder := NewBuilder()
	builder.oauth2Enabled = true
	builder.oauth2TokenURL = "https://auth.example.com/token"
	builder.oauth2ClientID = "client-id"

	err := builder.validateOAuth2Config()
	if err == nil {
		t.Error("expected error for missing client secret")
	}
}

func TestBuilder_ValidateOAuth2Config_Complete(t *testing.T) {
	builder := NewBuilder()
	builder.oauth2Enabled = true
	builder.oauth2TokenURL = "https://auth.example.com/token"
	builder.oauth2ClientID = "client-id"
	builder.oauth2ClientSecret = "secret"

	err := builder.validateOAuth2Config()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
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

func TestBuilder_BuildTLSConfig_InvalidCertPair(t *testing.T) {
	builder := NewBuilder()
	builder.tlsEnabled = true
	builder.tlsCertFile = "/nonexistent/cert.crt"
	builder.tlsKeyFile = "/nonexistent/key.pem"

	_, err := builder.buildTLSConfig()
	if err == nil {
		t.Error("expected error for invalid cert pair")
	}
}

func TestBuilder_BuildTLSConfig_OnlyCert(t *testing.T) {
	builder := NewBuilder()
	builder.tlsEnabled = true
	builder.tlsCertFile = "/path/to/cert.crt"
	// Missing key file

	_, err := builder.buildTLSConfig()
	if err == nil {
		t.Error("expected error for cert without key")
	}
}

func TestBuilder_BuildTLSConfig_OnlyKey(t *testing.T) {
	builder := NewBuilder()
	builder.tlsEnabled = true
	builder.tlsKeyFile = "/path/to/key.pem"
	// Missing cert file

	_, err := builder.buildTLSConfig()
	if err == nil {
		t.Error("expected error for key without cert")
	}
}

func TestBuilder_BuildTLSConfig_WithServerName(t *testing.T) {
	builder := NewBuilder()
	builder.tlsEnabled = true
	builder.tlsServerName = "server.example.com"

	tlsConfig, err := builder.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}

	if tlsConfig.ServerName != "server.example.com" {
		t.Errorf("expected ServerName 'server.example.com', got '%s'", tlsConfig.ServerName)
	}
}

func TestBuilder_BuildTLSConfig_MinVersion(t *testing.T) {
	builder := NewBuilder()
	builder.tlsEnabled = true

	tlsConfig, err := builder.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}

	// MinVersion should be TLS 1.2 (0x0303)
	expectedMinVersion := uint16(0x0303)
	if tlsConfig.MinVersion != expectedMinVersion {
		t.Errorf("expected MinVersion %d, got %d", expectedMinVersion, tlsConfig.MinVersion)
	}
}

func TestBuilder_BuildTLSConfig_ValidCAFile(t *testing.T) {
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

func TestBuilder_BuildTLSConfig_InvalidCAContent(t *testing.T) {
	// Create temporary file with invalid content
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")

	if err := os.WriteFile(caFile, []byte("not a valid certificate"), 0o600); err != nil {
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

func TestBuilder_Build_WithOAuth2ValidationError(t *testing.T) {
	builder := NewBuilder().
		WithAddress("localhost:9090").
		WithOAuth2("", "client-id", "secret", "openid")

	_, err := builder.Build(context.Background())
	if err == nil {
		t.Fatal("expected validation error")
	}

	if !strings.Contains(err.Error(), "OAuth2 token URL is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuilder_BuildTLSConfig_WithClientCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	certFile := filepath.Join(tmpDir, "client.crt")
	keyFile := filepath.Join(tmpDir, "client.key")

	testutil.WriteTestCACert(t, caFile)
	testutil.WriteTestCertAndKey(t, certFile, keyFile)

	builder := NewBuilder()
	builder.tlsEnabled = true
	builder.tlsCAFile = caFile
	builder.tlsCertFile = certFile
	builder.tlsKeyFile = keyFile
	builder.tlsServerName = "server.example.com"

	tlsConfig, err := builder.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}

	if tlsConfig.RootCAs == nil {
		t.Fatal("RootCAs should be set")
	}

	if len(tlsConfig.Certificates) == 0 {
		t.Fatal("expected client certificate to be loaded")
	}

	if tlsConfig.ServerName != "server.example.com" {
		t.Fatalf("expected ServerName to be set, got %q", tlsConfig.ServerName)
	}
}

func TestBuilder_Build_WithTLS_UsesCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	testutil.WriteTestCACert(t, caFile)

	builder := NewBuilder().
		WithAddress("localhost:9090").
		WithTLS(caFile, "", "", "localhost").
		WithDialOptions(grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go serverConn.Close()
			return clientConn, nil
		}))

	conn, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	defer conn.Close()
}

// Benchmark tests
func BenchmarkBuilder_Build(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := NewBuilder().
			WithAddress("localhost:9090").
			Build(ctx)
		if err != nil {
			b.Fatalf("Build failed: %v", err)
		}
		conn.Close()
	}
}

func BenchmarkBuilder_Build_WithOAuth2(b *testing.B) {
	server := newMockOAuth2Server(b)
	defer server.Close()

	ctx := server.Ctx

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := NewBuilder().
			WithAddress("localhost:9090").
			WithOAuth2(server.URL+"/token", "client", "secret", "openid").
			Build(ctx)
		if err != nil {
			b.Fatalf("Build failed: %v", err)
		}
		conn.Close()
	}
}
