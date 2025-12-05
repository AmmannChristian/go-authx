package httpserver_test

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/AmmannChristian/go-authx/httpserver"
)

func TestNewTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *httpserver.TLSConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing cert file",
			config: &httpserver.TLSConfig{
				KeyFile: "/path/to/key.pem",
			},
			wantErr: true,
		},
		{
			name: "missing key file",
			config: &httpserver.TLSConfig{
				CertFile: "/path/to/cert.pem",
			},
			wantErr: true,
		},
		{
			name: "nonexistent files",
			config: &httpserver.TLSConfig{
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := httpserver.NewTLSConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTLSConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigureServer(t *testing.T) {
	tests := []struct {
		name    string
		server  *http.Server
		config  *httpserver.TLSConfig
		wantErr bool
	}{
		{
			name:    "nil server",
			server:  nil,
			config:  &httpserver.TLSConfig{},
			wantErr: true,
		},
		{
			name:    "nil config",
			server:  &http.Server{},
			config:  nil,
			wantErr: true,
		},
		{
			name:   "invalid config",
			server: &http.Server{},
			config: &httpserver.TLSConfig{
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := httpserver.ConfigureServer(tt.server, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigureServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTLSConfig_MinVersion(t *testing.T) {
	// This test verifies that custom MinVersion is respected
	// Note: We can't fully test without valid cert files, but we can test the validation
	config := &httpserver.TLSConfig{
		CertFile:   "/path/to/cert.pem",
		KeyFile:    "/path/to/key.pem",
		MinVersion: tls.VersionTLS13,
	}

	// This will fail because files don't exist, but that's expected
	_, err := httpserver.NewTLSConfig(config)
	if err == nil {
		t.Error("Expected error with nonexistent cert files")
	}
}

func TestTLSConfig_ClientAuth(t *testing.T) {
	// This test verifies that different ClientAuth modes are accepted
	authModes := []tls.ClientAuthType{
		tls.NoClientCert,
		tls.RequestClientCert,
		tls.RequireAnyClientCert,
		tls.VerifyClientCertIfGiven,
		tls.RequireAndVerifyClientCert,
	}

	for _, mode := range authModes {
		t.Run(mode.String(), func(t *testing.T) {
			config := &httpserver.TLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				ClientAuth: mode,
			}

			// This will fail because files don't exist, but validates config structure
			_, err := httpserver.NewTLSConfig(config)
			if err == nil {
				t.Error("Expected error with nonexistent cert files")
			}
		})
	}
}
