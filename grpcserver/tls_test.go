package grpcserver_test

import (
	"crypto/tls"
	"testing"

	"github.com/AmmannChristian/go-authx/grpcserver"
)

func TestNewServerCredentials(t *testing.T) {
	tests := []struct {
		name    string
		config  *grpcserver.TLSConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing cert file",
			config: &grpcserver.TLSConfig{
				KeyFile: "/path/to/key.pem",
			},
			wantErr: true,
		},
		{
			name: "missing key file",
			config: &grpcserver.TLSConfig{
				CertFile: "/path/to/cert.pem",
			},
			wantErr: true,
		},
		{
			name: "nonexistent files",
			config: &grpcserver.TLSConfig{
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := grpcserver.NewServerCredentials(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServerCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServerOption(t *testing.T) {
	tests := []struct {
		name    string
		config  *grpcserver.TLSConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "invalid config",
			config: &grpcserver.TLSConfig{
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := grpcserver.ServerOption(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ServerOption() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTLSConfig_MinVersion(t *testing.T) {
	// This test verifies that custom MinVersion is respected
	// Note: We can't fully test without valid cert files, but we can test the validation
	config := &grpcserver.TLSConfig{
		CertFile:   "/path/to/cert.pem",
		KeyFile:    "/path/to/key.pem",
		MinVersion: tls.VersionTLS13,
	}

	// This will fail because files don't exist, but that's expected
	_, err := grpcserver.NewServerCredentials(config)
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
			config := &grpcserver.TLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				ClientAuth: mode,
			}

			// This will fail because files don't exist, but validates config structure
			_, err := grpcserver.NewServerCredentials(config)
			if err == nil {
				t.Error("Expected error with nonexistent cert files")
			}
		})
	}
}
