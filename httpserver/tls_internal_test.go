package httpserver

import (
	"strings"
	"testing"
)

func TestReadTLSFile_EmptyPath_Httpserver(t *testing.T) {
	_, err := readTLSFile("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "empty TLS file path") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadCertificate_EmptyPaths_Httpserver(t *testing.T) {
	if _, err := loadCertificate("", "key.pem"); err == nil {
		t.Fatal("expected error for empty cert path")
	}
}

func TestLoadCACertificate_EmptyPath_Httpserver(t *testing.T) {
	if _, err := loadCACertificate(""); err == nil {
		t.Fatal("expected error for empty CA path")
	}
}
