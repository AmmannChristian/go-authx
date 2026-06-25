package keys

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ZitadelKeyEnvelope is the JSON structure of a ZITADEL key file.
// application:    {"type":"application","keyId":"...","key":"...","clientId":"...","appId":"..."}
// serviceaccount: {"type":"serviceaccount","keyId":"...","key":"...","userId":"..."}
type ZitadelKeyEnvelope struct {
	Type     string `json:"type"`
	KeyID    string `json:"keyId"`
	Key      string `json:"key"`
	ClientID string `json:"clientId"` // application keys
	UserID   string `json:"userId"`   // serviceaccount keys
	AppID    string `json:"appId"`
}

// ParseZitadelKeyEnvelope parses a ZITADEL service-account key JSON and returns
// the envelope metadata and the parsed private key.
func ParseZitadelKeyEnvelope(rawJSON string) (ZitadelKeyEnvelope, any, error) {
	var envelope ZitadelKeyEnvelope
	if err := json.Unmarshal([]byte(rawJSON), &envelope); err != nil {
		return ZitadelKeyEnvelope{}, nil, fmt.Errorf("keys: invalid Zitadel key JSON: %w", err)
	}

	privateKeyPEM := strings.TrimSpace(envelope.Key)
	if privateKeyPEM == "" {
		return ZitadelKeyEnvelope{}, nil, errors.New("keys: invalid Zitadel key JSON: key is required")
	}

	privateKey, err := parsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return ZitadelKeyEnvelope{}, nil, err
	}

	envelope.KeyID = strings.TrimSpace(envelope.KeyID)
	envelope.ClientID = strings.TrimSpace(envelope.ClientID)
	envelope.UserID = strings.TrimSpace(envelope.UserID)
	envelope.AppID = strings.TrimSpace(envelope.AppID)

	return envelope, privateKey, nil
}

func parsePrivateKeyPEM(rawPEM string) (any, error) {
	block, _ := pem.Decode([]byte(rawPEM))
	if block == nil {
		return nil, errors.New("keys: invalid private key: expected PEM")
	}

	parsedPKCS8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if pkcs8Err == nil {
		switch key := parsedPKCS8Key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("keys: unsupported private key type %T", parsedPKCS8Key)
		}
	}

	if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes); rsaErr == nil {
		return rsaKey, nil
	}

	if ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
		return ecKey, nil
	}

	return nil, fmt.Errorf("keys: invalid private key: %w", pkcs8Err)
}
