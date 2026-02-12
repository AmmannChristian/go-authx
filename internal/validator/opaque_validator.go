package validator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	introspectionTokenTypeHintAccessToken = "access_token"
	// #nosec G101 -- OAuth2/RFC7523 assertion-type URI constant, not a credential.
	introspectionClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	privateKeyJWTAssertionLifetime            = time.Minute
)

// IntrospectionClientAuthMethod defines the OAuth2 client authentication method
// used when calling the introspection endpoint.
type IntrospectionClientAuthMethod string

const (
	// IntrospectionClientAuthMethodClientSecretBasic uses RFC 6749 client_secret_basic authentication.
	IntrospectionClientAuthMethodClientSecretBasic IntrospectionClientAuthMethod = "client_secret_basic"
	// IntrospectionClientAuthMethodPrivateKeyJWT uses RFC 7523 private_key_jwt authentication.
	IntrospectionClientAuthMethodPrivateKeyJWT IntrospectionClientAuthMethod = "private_key_jwt"
)

const (
	// IntrospectionPrivateKeyJWTAlgorithmRS256 signs private_key_jwt assertions using RSASSA-PKCS1-v1_5 + SHA-256.
	IntrospectionPrivateKeyJWTAlgorithmRS256 = "RS256"
	// IntrospectionPrivateKeyJWTAlgorithmES256 signs private_key_jwt assertions using ECDSA P-256 + SHA-256.
	IntrospectionPrivateKeyJWTAlgorithmES256 = "ES256"
)

// IntrospectionClientAuthConfig configures client authentication for the
// introspection request.
type IntrospectionClientAuthConfig struct {
	Method   IntrospectionClientAuthMethod
	ClientID string
	// #nosec G117 -- Public API field name is intentional for OAuth client_secret config.
	ClientSecret string
	// #nosec G117 -- Public API field name is intentional for private_key_jwt config.
	PrivateKey             string
	PrivateKeyJWTKeyID     string
	PrivateKeyJWTAlgorithm string
}

// OpaqueTokenValidator validates OAuth2 opaque tokens via RFC 7662 token introspection.
type OpaqueTokenValidator struct {
	introspectionURL string
	issuer           string
	audience         string
	authConfig       IntrospectionClientAuthConfig
	privateKey       any
	httpClient       *http.Client
	logger           Logger
}

// NewOpaqueTokenValidator creates a validator that uses token introspection for opaque tokens.
//
// Parameters:
//   - introspectionURL: OAuth2 introspection endpoint URL
//   - issuer: Expected token issuer (iss claim when provided by introspection)
//   - audience: Expected token audience (aud claim when provided by introspection)
//   - clientID: OAuth2 client ID for introspection endpoint authentication
//   - clientSecret: OAuth2 client secret for introspection endpoint authentication
//   - httpClient: HTTP client for introspection requests (optional, uses http.DefaultClient if nil)
//   - logger: Optional logger for debugging (can be nil)
func NewOpaqueTokenValidator(
	introspectionURL,
	issuer,
	audience,
	clientID,
	clientSecret string,
	httpClient *http.Client,
	logger Logger,
) (*OpaqueTokenValidator, error) {
	return NewOpaqueTokenValidatorWithAuth(
		introspectionURL,
		issuer,
		audience,
		IntrospectionClientAuthConfig{
			Method:       IntrospectionClientAuthMethodClientSecretBasic,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
		httpClient,
		logger,
	)
}

// NewOpaqueTokenValidatorWithAuth creates a validator that uses token introspection for
// opaque tokens and supports multiple OAuth2 client authentication methods for the
// introspection call.
func NewOpaqueTokenValidatorWithAuth(
	introspectionURL,
	issuer,
	audience string,
	authConfig IntrospectionClientAuthConfig,
	httpClient *http.Client,
	logger Logger,
) (*OpaqueTokenValidator, error) {
	if introspectionURL == "" {
		return nil, errors.New("validator: introspection URL is required")
	}
	if issuer == "" {
		return nil, errors.New("validator: issuer is required")
	}
	if audience == "" {
		return nil, errors.New("validator: audience is required")
	}

	normalizedIntrospectionURL, err := normalizeIntrospectionURL(introspectionURL)
	if err != nil {
		return nil, err
	}

	normalizedAuthConfig, privateKey, err := normalizeIntrospectionClientAuthConfig(authConfig)
	if err != nil {
		return nil, err
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &OpaqueTokenValidator{
		introspectionURL: normalizedIntrospectionURL,
		issuer:           issuer,
		audience:         audience,
		authConfig:       normalizedAuthConfig,
		privateKey:       privateKey,
		httpClient:       httpClient,
		logger:           logger,
	}, nil
}

// ValidateToken validates an opaque token via introspection and extracts claims.
func (v *OpaqueTokenValidator) ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if strings.TrimSpace(tokenString) == "" {
		return nil, errors.New("validator: token is empty")
	}

	introspectionClaims, err := v.introspect(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	tokenClaims, err := v.validateAndBuildClaims(introspectionClaims)
	if err != nil {
		return nil, err
	}

	if v.logger != nil {
		v.logger.Printf(
			"validator: introspected opaque token for subject %s with scopes %v",
			tokenClaims.Subject,
			tokenClaims.Scopes,
		)
	}

	return tokenClaims, nil
}

func (v *OpaqueTokenValidator) introspect(ctx context.Context, tokenString string) (map[string]interface{}, error) {
	req, err := v.newIntrospectionRequest(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	// #nosec G704 -- URL is normalized and restricted by normalizeIntrospectionURL.
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("validator: introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("validator: failed to read introspection response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("validator: introspection endpoint returned status %d", resp.StatusCode)
	}

	introspectionClaims, err := decodeIntrospectionClaims(body)
	if err != nil {
		return nil, err
	}

	if err := ensureActiveOpaqueToken(introspectionClaims); err != nil {
		return nil, err
	}

	return introspectionClaims, nil
}

func (v *OpaqueTokenValidator) newIntrospectionRequest(ctx context.Context, tokenString string) (*http.Request, error) {
	values := url.Values{}
	values.Set("token", tokenString)
	values.Set("token_type_hint", introspectionTokenTypeHintAccessToken)

	switch v.authConfig.Method {
	case IntrospectionClientAuthMethodClientSecretBasic:
		// Basic auth is set below to keep body handling shared.
	case IntrospectionClientAuthMethodPrivateKeyJWT:
		assertion, err := v.buildPrivateKeyJWTClientAssertion()
		if err != nil {
			return nil, err
		}
		values.Set("client_assertion_type", introspectionClientAssertionTypeJWTBearer)
		values.Set("client_assertion", assertion)
	default:
		return nil, fmt.Errorf("validator: unsupported introspection client auth method %q", v.authConfig.Method)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.introspectionURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("validator: failed to create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if v.authConfig.Method == IntrospectionClientAuthMethodClientSecretBasic {
		req.SetBasicAuth(v.authConfig.ClientID, v.authConfig.ClientSecret)
	}

	return req, nil
}

func (v *OpaqueTokenValidator) buildPrivateKeyJWTClientAssertion() (string, error) {
	jti, err := newIntrospectionJWTID()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(privateKeyJWTAssertionLifetime)
	claims := jwt.RegisteredClaims{
		Issuer:    v.authConfig.ClientID,
		Subject:   v.authConfig.ClientID,
		Audience:  jwt.ClaimStrings{v.introspectionURL},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		ID:        jti,
	}

	signingMethod := jwt.GetSigningMethod(v.authConfig.PrivateKeyJWTAlgorithm)
	if signingMethod == nil {
		return "", fmt.Errorf("validator: unsupported introspection private_key_jwt algorithm %q", v.authConfig.PrivateKeyJWTAlgorithm)
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	if v.authConfig.PrivateKeyJWTKeyID != "" {
		token.Header["kid"] = v.authConfig.PrivateKeyJWTKeyID
	}

	assertion, err := token.SignedString(v.privateKey)
	if err != nil {
		return "", fmt.Errorf("validator: failed to sign introspection client assertion: %w", err)
	}

	return assertion, nil
}

func normalizeIntrospectionClientAuthConfig(authConfig IntrospectionClientAuthConfig) (IntrospectionClientAuthConfig, any, error) {
	normalized := authConfig
	normalized.Method = normalizeIntrospectionClientAuthMethod(normalized.Method)
	normalized.ClientID = strings.TrimSpace(normalized.ClientID)
	normalized.ClientSecret = strings.TrimSpace(normalized.ClientSecret)
	normalized.PrivateKey = strings.TrimSpace(normalized.PrivateKey)
	normalized.PrivateKeyJWTKeyID = strings.TrimSpace(normalized.PrivateKeyJWTKeyID)
	normalized.PrivateKeyJWTAlgorithm = strings.TrimSpace(normalized.PrivateKeyJWTAlgorithm)

	switch normalized.Method {
	case IntrospectionClientAuthMethodClientSecretBasic:
		if normalized.ClientID == "" {
			return IntrospectionClientAuthConfig{}, nil, errors.New("validator: introspection client ID is required")
		}
		if normalized.ClientSecret == "" {
			return IntrospectionClientAuthConfig{}, nil, errors.New("validator: introspection client secret is required")
		}
		return normalized, nil, nil
	case IntrospectionClientAuthMethodPrivateKeyJWT:
		if normalized.PrivateKey == "" {
			return IntrospectionClientAuthConfig{}, nil, errors.New("validator: introspection private key is required")
		}

		privateKey, inferredKeyID, inferredAlgorithm, inferredClientID, err := parseIntrospectionPrivateKey(normalized.PrivateKey)
		if err != nil {
			return IntrospectionClientAuthConfig{}, nil, err
		}

		if normalized.ClientID == "" {
			normalized.ClientID = strings.TrimSpace(inferredClientID)
		}
		if normalized.ClientID == "" {
			return IntrospectionClientAuthConfig{}, nil, errors.New("validator: introspection client ID is required")
		}

		if normalized.PrivateKeyJWTAlgorithm == "" {
			normalized.PrivateKeyJWTAlgorithm = strings.TrimSpace(inferredAlgorithm)
		}
		if normalized.PrivateKeyJWTAlgorithm == "" {
			normalized.PrivateKeyJWTAlgorithm, err = inferPrivateKeyJWTAlgorithm(privateKey)
			if err != nil {
				return IntrospectionClientAuthConfig{}, nil, err
			}
		}

		if err := validatePrivateKeyJWTAlgorithm(normalized.PrivateKeyJWTAlgorithm, privateKey); err != nil {
			return IntrospectionClientAuthConfig{}, nil, err
		}

		if normalized.PrivateKeyJWTKeyID == "" {
			normalized.PrivateKeyJWTKeyID = strings.TrimSpace(inferredKeyID)
		}

		// Keep the parsed key only and avoid retaining the raw private key content.
		normalized.PrivateKey = ""

		return normalized, privateKey, nil
	default:
		return IntrospectionClientAuthConfig{}, nil, fmt.Errorf("validator: unsupported introspection client auth method %q", normalized.Method)
	}
}

func normalizeIntrospectionClientAuthMethod(method IntrospectionClientAuthMethod) IntrospectionClientAuthMethod {
	normalizedMethod := IntrospectionClientAuthMethod(strings.TrimSpace(string(method)))
	if normalizedMethod == "" {
		return IntrospectionClientAuthMethodClientSecretBasic
	}

	return normalizedMethod
}

func inferPrivateKeyJWTAlgorithm(privateKey any) (string, error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return IntrospectionPrivateKeyJWTAlgorithmRS256, nil
	case *ecdsa.PrivateKey:
		return IntrospectionPrivateKeyJWTAlgorithmES256, nil
	default:
		return "", fmt.Errorf("validator: unsupported introspection private key type %T", privateKey)
	}
}

func validatePrivateKeyJWTAlgorithm(algorithm string, privateKey any) error {
	switch algorithm {
	case IntrospectionPrivateKeyJWTAlgorithmRS256:
		if _, ok := privateKey.(*rsa.PrivateKey); !ok {
			return errors.New("validator: private_key_jwt algorithm RS256 requires an RSA private key")
		}
		return nil
	case IntrospectionPrivateKeyJWTAlgorithmES256:
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("validator: private_key_jwt algorithm ES256 requires an EC private key")
		}
		if ecdsaKey.Curve != elliptic.P256() {
			return errors.New("validator: private_key_jwt algorithm ES256 requires an EC P-256 private key")
		}
		return nil
	default:
		return fmt.Errorf("validator: unsupported introspection private_key_jwt algorithm %q", algorithm)
	}
}

func parseIntrospectionPrivateKey(rawPrivateKey string) (any, string, string, string, error) {
	trimmedKey := strings.TrimSpace(rawPrivateKey)
	if trimmedKey == "" {
		return nil, "", "", "", errors.New("validator: introspection private key is required")
	}

	if strings.HasPrefix(trimmedKey, "{") {
		privateKey, keyID, algorithm, clientID, err := parseIntrospectionPrivateKeyJSON(trimmedKey)
		if err != nil {
			return nil, "", "", "", err
		}
		return privateKey, keyID, algorithm, clientID, nil
	}

	privateKey, err := parsePrivateKeyPEM(trimmedKey)
	if err != nil {
		return nil, "", "", "", err
	}

	return privateKey, "", "", "", nil
}

func parseIntrospectionPrivateKeyJSON(rawJSON string) (any, string, string, string, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawJSON), &envelope); err != nil {
		return nil, "", "", "", fmt.Errorf("validator: invalid introspection private key JSON: %w", err)
	}

	if _, isJWK := envelope["kty"]; isJWK {
		privateKey, keyID, algorithm, err := parsePrivateKeyJWK(rawJSON)
		if err != nil {
			return nil, "", "", "", err
		}
		return privateKey, keyID, algorithm, "", nil
	}

	if _, isZitadelKey := envelope["key"]; isZitadelKey {
		privateKey, keyID, clientID, err := parseZitadelPrivateKeyEnvelope(rawJSON)
		if err != nil {
			return nil, "", "", "", err
		}
		return privateKey, keyID, "", clientID, nil
	}

	return nil, "", "", "", errors.New("validator: invalid introspection private key JSON: expected JWK or Zitadel key JSON")
}

type zitadelPrivateKeyEnvelope struct {
	KeyID    string `json:"keyId"`
	Key      string `json:"key"`
	ClientID string `json:"clientId"`
}

func parseZitadelPrivateKeyEnvelope(rawJSON string) (any, string, string, error) {
	var envelope zitadelPrivateKeyEnvelope
	if err := json.Unmarshal([]byte(rawJSON), &envelope); err != nil {
		return nil, "", "", fmt.Errorf("validator: invalid Zitadel key JSON: %w", err)
	}

	privateKeyPEM := strings.TrimSpace(envelope.Key)
	if privateKeyPEM == "" {
		return nil, "", "", errors.New("validator: invalid Zitadel key JSON: key is required")
	}

	privateKey, err := parsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, "", "", err
	}

	return privateKey, strings.TrimSpace(envelope.KeyID), strings.TrimSpace(envelope.ClientID), nil
}

func parsePrivateKeyPEM(rawPEM string) (any, error) {
	pemBytes := []byte(rawPEM)

	rsaKey, rsaErr := jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
	if rsaErr == nil {
		return rsaKey, nil
	}

	ecdsaKey, ecdsaErr := jwt.ParseECPrivateKeyFromPEM(pemBytes)
	if ecdsaErr == nil {
		return ecdsaKey, nil
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("validator: invalid introspection private key: expected PEM or JWK")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("validator: invalid introspection private key: %w", err)
	}

	switch key := parsedKey.(type) {
	case *rsa.PrivateKey:
		return key, nil
	case *ecdsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("validator: unsupported introspection private key type %T", parsedKey)
	}
}

type privateKeyJWK struct {
	KTY string `json:"kty"`
	ALG string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
	P   string `json:"p"`
	Q   string `json:"q"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parsePrivateKeyJWK(rawJWK string) (any, string, string, error) {
	var jwk privateKeyJWK
	if err := json.Unmarshal([]byte(rawJWK), &jwk); err != nil {
		return nil, "", "", fmt.Errorf("validator: invalid introspection private JWK: %w", err)
	}

	switch strings.ToUpper(strings.TrimSpace(jwk.KTY)) {
	case "RSA":
		privateKey, err := parseRSAPrivateKeyJWK(jwk)
		if err != nil {
			return nil, "", "", err
		}
		return privateKey, strings.TrimSpace(jwk.KID), strings.TrimSpace(jwk.ALG), nil
	case "EC":
		privateKey, err := parseECPrivateKeyJWK(jwk)
		if err != nil {
			return nil, "", "", err
		}
		return privateKey, strings.TrimSpace(jwk.KID), strings.TrimSpace(jwk.ALG), nil
	default:
		return nil, "", "", fmt.Errorf("validator: unsupported introspection JWK key type %q", jwk.KTY)
	}
}

func parseRSAPrivateKeyJWK(jwk privateKeyJWK) (*rsa.PrivateKey, error) {
	n, err := decodeJWKBigInt("n", jwk.N)
	if err != nil {
		return nil, err
	}

	eBytes, err := decodeJWKBase64URL("e", jwk.E)
	if err != nil {
		return nil, err
	}
	eBigInt := new(big.Int).SetBytes(eBytes)
	if !eBigInt.IsInt64() {
		return nil, errors.New("validator: invalid e in introspection JWK: exponent is too large")
	}
	e := int(eBigInt.Int64())
	if e < 3 {
		return nil, errors.New("validator: invalid e in introspection JWK: exponent must be >= 3")
	}

	d, err := decodeJWKBigInt("d", jwk.D)
	if err != nil {
		return nil, err
	}

	privateKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: e},
		D:         d,
	}

	if jwk.P == "" || jwk.Q == "" {
		return nil, errors.New("validator: introspection RSA JWK requires p and q")
	}

	p, pErr := decodeJWKBigInt("p", jwk.P)
	if pErr != nil {
		return nil, pErr
	}
	q, qErr := decodeJWKBigInt("q", jwk.Q)
	if qErr != nil {
		return nil, qErr
	}

	privateKey.Primes = []*big.Int{p, q}
	if validateErr := privateKey.Validate(); validateErr != nil {
		return nil, fmt.Errorf("validator: invalid introspection RSA JWK: %w", validateErr)
	}
	privateKey.Precompute()

	return privateKey, nil
}

func parseECPrivateKeyJWK(jwk privateKeyJWK) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(jwk.CRV) != "P-256" {
		return nil, fmt.Errorf("validator: unsupported introspection EC JWK curve %q", jwk.CRV)
	}

	dBytes, err := decodeJWKBase64URL("d", jwk.D)
	if err != nil {
		return nil, err
	}

	curve := elliptic.P256()
	d := new(big.Int).SetBytes(dBytes)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("validator: invalid d in introspection EC JWK")
	}

	x, y := curve.ScalarBaseMult(dBytes)
	if x == nil || y == nil {
		return nil, errors.New("validator: failed to derive public key from introspection EC JWK")
	}

	if jwk.X != "" || jwk.Y != "" {
		if jwk.X == "" || jwk.Y == "" {
			return nil, errors.New("validator: introspection EC JWK requires both x and y when one is provided")
		}

		expectedX, expectedXErr := decodeJWKBigInt("x", jwk.X)
		if expectedXErr != nil {
			return nil, expectedXErr
		}
		expectedY, expectedYErr := decodeJWKBigInt("y", jwk.Y)
		if expectedYErr != nil {
			return nil, expectedYErr
		}

		if x.Cmp(expectedX) != 0 || y.Cmp(expectedY) != 0 {
			return nil, errors.New("validator: introspection EC JWK x/y do not match private key")
		}
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}, nil
}

func decodeJWKBigInt(name, value string) (*big.Int, error) {
	decoded, err := decodeJWKBase64URL(name, value)
	if err != nil {
		return nil, err
	}

	bigInt := new(big.Int).SetBytes(decoded)
	if bigInt.Sign() <= 0 {
		return nil, fmt.Errorf("validator: invalid %s in introspection JWK: value must be > 0", name)
	}

	return bigInt, nil
}

func decodeJWKBase64URL(name, value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("validator: invalid %s in introspection JWK: empty", name)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("validator: invalid %s in introspection JWK: %w", name, err)
	}

	return decoded, nil
}

func newIntrospectionJWTID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("validator: failed to generate introspection client assertion jti: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func decodeIntrospectionClaims(body []byte) (map[string]interface{}, error) {
	var introspectionClaims map[string]interface{}
	if err := json.Unmarshal(body, &introspectionClaims); err != nil {
		return nil, fmt.Errorf("validator: invalid introspection response: %w", err)
	}

	return introspectionClaims, nil
}

func ensureActiveOpaqueToken(introspectionClaims map[string]interface{}) error {
	active, ok := introspectionClaims["active"].(bool)
	if !ok || !active {
		return errors.New("validator: opaque token is inactive")
	}

	return nil
}

func (v *OpaqueTokenValidator) validateAndBuildClaims(introspectionClaims map[string]interface{}) (*TokenClaims, error) {
	issuer, err := v.resolveIssuer(introspectionClaims)
	if err != nil {
		return nil, err
	}

	audience, err := v.resolveAudience(introspectionClaims)
	if err != nil {
		return nil, err
	}

	subject, err := resolveSubject(introspectionClaims)
	if err != nil {
		return nil, err
	}

	expiry, err := resolveExpiry(introspectionClaims)
	if err != nil {
		return nil, err
	}

	issuedAt, err := resolveIssuedAt(introspectionClaims)
	if err != nil {
		return nil, err
	}

	scopes := ExtractScopes(jwt.MapClaims(introspectionClaims))
	email := firstNonEmpty(
		claimString(introspectionClaims, "email"),
		claimString(introspectionClaims, "username"),
	)

	return &TokenClaims{
		Subject:   subject,
		Issuer:    issuer,
		Audience:  audience,
		Expiry:    expiry,
		IssuedAt:  issuedAt,
		Scopes:    scopes,
		Email:     email,
		RawClaims: cloneClaimsMap(introspectionClaims),
	}, nil
}

func (v *OpaqueTokenValidator) resolveIssuer(introspectionClaims map[string]interface{}) (string, error) {
	issuer := v.issuer
	if tokenIssuer := claimString(introspectionClaims, "iss"); tokenIssuer != "" {
		if tokenIssuer != v.issuer {
			return "", fmt.Errorf("validator: invalid issuer: expected %s, got %s", v.issuer, tokenIssuer)
		}
		issuer = tokenIssuer
	}

	return issuer, nil
}

func (v *OpaqueTokenValidator) resolveAudience(introspectionClaims map[string]interface{}) ([]string, error) {
	audience := extractAudience(introspectionClaims["aud"])
	if len(audience) > 0 && !contains(audience, v.audience) {
		return nil, fmt.Errorf("validator: invalid audience: expected %s in %v", v.audience, audience)
	}
	if len(audience) == 0 {
		audience = []string{v.audience}
	}

	return audience, nil
}

func resolveSubject(introspectionClaims map[string]interface{}) (string, error) {
	subject := firstNonEmpty(
		claimString(introspectionClaims, "sub"),
		claimString(introspectionClaims, "client_id"),
		claimString(introspectionClaims, "username"),
	)
	if subject == "" {
		return "", errors.New("validator: invalid subject claim: empty")
	}

	return subject, nil
}

func resolveExpiry(introspectionClaims map[string]interface{}) (time.Time, error) {
	var expiry time.Time
	if expRaw, ok := introspectionClaims["exp"]; ok {
		parsedExpiry, err := parseUnixTimeClaim(expRaw)
		if err != nil {
			return time.Time{}, fmt.Errorf("validator: invalid expiry claim: %w", err)
		}
		expiry = parsedExpiry
		if !expiry.After(time.Now()) {
			return time.Time{}, errors.New("validator: opaque token has expired")
		}
	}

	return expiry, nil
}

func resolveIssuedAt(introspectionClaims map[string]interface{}) (time.Time, error) {
	var issuedAt time.Time
	if iatRaw, ok := introspectionClaims["iat"]; ok {
		parsedIssuedAt, err := parseUnixTimeClaim(iatRaw)
		if err != nil {
			return time.Time{}, fmt.Errorf("validator: invalid issued at claim: %w", err)
		}
		issuedAt = parsedIssuedAt
	}

	return issuedAt, nil
}

func claimString(claims map[string]interface{}, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}

	stringValue, ok := value.(string)
	if !ok {
		return ""
	}

	return strings.TrimSpace(stringValue)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

func extractAudience(rawAudience interface{}) []string {
	switch value := rawAudience.(type) {
	case string:
		if value == "" {
			return []string{}
		}
		return []string{value}
	case []interface{}:
		audience := make([]string, 0, len(value))
		for _, audienceValue := range value {
			if audienceString, ok := audienceValue.(string); ok {
				audience = append(audience, audienceString)
			}
		}
		return audience
	case []string:
		audience := make([]string, 0, len(value))
		audience = append(audience, value...)
		return audience
	default:
		return []string{}
	}
}

func parseUnixTimeClaim(raw interface{}) (time.Time, error) {
	switch value := raw.(type) {
	case float64:
		return time.Unix(int64(value), 0), nil
	case int64:
		return time.Unix(value, 0), nil
	case int:
		return time.Unix(int64(value), 0), nil
	case json.Number:
		number, err := value.Int64()
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(number, 0), nil
	case string:
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(number, 0), nil
	default:
		return time.Time{}, fmt.Errorf("unexpected type %T", raw)
	}
}

func normalizeIntrospectionURL(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("validator: invalid introspection URL: %w", err)
	}

	if !parsedURL.IsAbs() {
		return "", errors.New("validator: introspection URL must be absolute")
	}
	if parsedURL.Scheme != "https" {
		return "", errors.New("validator: introspection URL must use https")
	}
	if parsedURL.Host == "" {
		return "", errors.New("validator: introspection URL host is required")
	}
	if parsedURL.User != nil {
		return "", errors.New("validator: introspection URL must not include user info")
	}
	if parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return "", errors.New("validator: introspection URL must not include query or fragment")
	}

	host := parsedURL.Hostname()
	if ipAddress, parseErr := netip.ParseAddr(host); parseErr == nil {
		if ipAddress.IsLoopback() ||
			ipAddress.IsPrivate() ||
			ipAddress.IsLinkLocalUnicast() ||
			ipAddress.IsLinkLocalMulticast() ||
			ipAddress.IsMulticast() ||
			ipAddress.IsUnspecified() {
			return "", errors.New("validator: introspection URL must not use local or private IP addresses")
		}
	}

	return parsedURL.String(), nil
}
