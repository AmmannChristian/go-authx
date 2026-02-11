package validator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OpaqueTokenValidator validates OAuth2 opaque tokens via RFC 7662 token introspection.
type OpaqueTokenValidator struct {
	introspectionURL string
	issuer           string
	audience         string
	clientID         string
	clientSecret     string
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
	if introspectionURL == "" {
		return nil, errors.New("validator: introspection URL is required")
	}
	if issuer == "" {
		return nil, errors.New("validator: issuer is required")
	}
	if audience == "" {
		return nil, errors.New("validator: audience is required")
	}
	if clientID == "" {
		return nil, errors.New("validator: introspection client ID is required")
	}
	if clientSecret == "" {
		return nil, errors.New("validator: introspection client secret is required")
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &OpaqueTokenValidator{
		introspectionURL: introspectionURL,
		issuer:           issuer,
		audience:         audience,
		clientID:         clientID,
		clientSecret:     clientSecret,
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
	values.Set("token_type_hint", "access_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.introspectionURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("validator: failed to create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(v.clientID, v.clientSecret)

	return req, nil
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
		Subject:  subject,
		Issuer:   issuer,
		Audience: audience,
		Expiry:   expiry,
		IssuedAt: issuedAt,
		Scopes:   scopes,
		Email:    email,
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
