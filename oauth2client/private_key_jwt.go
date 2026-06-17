package oauth2client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AmmannChristian/go-authx/internal/keys"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	// #nosec G101 -- OAuth2/RFC7523 grant-type URI constant, not a credential.
	grantTypeJWTBearer       = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	jwtAssertionLifetime     = 60 * time.Second
	defaultHTTPClientTimeout = 5 * time.Second
)

type privateKeyJWTFetcher struct {
	privateKey any
	keyID      string
	clientID   string
	issuerURI  string
	scopes     []string
	httpClient *http.Client
}

func (f *privateKeyJWTFetcher) fetchToken(ctx context.Context) (*oauth2.Token, error) {
	now := time.Now().UTC()
	//nolint:gosec // jti only needs uniqueness, not cryptographic security (RFC 7523)
	jti := fmt.Sprintf("%d-%d", now.UnixNano(), rand.Int64())

	claims := jwt.RegisteredClaims{
		Issuer:    f.clientID,
		Subject:   f.clientID,
		Audience:  jwt.ClaimStrings{f.issuerURI},
		ExpiresAt: jwt.NewNumericDate(now.Add(jwtAssertionLifetime)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        jti,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if f.keyID != "" {
		token.Header["kid"] = f.keyID
	}

	assertionStr, err := token.SignedString(f.privateKey)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to sign JWT assertion: %w", err)
	}

	tokenURL := f.issuerURI + "/oauth/v2/token"
	formData := url.Values{
		"grant_type": {grantTypeJWTBearer},
		"assertion":  {assertionStr},
	}
	if len(f.scopes) > 0 {
		formData.Set("scope", strings.Join(f.scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("oauth2: token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("oauth2: failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("oauth2: token endpoint returned empty access token")
	}

	t := &oauth2.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
	}
	if tokenResp.ExpiresIn > 0 {
		t.Expiry = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return t, nil
}

// NewPrivateKeyJWTTokenManager creates a TokenManager that obtains tokens via the
// urn:ietf:params:oauth:grant-type:jwt-bearer grant using a ZITADEL service-account
// key file.
//
// keyFileJSON must be a ZITADEL service-account JSON:
//
//	{"type":"application","keyId":"...","key":"-----BEGIN ...","clientId":"...","appId":"..."}
//
// issuerURI is the ZITADEL issuer, e.g. "https://my-org.zitadel.cloud".
// scopes is space-separated, e.g. "openid".
// opts may include WithLogger, WithLoggingEnabled, WithHTTPClient.
func NewPrivateKeyJWTTokenManager(
	ctx context.Context,
	issuerURI string,
	keyFileJSON string,
	scopes string,
	opts ...Option,
) (*TokenManager, error) {
	envelope, privateKey, err := keys.ParseZitadelKeyEnvelope(keyFileJSON)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to parse key file: %w", err)
	}

	normalizedIssuer := strings.TrimRight(strings.TrimSpace(issuerURI), "/")

	fetcher := &privateKeyJWTFetcher{
		privateKey: privateKey,
		keyID:      envelope.KeyID,
		clientID:   envelope.ClientID,
		issuerURI:  normalizedIssuer,
		scopes:     strings.Fields(scopes),
		httpClient: &http.Client{Timeout: defaultHTTPClientTimeout},
	}

	tm := newTokenManagerWithFetcher(ctx, fetcher, opts...)

	// If WithHTTPClient was supplied via opts, override the fetcher's client.
	if tm.httpClient != nil {
		fetcher.httpClient = tm.httpClient
	}

	return tm, nil
}
