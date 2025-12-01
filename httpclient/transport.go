package httpclient

import (
	"fmt"
	"net/http"

	"github.com/AmmannChristian/go-authx/oauth2client"
)

// OAuth2Transport is an http.RoundTripper that automatically adds OAuth2
// Bearer tokens to outgoing HTTP requests.
//
// It wraps an existing transport (typically http.DefaultTransport) and
// injects the Authorization header before each request.
type OAuth2Transport struct {
	// Base is the underlying HTTP transport. If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// TokenManager provides OAuth2 access tokens.
	TokenManager *oauth2client.TokenManager
}

// RoundTrip implements http.RoundTripper interface.
// It fetches a valid OAuth2 token and adds it as "Authorization: Bearer <token>"
// to the request headers before delegating to the base transport.
// The token fetch respects the request context's cancellation and deadline.
func (t *OAuth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.TokenManager == nil {
		return nil, fmt.Errorf("httpclient: TokenManager is nil")
	}

	// Get a valid access token using the request context
	token, err := t.TokenManager.GetTokenWithContext(req.Context())
	if err != nil {
		return nil, fmt.Errorf("httpclient: failed to get token: %w", err)
	}

	// Clone the request to avoid modifying the original
	reqClone := req.Clone(req.Context())

	// Add Authorization header
	reqClone.Header.Set("Authorization", "Bearer "+token)

	// Use base transport or default
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(reqClone)
}

// NewOAuth2Transport creates a new OAuth2Transport with the given token manager.
// The base transport defaults to http.DefaultTransport if not specified.
func NewOAuth2Transport(tm *oauth2client.TokenManager, base http.RoundTripper) *OAuth2Transport {
	if base == nil {
		base = http.DefaultTransport
	}

	return &OAuth2Transport{
		Base:         base,
		TokenManager: tm,
	}
}
