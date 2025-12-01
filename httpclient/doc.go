// Package httpclient offers HTTP client construction helpers with OAuth2 authentication and TLS/mTLS options.
//
// It provides a fluent Builder that can create an http.Client with automatic Bearer token injection using
// oauth2client.TokenManager, configurable TLS (custom CA, mTLS, insecure for tests), timeouts, base transports,
// and redirect handling. OAuth2Transport can wrap any RoundTripper.
//
// # Features
//
//   - Fluent builder for http.Client with optional OAuth2 token injection
//   - TLS 1.2+ by default, with custom CA/mTLS and optional InsecureSkipVerify
//   - Custom timeouts, base transport override, and redirect disabling
//   - Reusable OAuth2Transport for manual composition
//
// # Quick Start
//
//	client, err := httpclient.NewBuilder().
//	    WithOAuth2(ctx,
//	        "https://auth.example.com/oauth/v2/token",
//	        "client-id",
//	        "client-secret",
//	        "openid profile",
//	    ).
//	    WithTLS("/path/to/ca.crt", "", "").
//	    WithTimeout(60 * time.Second).
//	    Build()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	resp, err := client.Get("https://api.example.com/data")
//
// # Manual Transport Wrapping
//
//	transport := httpclient.NewOAuth2Transport(tm, nil)
//	client := &http.Client{Transport: transport}
//
// All components are safe for concurrent use if the provided TokenManager is.
package httpclient
