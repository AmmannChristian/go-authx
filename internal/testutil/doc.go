// Package testutil provides test helpers for go-authx packages.
//
// It includes utilities to spin up IPv4-only local HTTP servers (avoiding IPv6 in sandboxes),
// mock OAuth2 endpoints without real sockets, and generate self-signed certificates for TLS/mTLS tests.
//
// # Utilities
//
//   - NewLocalHTTPServer: start httptest server bound to 127.0.0.1
//   - MockOAuth2Server and StaticJSONResponse: stub OAuth2 token endpoints and capture requests
//   - RoundTripFunc: inline http.RoundTripper implementations
//   - WriteTestCACert / WriteTestCertAndKey: generate temporary CA and leaf certificates for tests
//
// These helpers are designed for tests and may mutate http.DefaultClient/Transport; they restore previous values via tb.Cleanup.
package testutil
