package httpclient

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AmmannChristian/go-authx/oauth2client"
	"github.com/AmmannChristian/go-authx/testutil"
)

func newMockOAuth2Server(tb testing.TB) *testutil.MockOAuth2Server {
	tb.Helper()

	return testutil.NewMockOAuth2Server(tb, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/token" {
			tb.Fatalf("unexpected token path: %s", req.URL.Path)
		}
		if req.Method != http.MethodPost {
			tb.Fatalf("unexpected token method: %s", req.Method)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{
			"access_token": "mock-access-token",
			"token_type": "Bearer",
			"expires_in": 3600
		}`)),
			Request: req,
		}, nil
	})
}

func TestNewOAuth2Transport(t *testing.T) {
	authServer := newMockOAuth2Server(t)
	defer authServer.Close()

	ctx := authServer.Ctx
	tm := oauth2client.NewTokenManager(ctx, authServer.URL+"/token", "client", "secret", "openid")

	transport := NewOAuth2Transport(tm, nil)

	if transport == nil {
		t.Fatal("transport should not be nil")
	}

	if transport.TokenManager != tm {
		t.Error("TokenManager not set correctly")
	}

	if transport.Base == nil {
		t.Error("Base should default to a transport")
	}
}

func TestNewOAuth2Transport_WithCustomBase(t *testing.T) {
	authServer := newMockOAuth2Server(t)
	defer authServer.Close()

	ctx := authServer.Ctx
	tm := oauth2client.NewTokenManager(ctx, authServer.URL+"/token", "client", "secret", "openid")

	customTransport := &http.Transport{}
	transport := NewOAuth2Transport(tm, customTransport)

	if transport.Base != customTransport {
		t.Error("Base should be set to custom transport")
	}
}

func TestOAuth2Transport_RoundTrip(t *testing.T) {
	authServer := newMockOAuth2Server(t)
	defer authServer.Close()

	// Create OAuth2 transport
	ctx := authServer.Ctx
	tm := oauth2client.NewTokenManager(ctx, authServer.URL+"/token", "client", "secret", "openid")
	baseTransport := testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			t.Error("Authorization header not found")
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader("missing auth")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			t.Errorf("expected Bearer token, got: %s", authHeader)
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != "mock-access-token" {
			t.Errorf("unexpected token: %s", token)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("success")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})

	transport := NewOAuth2Transport(tm, baseTransport)

	// Create HTTP client with OAuth2 transport
	client := &http.Client{Transport: transport}

	// Make request
	resp, err := client.Get("https://api.example.com")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "success" {
		t.Errorf("unexpected response body: %s", body)
	}
}

func TestOAuth2Transport_RoundTrip_NilTokenManager(t *testing.T) {
	transport := &OAuth2Transport{
		Base:         nil,
		TokenManager: nil,
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)

	resp, err := transport.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Error("expected error for nil TokenManager")
	}

	if !strings.Contains(err.Error(), "TokenManager is nil") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOAuth2Transport_RoundTrip_TokenFetchError(t *testing.T) {
	authServer := testutil.NewMockOAuth2Server(t, func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("token fetch failed")
	})
	defer authServer.Close()

	tm := oauth2client.NewTokenManager(authServer.Ctx, authServer.URL+"/token", "client", "secret", "openid")

	transport := NewOAuth2Transport(tm, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)

	resp, err := transport.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Error("expected error when token fetch fails")
	}

	if !strings.Contains(err.Error(), "failed to get token") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOAuth2Transport_RoundTrip_DefaultTransportUsed(t *testing.T) {
	authServer := newMockOAuth2Server(t)
	defer authServer.Close()

	tm := oauth2client.NewTokenManager(authServer.Ctx, authServer.URL+"/token", "client", "secret", "openid")

	called := false
	prevTransport := http.DefaultTransport
	http.DefaultTransport = testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("default")),
			Request:    req,
		}, nil
	})
	defer func() { http.DefaultTransport = prevTransport }()

	client := &http.Client{Transport: &OAuth2Transport{TokenManager: tm}}

	resp, err := client.Get("https://api.example.com/resource")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if !called {
		t.Fatal("expected default transport to be used")
	}
}

func TestOAuth2Transport_RoundTrip_RequestNotModified(t *testing.T) {
	authServer := newMockOAuth2Server(t)
	defer authServer.Close()

	ctx := authServer.Ctx
	tm := oauth2client.NewTokenManager(ctx, authServer.URL+"/token", "client", "secret", "openid")
	baseTransport := testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	transport := NewOAuth2Transport(tm, baseTransport)

	// Create original request with proper URL (not httptest.NewRequest which sets RequestURI)
	originalReq, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	originalReq.Header.Set("X-Custom-Header", "test-value")

	// Clone request and do RoundTrip
	client := &http.Client{Transport: transport}
	resp, err := client.Do(originalReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Original request should not have Authorization header
	if originalReq.Header.Get("Authorization") != "" {
		t.Error("original request should not be modified")
	}
}

func TestOAuth2Transport_RoundTrip_PreservesOtherHeaders(t *testing.T) {
	authServer := newMockOAuth2Server(t)
	defer authServer.Close()

	ctx := authServer.Ctx
	tm := oauth2client.NewTokenManager(ctx, authServer.URL+"/token", "client", "secret", "openid")
	baseTransport := testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Check that custom headers are preserved
		if req.Header.Get("X-Custom-Header") != "test-value" {
			t.Error("custom header not preserved")
		}

		if req.Header.Get("Content-Type") != "application/json" {
			t.Error("content-type header not preserved")
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	transport := NewOAuth2Transport(tm, baseTransport)

	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/resource", strings.NewReader("{}"))
	req.Header.Set("X-Custom-Header", "test-value")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
}

func TestNewHTTPClient(t *testing.T) {
	authServer := newMockOAuth2Server(t)
	defer authServer.Close()

	ctx := authServer.Ctx
	tm := oauth2client.NewTokenManager(ctx, authServer.URL+"/token", "client", "secret", "openid")

	client := NewHTTPClient(tm)

	if client == nil {
		t.Fatal("client should not be nil")
	}

	if client.Timeout == 0 {
		t.Error("timeout should be set")
	}

	if client.Transport == nil {
		t.Fatal("transport should not be nil")
	}

	// Verify transport is OAuth2Transport
	_, ok := client.Transport.(*OAuth2Transport)
	if !ok {
		t.Error("transport should be OAuth2Transport")
	}
}

func TestNewHTTPClient_Integration(t *testing.T) {
	authServer := newMockOAuth2Server(t)
	defer authServer.Close()

	ctx := authServer.Ctx
	tm := oauth2client.NewTokenManager(ctx, authServer.URL+"/token", "client", "secret", "openid")
	client := NewHTTPClient(tm)
	if transport, ok := client.Transport.(*OAuth2Transport); ok {
		transport.Base = testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			authHeader := req.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer mock-access-token") {
				t.Fatalf("unexpected authorization header: %s", authHeader)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("authenticated")),
				Request:    req,
			}, nil
		})
	}

	resp, err := client.Get("https://api.example.com/resource")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "authenticated" {
		t.Errorf("unexpected response: %s", body)
	}
}

// Benchmark tests
func BenchmarkOAuth2Transport_RoundTrip(b *testing.B) {
	authServer := newMockOAuth2Server(b)
	defer authServer.Close()

	ctx := authServer.Ctx
	tm := oauth2client.NewTokenManager(ctx, authServer.URL+"/token", "client", "secret", "openid")
	transport := NewOAuth2Transport(tm, testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	}))
	client := &http.Client{Transport: transport}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, _ := client.Get("https://api.example.com")
		if resp != nil {
			resp.Body.Close()
		}
	}
}

func BenchmarkOAuth2Transport_RoundTrip_Parallel(b *testing.B) {
	authServer := newMockOAuth2Server(b)
	defer authServer.Close()

	ctx := authServer.Ctx
	tm := oauth2client.NewTokenManager(ctx, authServer.URL+"/token", "client", "secret", "openid")
	transport := NewOAuth2Transport(tm, testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	}))
	client := &http.Client{Transport: transport}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, _ := client.Get("https://api.example.com")
			if resp != nil {
				resp.Body.Close()
			}
		}
	})
}
