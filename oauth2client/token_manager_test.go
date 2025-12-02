package oauth2client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AmmannChristian/go-authx/internal/testutil"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type stubLogger struct {
	mu       sync.Mutex
	messages []string
}

func (l *stubLogger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, fmt.Sprintf(format, args...))
}

func (l *stubLogger) getMessages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	msgs := make([]string, len(l.messages))
	copy(msgs, l.messages)
	return msgs
}

// Mock OAuth2 server for testing
func newMockOAuth2Server(tb testing.TB) *testutil.MockOAuth2Server {
	tb.Helper()

	return testutil.NewMockOAuth2Server(tb, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/token" {
			tb.Fatalf("unexpected path: %s", req.URL.Path)
		}

		if req.Method != http.MethodPost {
			tb.Fatalf("unexpected method: %s", req.Method)
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

func TestNewTokenManager(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		tokenURL     string
		clientID     string
		clientSecret string
		scopes       string
	}{
		{
			name:         "basic configuration",
			tokenURL:     "https://auth.example.com/token",
			clientID:     "test-client",
			clientSecret: "test-secret",
			scopes:       "openid profile",
		},
		{
			name:         "empty scopes",
			tokenURL:     "https://auth.example.com/token",
			clientID:     "test-client",
			clientSecret: "test-secret",
			scopes:       "",
		},
		{
			name:         "multiple scopes",
			tokenURL:     "https://auth.example.com/token",
			clientID:     "test-client",
			clientSecret: "test-secret",
			scopes:       "openid profile email address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm := NewTokenManager(ctx, tt.tokenURL, tt.clientID, tt.clientSecret, tt.scopes)

			if tm == nil {
				t.Fatal("TokenManager should not be nil")
			}

			if tm.config == nil {
				t.Fatal("config should not be nil")
			}

			if tm.config.ClientID != tt.clientID {
				t.Errorf("expected ClientID %s, got %s", tt.clientID, tm.config.ClientID)
			}

			if tm.config.ClientSecret != tt.clientSecret {
				t.Errorf("expected ClientSecret %s, got %s", tt.clientSecret, tm.config.ClientSecret)
			}

			if tm.config.TokenURL != tt.tokenURL {
				t.Errorf("expected TokenURL %s, got %s", tt.tokenURL, tm.config.TokenURL)
			}

			if tm.expiryLeeway != time.Minute {
				t.Errorf("expected expiryLeeway 1m, got %v", tm.expiryLeeway)
			}
		})
	}
}

func TestNewTokenManager_NilContext(t *testing.T) {
	//lint:ignore SA1012 intentionally verify nil context falls back to background
	//nolint:staticcheck // golangci-lint
	tm := NewTokenManager(nil, "https://auth.example.com/token", "client", "secret", "openid")

	if tm == nil {
		t.Fatal("TokenManager should not be nil")
	}

	if tm.ctx == nil {
		t.Fatal("context should not be nil (should use Background)")
	}
}

func TestTokenManager_GetToken(t *testing.T) {
	server := newMockOAuth2Server(t)
	defer server.Close()

	ctx := server.Ctx
	tm := NewTokenManager(ctx, server.URL+"/token", "test-client", "test-secret", "openid")

	// First call should fetch a new token
	token1, err := tm.GetToken()
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}

	if token1 != "mock-access-token" {
		t.Errorf("expected token 'mock-access-token', got '%s'", token1)
	}

	// Second call should return cached token
	token2, err := tm.GetToken()
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}

	if token2 != token1 {
		t.Error("expected cached token to be returned")
	}
}

func TestTokenManager_GetToken_Concurrent(t *testing.T) {
	server := newMockOAuth2Server(t)
	defer server.Close()

	ctx := server.Ctx
	tm := NewTokenManager(ctx, server.URL+"/token", "test-client", "test-secret", "openid")

	// Test concurrent access
	const goroutines = 10
	results := make(chan string, goroutines)
	errors := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			token, err := tm.GetToken()
			if err != nil {
				errors <- err
				return
			}
			results <- token
		}()
	}

	// Collect results
	tokens := make([]string, 0, goroutines)
	for i := 0; i < goroutines; i++ {
		select {
		case token := <-results:
			tokens = append(tokens, token)
		case err := <-errors:
			t.Errorf("GetToken failed in goroutine: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for goroutine")
		}
	}

	// All tokens should be the same (cached)
	for i, token := range tokens {
		if token != "mock-access-token" {
			t.Errorf("goroutine %d: expected 'mock-access-token', got '%s'", i, token)
		}
	}
}

func TestTokenManager_GetTokenWithContext_DoubleCheckCache(t *testing.T) {
	// Use proper synchronization instead of time.Sleep to avoid flaky tests
	requestStarted := make(chan struct{})
	requestComplete := make(chan struct{})

	server := testutil.NewMockOAuth2Server(t, func(req *http.Request) (*http.Response, error) {
		// Signal that the first goroutine has entered the token request
		select {
		case requestStarted <- struct{}{}:
		default:
		}

		// Wait for signal to complete the request
		<-requestComplete

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
	defer server.Close()

	tm := NewTokenManager(server.Ctx, server.URL+"/token", "client", "secret", "openid")

	var wg sync.WaitGroup
	wg.Add(2)

	tokens := make(chan string, 2)
	errs := make(chan error, 2)

	// Start first goroutine
	go func() {
		defer wg.Done()
		token, err := tm.GetTokenWithContext(context.Background())
		if err != nil {
			errs <- err
			return
		}
		tokens <- token
	}()

	// Wait for first goroutine to enter the token request
	<-requestStarted

	// Start second goroutine - it should wait for the first to complete
	go func() {
		defer wg.Done()
		token, err := tm.GetTokenWithContext(context.Background())
		if err != nil {
			errs <- err
			return
		}
		tokens <- token
	}()

	// Allow the request to complete
	close(requestComplete)

	wg.Wait()

	close(errs)
	for err := range errs {
		t.Fatalf("GetTokenWithContext failed: %v", err)
	}

	// Both goroutines should have received the same token from a single request
	if len(server.Requests) != 1 {
		t.Fatalf("expected single token request due to double-check locking, got %d", len(server.Requests))
	}

	close(tokens)
	tokensReceived := 0
	for token := range tokens {
		tokensReceived++
		if token != "mock-access-token" {
			t.Errorf("unexpected token: %s", token)
		}
	}

	if tokensReceived != 2 {
		t.Errorf("expected 2 tokens received, got %d", tokensReceived)
	}
}

func TestTokenManager_GetToken_InvalidServer(t *testing.T) {
	server := testutil.NewMockOAuth2Server(t, func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("token fetch failed")
	})
	defer server.Close()

	tm := NewTokenManager(server.Ctx, server.URL+"/token", "client", "secret", "openid")

	_, err := tm.GetToken()
	if err == nil {
		t.Error("expected error for invalid server, got nil")
	}

	if !strings.Contains(err.Error(), "token fetch failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTokenManager_UnaryClientInterceptor(t *testing.T) {
	server := newMockOAuth2Server(t)
	defer server.Close()

	ctx := server.Ctx
	tm := NewTokenManager(ctx, server.URL+"/token", "test-client", "test-secret", "openid")

	// Create interceptor
	interceptor := tm.UnaryClientInterceptor()
	if interceptor == nil {
		t.Fatal("interceptor should not be nil")
	}

	// Test interceptor with mock invoker
	called := false
	mockInvoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		called = true

		// Check that authorization header was added
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Error("metadata not found in context")
			return nil
		}

		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			t.Error("authorization header not found")
			return nil
		}

		if !strings.HasPrefix(authHeaders[0], "Bearer ") {
			t.Errorf("expected Bearer token, got: %s", authHeaders[0])
		}

		return nil
	}

	err := interceptor(ctx, "/test.Service/Method", nil, nil, nil, mockInvoker)
	if err != nil {
		t.Errorf("interceptor failed: %v", err)
	}

	if !called {
		t.Error("invoker was not called")
	}
}

func TestTokenManager_StreamClientInterceptor(t *testing.T) {
	server := newMockOAuth2Server(t)
	defer server.Close()

	ctx := server.Ctx
	tm := NewTokenManager(ctx, server.URL+"/token", "test-client", "test-secret", "openid")

	// Create interceptor
	interceptor := tm.StreamClientInterceptor()
	if interceptor == nil {
		t.Fatal("interceptor should not be nil")
	}

	// Test interceptor with mock streamer
	called := false
	mockStreamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		called = true

		// Check that authorization header was added
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Error("metadata not found in context")
			return nil, nil
		}

		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			t.Error("authorization header not found")
			return nil, nil
		}

		if !strings.HasPrefix(authHeaders[0], "Bearer ") {
			t.Errorf("expected Bearer token, got: %s", authHeaders[0])
		}

		return nil, nil
	}

	_, err := interceptor(ctx, &grpc.StreamDesc{}, nil, "/test.Service/Method", mockStreamer)
	if err != nil {
		t.Errorf("interceptor failed: %v", err)
	}

	if !called {
		t.Error("streamer was not called")
	}
}

func TestTokenManager_TokenValid(t *testing.T) {
	ctx := context.Background()
	tm := NewTokenManager(ctx, "https://auth.example.com/token", "client", "secret", "openid")

	if tm.tokenValid() {
		t.Error("nil token should not be valid")
	}

	tm.token = &oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(30 * time.Second),
	}

	if tm.tokenValid() {
		t.Error("token close to expiry should be treated as invalid")
	}

	tm.token = &oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(2 * time.Minute),
	}

	if !tm.tokenValid() {
		t.Error("fresh token should be valid")
	}
}

func TestTokenManager_Interceptor_TokenFetchError(t *testing.T) {
	server := testutil.NewMockOAuth2Server(t, func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("token fetch failed")
	})
	defer server.Close()

	tm := NewTokenManager(server.Ctx, server.URL+"/token", "client", "secret", "openid")

	// Test unary interceptor
	unaryInterceptor := tm.UnaryClientInterceptor()
	err := unaryInterceptor(server.Ctx, "/test", nil, nil, nil, func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		t.Error("invoker should not be called when token fetch fails")
		return nil
	})

	if err == nil {
		t.Error("expected error from unary interceptor, got nil")
	}

	// Test stream interceptor
	streamInterceptor := tm.StreamClientInterceptor()
	_, err = streamInterceptor(server.Ctx, &grpc.StreamDesc{}, nil, "/test", func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		t.Error("streamer should not be called when token fetch fails")
		return nil, nil
	})

	if err == nil {
		t.Error("expected error from stream interceptor, got nil")
	}
}

func TestTokenManager_GetTokenWithContext_NilContextAndCache(t *testing.T) {
	server := newMockOAuth2Server(t)
	defer server.Close()

	//lint:ignore SA1012 intentionally verify nil context falls back to background
	//nolint:staticcheck // golangci-lint
	tm := NewTokenManager(nil, server.URL+"/token", "client", "secret", "openid")

	//lint:ignore SA1012 intentionally verify nil context falls back to background
	//nolint:staticcheck // golangci-lint
	token1, err := tm.GetTokenWithContext(nil)
	if err != nil {
		t.Fatalf("GetTokenWithContext failed: %v", err)
	}
	if token1 == "" {
		t.Fatal("token should not be empty")
	}

	//lint:ignore SA1012 intentionally verify nil context falls back to background
	//nolint:staticcheck // golangci-lint
	token2, err := tm.GetTokenWithContext(nil)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if token1 != token2 {
		t.Errorf("expected cached token, got %q vs %q", token1, token2)
	}

	if len(server.Requests) != 1 {
		t.Fatalf("expected single token request, got %d", len(server.Requests))
	}
}

func TestTokenManager_WithLogger_LogsOnFetch(t *testing.T) {
	server := newMockOAuth2Server(t)
	defer server.Close()

	logger := &stubLogger{}

	tm := NewTokenManager(server.Ctx, server.URL+"/token", "client", "secret", "openid", WithLogger(logger))
	_, err := tm.GetTokenWithContext(context.Background())
	if err != nil {
		t.Fatalf("GetTokenWithContext failed: %v", err)
	}

	if len(logger.getMessages()) == 0 {
		t.Fatal("expected logger to receive messages")
	}
}

func TestTokenManager_WithLoggingEnabled_SetsLogger(t *testing.T) {
	tm := NewTokenManager(context.Background(), "https://auth.example.com/token", "client", "secret", "openid", WithLoggingEnabled())
	if tm.logger == nil {
		t.Fatal("expected logger to be set")
	}
}

// Benchmark tests
func BenchmarkTokenManager_GetToken_Cached(b *testing.B) {
	server := newMockOAuth2Server(b)
	defer server.Close()

	tm := NewTokenManager(server.Ctx, server.URL+"/token", "client", "secret", "openid")

	// Pre-fetch token
	_, _ = tm.GetToken()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tm.GetToken()
	}
}

func BenchmarkTokenManager_GetToken_Concurrent(b *testing.B) {
	server := newMockOAuth2Server(b)
	defer server.Close()

	tm := NewTokenManager(server.Ctx, server.URL+"/token", "client", "secret", "openid")

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = tm.GetToken()
		}
	})
}
