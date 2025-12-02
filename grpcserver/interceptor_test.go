package grpcserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockValidator is a mock implementation of TokenValidator for testing
type mockValidator struct {
	validateFunc func(ctx context.Context, token string) (*TokenClaims, error)
}

func (m *mockValidator) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return &TokenClaims{
		Subject:  "test-user",
		Issuer:   "https://auth.example.com",
		Audience: []string{"my-api"},
		Expiry:   time.Now().Add(time.Hour),
		IssuedAt: time.Now(),
		Scopes:   []string{"read", "write"},
		Email:    "test@example.com",
	}, nil
}

func TestUnaryServerInterceptor_Success(t *testing.T) {
	validator := &mockValidator{}
	interceptor := UnaryServerInterceptor(validator)

	// Create context with valid authorization header
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer valid-token"),
	)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true

		// Verify claims are in context
		claims, ok := TokenClaimsFromContext(ctx)
		if !ok {
			t.Error("expected claims to be in context")
		}
		if claims.Subject != "test-user" {
			t.Errorf("expected subject test-user, got %s", claims.Subject)
		}

		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	resp, err := interceptor(ctx, "request", info, handler)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("expected handler to be called")
	}
	if resp != "response" {
		t.Errorf("expected response 'response', got %v", resp)
	}
}

func TestUnaryServerInterceptor_MissingMetadata(t *testing.T) {
	validator := &mockValidator{}
	interceptor := UnaryServerInterceptor(validator)

	// Context without metadata
	ctx := context.Background()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Error("handler should not be called")
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	_, err := interceptor(ctx, "request", info, handler)

	if err == nil {
		t.Error("expected error when metadata is missing")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Error("expected gRPC status error")
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected code Unauthenticated, got %v", st.Code())
	}
}

func TestUnaryServerInterceptor_MissingAuthHeader(t *testing.T) {
	validator := &mockValidator{}
	interceptor := UnaryServerInterceptor(validator)

	// Metadata without authorization header
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("other-header", "value"),
	)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Error("handler should not be called")
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	_, err := interceptor(ctx, "request", info, handler)

	if err == nil {
		t.Error("expected error when authorization header is missing")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Error("expected gRPC status error")
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected code Unauthenticated, got %v", st.Code())
	}
}

func TestUnaryServerInterceptor_InvalidAuthFormat(t *testing.T) {
	validator := &mockValidator{}
	interceptor := UnaryServerInterceptor(validator)

	tests := []string{
		"invalid-format",
		"Basic token",
		"Bearer",
		"Bearer ",
	}

	for _, authHeader := range tests {
		t.Run(authHeader, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", authHeader),
			)

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				t.Error("handler should not be called")
				return nil, nil
			}

			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

			_, err := interceptor(ctx, "request", info, handler)

			if err == nil {
				t.Error("expected error for invalid auth format")
			}
		})
	}
}

func TestUnaryServerInterceptor_ValidationError(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return nil, errors.New("token expired")
		},
	}
	interceptor := UnaryServerInterceptor(validator)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer expired-token"),
	)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Error("handler should not be called")
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	_, err := interceptor(ctx, "request", info, handler)

	if err == nil {
		t.Error("expected error when validation fails")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Error("expected gRPC status error")
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected code Unauthenticated, got %v", st.Code())
	}
}

func TestUnaryServerInterceptor_ExemptMethod(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			t.Error("validator should not be called for exempt method")
			return nil, errors.New("should not be called")
		},
	}

	interceptor := UnaryServerInterceptor(
		validator,
		WithExemptMethods("/grpc.health.v1.Health/Check"),
	)

	// Context without authorization header (would normally fail)
	ctx := context.Background()

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}

	resp, err := interceptor(ctx, "request", info, handler)
	if err != nil {
		t.Errorf("unexpected error for exempt method: %v", err)
	}
	if !handlerCalled {
		t.Error("expected handler to be called for exempt method")
	}
	if resp != "response" {
		t.Errorf("expected response 'response', got %v", resp)
	}
}

func TestUnaryServerInterceptor_WithLogger(t *testing.T) {
	logger := &mockLogger{}
	validator := &mockValidator{}

	interceptor := UnaryServerInterceptor(
		validator,
		WithInterceptorLogger(logger),
	)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer valid-token"),
	)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	_, err := interceptor(ctx, "request", info, handler)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify logger was called
	if len(logger.getMessages()) == 0 {
		t.Error("expected logger to be called")
	}
}

func TestUnaryServerInterceptor_CustomUnauthorizedCode(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return nil, errors.New("invalid token")
		},
	}

	interceptor := UnaryServerInterceptor(
		validator,
		WithUnauthorizedCode(codes.PermissionDenied),
	)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer invalid-token"),
	)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	_, err := interceptor(ctx, "request", info, handler)

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected code PermissionDenied, got %v", st.Code())
	}
}

func TestUnaryServerInterceptor_CustomTokenExtractor(t *testing.T) {
	validator := &mockValidator{}

	customExtractor := func(md metadata.MD) (string, bool) {
		// Extract from custom header "x-api-token"
		tokens := md.Get("x-api-token")
		if len(tokens) == 0 {
			return "", false
		}
		return tokens[0], true
	}

	interceptor := UnaryServerInterceptor(
		validator,
		WithTokenExtractor(customExtractor),
	)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("x-api-token", "custom-token"),
	)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	_, err := interceptor(ctx, "request", info, handler)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("expected handler to be called")
	}
}

func TestStreamServerInterceptor_Success(t *testing.T) {
	validator := &mockValidator{}
	interceptor := StreamServerInterceptor(validator)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer valid-token"),
	)

	stream := &mockServerStream{ctx: ctx}

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true

		// Verify claims are in stream context
		claims, ok := TokenClaimsFromContext(stream.Context())
		if !ok {
			t.Error("expected claims to be in stream context")
		}
		if claims.Subject != "test-user" {
			t.Errorf("expected subject test-user, got %s", claims.Subject)
		}

		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	err := interceptor(nil, stream, info, handler)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("expected handler to be called")
	}
}

func TestStreamServerInterceptor_ValidationError(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return nil, errors.New("token expired")
		},
	}
	interceptor := StreamServerInterceptor(validator)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer expired-token"),
	)

	stream := &mockServerStream{ctx: ctx}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		t.Error("handler should not be called")
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	err := interceptor(nil, stream, info, handler)

	if err == nil {
		t.Error("expected error when validation fails")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Error("expected gRPC status error")
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected code Unauthenticated, got %v", st.Code())
	}
}

func TestStreamServerInterceptor_ExemptMethod(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			t.Error("validator should not be called for exempt method")
			return nil, errors.New("should not be called")
		},
	}

	interceptor := StreamServerInterceptor(
		validator,
		WithExemptMethods("/grpc.health.v1.Health/Watch"),
	)

	stream := &mockServerStream{ctx: context.Background()}

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/grpc.health.v1.Health/Watch"}

	err := interceptor(nil, stream, info, handler)
	if err != nil {
		t.Errorf("unexpected error for exempt method: %v", err)
	}
	if !handlerCalled {
		t.Error("expected handler to be called for exempt method")
	}
}

func TestWithExemptMethods(t *testing.T) {
	config := &InterceptorConfig{}

	opt := WithExemptMethods("/method1", "/method2", "/method3")
	opt(config)

	if len(config.exemptMethods) != 3 {
		t.Errorf("expected 3 exempt methods, got %d", len(config.exemptMethods))
	}
	if !config.exemptMethods["/method1"] {
		t.Error("expected /method1 to be exempt")
	}
	if !config.exemptMethods["/method2"] {
		t.Error("expected /method2 to be exempt")
	}
	if !config.exemptMethods["/method3"] {
		t.Error("expected /method3 to be exempt")
	}
}

func TestWrappedServerStream_Context(t *testing.T) {
	type testKey string
	originalCtx := context.Background()
	newCtx := context.WithValue(originalCtx, testKey("test-key"), "test-value")

	stream := &mockServerStream{ctx: originalCtx}
	wrapped := &wrappedServerStream{
		ServerStream: stream,
		ctx:          newCtx,
	}

	// Verify wrapped stream returns new context
	if wrapped.Context() != newCtx {
		t.Error("expected wrapped stream to return new context")
	}

	// Verify original stream context is unchanged
	if stream.Context() != originalCtx {
		t.Error("expected original stream context to be unchanged")
	}
}

// mockServerStream is a mock implementation of grpc.ServerStream for testing
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockServerStream) RecvMsg(msg interface{}) error {
	return nil
}

func TestStreamServerInterceptor_WithLogger(t *testing.T) {
	logger := &mockLogger{}
	validator := &mockValidator{}

	interceptor := StreamServerInterceptor(
		validator,
		WithInterceptorLogger(logger),
	)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer valid-token"),
	)

	stream := &mockServerStream{ctx: ctx}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	err := interceptor(nil, stream, info, handler)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify logger was called
	if len(logger.getMessages()) == 0 {
		t.Error("expected logger to be called")
	}
}

func TestStreamServerInterceptor_MissingMetadata(t *testing.T) {
	validator := &mockValidator{}
	interceptor := StreamServerInterceptor(validator)

	// Context without metadata
	stream := &mockServerStream{ctx: context.Background()}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		t.Error("handler should not be called")
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	err := interceptor(nil, stream, info, handler)

	if err == nil {
		t.Error("expected error when metadata is missing")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Error("expected gRPC status error")
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected code Unauthenticated, got %v", st.Code())
	}
}

func TestStreamServerInterceptor_CustomUnauthorizedCode(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return nil, errors.New("invalid token")
		},
	}

	interceptor := StreamServerInterceptor(
		validator,
		WithUnauthorizedCode(codes.PermissionDenied),
	)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer invalid-token"),
	)

	stream := &mockServerStream{ctx: ctx}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	err := interceptor(nil, stream, info, handler)

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected code PermissionDenied, got %v", st.Code())
	}
}

func TestUnaryServerInterceptor_ExemptMethod_WithLogger(t *testing.T) {
	logger := &mockLogger{}
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			t.Error("validator should not be called for exempt method")
			return nil, errors.New("should not be called")
		},
	}

	interceptor := UnaryServerInterceptor(
		validator,
		WithExemptMethods("/grpc.health.v1.Health/Check"),
		WithInterceptorLogger(logger),
	)

	// Context without authorization header (would normally fail)
	ctx := context.Background()

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}

	resp, err := interceptor(ctx, "request", info, handler)
	if err != nil {
		t.Errorf("unexpected error for exempt method: %v", err)
	}
	if !handlerCalled {
		t.Error("expected handler to be called for exempt method")
	}
	if resp != "response" {
		t.Errorf("expected response 'response', got %v", resp)
	}

	// Verify logger was called for exempt method
	if len(logger.getMessages()) == 0 {
		t.Error("expected logger to be called")
	}
}

func TestStreamServerInterceptor_ExemptMethod_WithLogger(t *testing.T) {
	logger := &mockLogger{}
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			t.Error("validator should not be called for exempt method")
			return nil, errors.New("should not be called")
		},
	}

	interceptor := StreamServerInterceptor(
		validator,
		WithExemptMethods("/grpc.health.v1.Health/Watch"),
		WithInterceptorLogger(logger),
	)

	stream := &mockServerStream{ctx: context.Background()}

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/grpc.health.v1.Health/Watch"}

	err := interceptor(nil, stream, info, handler)
	if err != nil {
		t.Errorf("unexpected error for exempt method: %v", err)
	}
	if !handlerCalled {
		t.Error("expected handler to be called for exempt method")
	}

	// Verify logger was called for exempt method
	if len(logger.getMessages()) == 0 {
		t.Error("expected logger to be called")
	}
}

func TestUnaryServerInterceptor_ValidationError_WithLogger(t *testing.T) {
	logger := &mockLogger{}
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return nil, errors.New("token expired")
		},
	}
	interceptor := UnaryServerInterceptor(
		validator,
		WithInterceptorLogger(logger),
	)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer expired-token"),
	)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Error("handler should not be called")
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	_, err := interceptor(ctx, "request", info, handler)

	if err == nil {
		t.Error("expected error when validation fails")
	}

	// Verify logger was called with error
	if len(logger.getMessages()) == 0 {
		t.Error("expected logger to be called with error message")
	}
}
