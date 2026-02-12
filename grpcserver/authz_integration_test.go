package grpcserver

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const testBufConnSize = 1024 * 1024

func TestUnaryServerInterceptor_AuthorizationPolicyIntegration_Allow(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return &TokenClaims{
				Subject: "user-1",
				Scopes:  []string{"read"},
				RawClaims: map[string]any{
					"roles": []any{"admin"},
				},
			}, nil
		},
	}

	conn, cleanup := newHealthClientConn(t, validator,
		WithAuthorizationPolicy(AuthorizationPolicy{
			RequiredRoles: []string{"admin"},
		}),
	)
	defer cleanup()

	client := healthpb.NewHealthClient(conn)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer valid-token")

	resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("expected SERVING status, got %v", resp.GetStatus())
	}
}

func TestUnaryServerInterceptor_AuthorizationPolicyIntegration_Deny(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return &TokenClaims{
				Subject: "user-1",
				Scopes:  []string{"read"},
				RawClaims: map[string]any{
					"roles": []any{"viewer"},
				},
			}, nil
		},
	}

	conn, cleanup := newHealthClientConn(t, validator,
		WithAuthorizationPolicy(AuthorizationPolicy{
			RequiredRoles: []string{"admin"},
		}),
	)
	defer cleanup()

	client := healthpb.NewHealthClient(conn)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer valid-token")

	_, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
	if err == nil {
		t.Fatal("expected permission denied error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %v", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", st.Code())
	}
}

func TestUnaryServerInterceptor_AuthorizationPolicyIntegration_ExemptMethod(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return nil, errors.New("validator should not be called for exempt method")
		},
	}

	conn, cleanup := newHealthClientConn(t, validator,
		WithExemptMethods("/grpc.health.v1.Health/Check"),
		WithAuthorizationPolicy(AuthorizationPolicy{
			RequiredRoles: []string{"admin"},
		}),
	)
	defer cleanup()

	client := healthpb.NewHealthClient(conn)
	resp, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("unexpected error for exempt method: %v", err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("expected SERVING status, got %v", resp.GetStatus())
	}
}

func newHealthClientConn(t *testing.T, validator TokenValidator, opts ...InterceptorOption) (*grpc.ClientConn, func()) {
	t.Helper()

	listener := bufconn.Listen(testBufConnSize)
	server := grpc.NewServer(grpc.UnaryInterceptor(UnaryServerInterceptor(validator, opts...)))

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)

	go func() {
		_ = server.Serve(listener)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
	)
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatalf("failed to dial bufconn server: %v", err)
	}

	cleanup := func() {
		_ = conn.Close()
		server.Stop()
		_ = listener.Close()
	}

	return conn, cleanup
}
