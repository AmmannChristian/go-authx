package oauth2client_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/AmmannChristian/go-authx/oauth2client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024

var (
	bufListener = bufconn.Listen(bufSize)
	bufServer   = grpc.NewServer()
	bufOnce     sync.Once
)

func startBufServer() {
	bufOnce.Do(func() {
		go func() {
			_ = bufServer.Serve(bufListener)
		}()
	})
}

func dialBufConn(opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	startBufServer()

	dialOpts := []grpc.DialOption{
		grpc.WithContextDialer(func(c context.Context, _ string) (net.Conn, error) {
			select {
			case <-c.Done():
				return nil, c.Err()
			default:
			}
			return bufListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	dialOpts = append(dialOpts, opts...)
	return grpc.NewClient("bufnet", dialOpts...)
}

// Example demonstrates basic usage of TokenManager with gRPC interceptors.
func Example() {
	ctx := context.Background()

	// Create token manager
	tm := oauth2client.NewTokenManager(
		ctx,
		"https://auth.example.com/oauth/v2/token",
		"client-id",
		"client-secret",
		"openid profile email",
	)

	// Use with gRPC client
	conn, err := dialBufConn(
		grpc.WithUnaryInterceptor(tm.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(tm.StreamClientInterceptor()),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("gRPC client configured with OAuth2 authentication")
	// Output: gRPC client configured with OAuth2 authentication
}

// ExampleNewTokenManager demonstrates creating a new token manager.
func ExampleNewTokenManager() {
	ctx := context.Background()

	tm := oauth2client.NewTokenManager(
		ctx,
		"https://auth.example.com/oauth/v2/token",
		"my-client-id",
		"my-client-secret",
		"openid profile",
	)

	fmt.Printf("TokenManager created for client: %s\n", "my-client-id")
	_ = tm // Use the token manager

	// Output: TokenManager created for client: my-client-id
}

// ExampleTokenManager_GetToken demonstrates manual token retrieval.
func ExampleTokenManager_GetToken() {
	ctx := context.Background()

	tm := oauth2client.NewTokenManager(
		ctx,
		"https://auth.example.com/oauth/v2/token",
		"client-id",
		"client-secret",
		"openid",
	)

	// This would normally fetch a real token
	// For demonstration purposes, we just show the pattern
	_, err := tm.GetToken()
	if err != nil {
		// Handle error (in production this would connect to real OAuth2 server)
		fmt.Println("Token fetch attempted")
	}

	// Output: Token fetch attempted
}

// ExampleTokenManager_UnaryClientInterceptor demonstrates using the unary interceptor.
func ExampleTokenManager_UnaryClientInterceptor() {
	ctx := context.Background()

	tm := oauth2client.NewTokenManager(
		ctx,
		"https://auth.example.com/oauth/v2/token",
		"client-id",
		"client-secret",
		"openid",
	)

	// Create gRPC connection with unary interceptor
	conn, err := dialBufConn(
		grpc.WithUnaryInterceptor(tm.UnaryClientInterceptor()),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("Unary interceptor configured")
	// Output: Unary interceptor configured
}

// ExampleTokenManager_StreamClientInterceptor demonstrates using the stream interceptor.
func ExampleTokenManager_StreamClientInterceptor() {
	ctx := context.Background()

	tm := oauth2client.NewTokenManager(
		ctx,
		"https://auth.example.com/oauth/v2/token",
		"client-id",
		"client-secret",
		"openid",
	)

	// Create gRPC connection with stream interceptor
	conn, err := dialBufConn(
		grpc.WithStreamInterceptor(tm.StreamClientInterceptor()),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("Stream interceptor configured")
	// Output: Stream interceptor configured
}
