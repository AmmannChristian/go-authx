// Package grpcclient provides a fluent builder for secure gRPC client connections with optional
// OAuth2 client-credentials authentication.
//
// It defaults to TLS 1.2+ using system roots to avoid accidental plaintext connections. Optional
// methods let you add OAuth2 interceptors, custom CA or mTLS credentials, and extra dial options.
//
// # Features
//
//   - Fluent builder for gRPC clients
//   - OAuth2 client-credentials integration via oauth2client
//   - Secure-by-default TLS; optional custom CA and mTLS
//   - Additional dial options via WithDialOptions
//
// # Quick Start
//
//	conn, err := grpcclient.NewBuilder().
//	    WithAddress("server.example.com:9090").
//	    WithOAuth2(
//	        "https://auth.example.com/oauth/v2/token",
//	        "client-id",
//	        "client-secret",
//	        "openid profile",
//	    ).
//	    WithTLS("/path/to/ca.crt", "", "", "server.example.com").
//	    Build(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer conn.Close()
//
//	client := pb.NewYourServiceClient(conn)
//
// # TLS Behavior
//
// TLS is enabled by default with system CAs and TLS 1.2 minimum. WithTLS allows supplying a custom
// root CA and optional client cert/key for mTLS; both cert and key must be provided together.
package grpcclient
