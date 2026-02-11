package main

import (
	"crypto/tls"
	"log"
	"net"

	"github.com/AmmannChristian/go-authx/grpcserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Create OAuth2 validator
	validator, err := grpcserver.NewValidatorBuilder(
		"https://auth.example.com",
		"my-api",
	).WithLogger(log.Default()).Build()
	if err != nil {
		log.Fatalf("Failed to create validator: %v", err)
	}

	// Configure TLS with mTLS (mutual TLS)
	tlsConfig := &grpcserver.TLSConfig{
		CertFile:   "/path/to/server.crt",
		KeyFile:    "/path/to/server.key",
		CAFile:     "/path/to/ca.crt", // Optional: for client certificate verification
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	tlsOpt, err := grpcserver.ServerOption(tlsConfig)
	if err != nil {
		log.Fatalf("Failed to create TLS option: %v", err)
	}

	// Create gRPC server with TLS and authentication
	grpcServer := grpc.NewServer(
		tlsOpt,
		grpc.UnaryInterceptor(
			grpcserver.UnaryServerInterceptor(
				validator,
				grpcserver.WithExemptMethods("/grpc.health.v1.Health/Check"),
				grpcserver.WithInterceptorLogger(log.Default()),
			),
		),
	)

	// Register services
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	reflection.Register(grpcServer)

	// Start server
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Println("gRPC server with TLS listening on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
