package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"

	"github.com/AmmannChristian/go-authx/grpcserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	// Extract token claims from context
	claims, ok := grpcserver.TokenClaimsFromContext(ctx)
	if !ok {
		return &pb.HelloReply{Message: "Hello " + in.GetName()}, nil
	}

	log.Printf("Authenticated user: %s (subject: %s)", claims.PreferredUsername, claims.Subject)
	return &pb.HelloReply{Message: "Hello " + in.GetName() + " (authenticated)"}, nil
}

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
	pb.RegisterGreeterServer(grpcServer, &server{})
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
