package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelseyhightower/envconfig"

	greeter "github.com/larwef/papers-please/api/greeter/v1"
	"github.com/larwef/papers-please/internal/papers"
	"github.com/larwef/papers-please/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Version injected at compile time.
var version = "No version provided"

type Config struct {
	ServerAddr string `envconfig:"SERVER_ADDR" default:":8081"`
	PapersAddr string `envconfig:"CLIENT_PAPERS_ADDR" required:"true"`
}

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := realMain(ctx)
	done()
	if err != nil {
		log.Fatal(err)
	}
}

func realMain(ctx context.Context) error {
	log.Printf("Starting server v%s\n", version)
	var conf Config
	if err := envconfig.Process("server", &conf); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", conf.ServerAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	papersClient, err := papers.NewClient(conf.PapersAddr, "server@foo.com")
	if err != nil {
		return fmt.Errorf("failed to create papers client: %w", err)
	}
	tlsConf, err := papersClient.GetTLSConfig(ctx, &x509.CertificateRequest{
		DNSNames: []string{"localhost", "server"},
	}, []string{"client@foo.com"})
	if err != nil {
		return fmt.Errorf("failed to get TLS config: %w", err)
	}
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConf)))
	greeter.RegisterGreeterServiceServer(grpcSrv, &server.Server{})

	errCh := make(chan error)
	go func() {
		if err := grpcSrv.Serve(listener); err != nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		grpcSrv.GracefulStop()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}
