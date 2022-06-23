package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelseyhightower/envconfig"

	greeter "github.com/larwef/papers-please/api/greeter/v1"
	"github.com/larwef/papers-please/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Version injected at compile time.
var version = "No version provided"

type Config struct {
	ServerAddr string `envconfig:"SERVER_ADDR" default:":8081"`
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

	tlsConf, err := getTLSConfig()
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
func getTLSConfig() (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, fmt.Errorf("failed to load server key pair: %w", err)
	}
	pemServerCA, err := ioutil.ReadFile("root.crt")
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to append server CA cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}
