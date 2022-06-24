package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelseyhightower/envconfig"

	greeter "github.com/larwef/papers-please/api/greeter/v1"
	paperspb "github.com/larwef/papers-please/api/papers/v1"
	"github.com/larwef/papers-please/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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

	tlsConf, err := getTLSConfig(ctx, conf)
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

func getTLSConfig(ctx context.Context, conf Config) (*tls.Config, error) {
	conn, err := grpc.Dial(conf.PapersAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to dial papers: %w", err)
	}
	defer conn.Close()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"localhost", "server"},
	}, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}
	client := paperspb.NewPaperServiceClient(conn)
	res, err := client.GetCertificate(ctx, &paperspb.GetCertificateRequest{
		CertificateSigningRequest: csr,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(res.Certificate, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyDER,
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key pair: %w", err)
	}
	certPool := x509.NewCertPool()
	for _, caPem := range res.GetCaCertificates() {
		if !certPool.AppendCertsFromPEM(caPem) {
			return nil, fmt.Errorf("failed to append server CA cert: %w", err)
		}
	}
	return &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{certificate},
	}, nil
}
