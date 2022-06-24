package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelseyhightower/envconfig"

	greeterpb "github.com/larwef/papers-please/api/greeter/v1"
	"github.com/larwef/papers-please/internal/papers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Version injected at compile time.
var version = "No version provided"

type Config struct {
	PapersAddr  string `envconfig:"CLIENT_PAPERS_ADDR" required:"true"`
	GreeterAddr string `envconfig:"CLIENT_GREETER_ADDR" required:"true"`
	Name        string `envconfig:"CLIENT_NAME" default:"World"`
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
	log.Printf("Starting client v%s\n", version)

	var conf Config
	if err := envconfig.Process("client'", &conf); err != nil {
		return err
	}

	papersClient, err := papers.NewClient(conf.PapersAddr)
	if err != nil {
		return fmt.Errorf("failed to create papers client: %w", err)
	}
	tlsConf, err := papersClient.GetTLSConfig(ctx, &x509.CertificateRequest{})
	if err != nil {
		return fmt.Errorf("failed to get TLS config: %w", err)
	}
	
	opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))}
	conn, err := grpc.Dial(conf.GreeterAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	client := greeterpb.NewGreeterServiceClient(conn)

	res, err := client.SayHello(ctx, &greeterpb.SayHelloRequest{Name: conf.Name})
	if err != nil {
		return err
	}
	log.Println(res.Message)

	return nil
}
