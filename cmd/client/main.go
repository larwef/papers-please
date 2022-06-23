package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelseyhightower/envconfig"

	greeter "github.com/larwef/papers-please/api/greeter/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Version injected at compile time.
var version = "No version provided"

type Config struct {
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

	tlsConf, err := getTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to get TLS config: %w", err)
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))}
	conn, err := grpc.Dial(conf.GreeterAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	client := greeter.NewGreeterServiceClient(conn)

	res, err := client.SayHello(ctx, &greeter.SayHelloRequest{Name: conf.Name})
	if err != nil {
		return err
	}
	log.Println(res.Message)

	return nil
}

func getTLSConfig() (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		return nil, fmt.Errorf("failed to load client key pair: %w", err)
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
		RootCAs:      certPool,
		Certificates: []tls.Certificate{certificate},
	}, nil
}
