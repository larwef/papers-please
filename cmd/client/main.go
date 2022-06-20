package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelseyhightower/envconfig"

	greeter "github.com/larwef/papers-please/api/greeter/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.Dial(conf.GreeterAddr, opts...)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
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
