package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelseyhightower/envconfig"

	greeter "github.com/larwef/papers-please/api/greeter/v1"
	"github.com/larwef/papers-please/internal/server"
	"google.golang.org/grpc"
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
		return fmt.Errorf("failed to listen: %v", err)
	}
	defer listener.Close()

	opts := []grpc.ServerOption{}
	grpcSrv := grpc.NewServer(opts...)
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
