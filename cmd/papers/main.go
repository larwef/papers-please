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
	paperspb "github.com/larwef/papers-please/api/papers/v1"
	"github.com/larwef/papers-please/internal/papers"
	"google.golang.org/grpc"
)

// Version injected at compile time.
var version = "No version provided"

type Config struct {
	Addr string `envconfig:"PAPERS_ADDR" default:":8083"`
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
	log.Printf("Starting papers v%s\n", version)

	var conf Config
	if err := envconfig.Process("papers", &conf); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", conf.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	opts := []grpc.ServerOption{}
	grpcSrv := grpc.NewServer(opts...)
	papers, err := papers.NewWithGeneratedKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create papers: %w", err)
	}
	paperspb.RegisterPaperServiceServer(grpcSrv, papers)

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
