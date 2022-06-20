package server

import (
	"context"

	greeter "github.com/larwef/papers-please/api/greeter/v1"
)

type Server struct {
	greeter.UnimplementedGreeterServiceServer
}

func (s *Server) SayHello(ctx context.Context, req *greeter.SayHelloRequest) (*greeter.SayHelloResponse, error) {
	return &greeter.SayHelloResponse{Message: "Hello " + req.Name}, nil
}
