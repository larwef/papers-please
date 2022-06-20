package papers

import (
	"context"

	paperspb "github.com/larwef/papers-please/api/papers/v1"
)

type Server struct {
	paperspb.UnimplementedPaperServiceServer
}

func (s *Server) GetPaper(ctx context.Context, req *paperspb.GetCertificateRequest) (*paperspb.GetCertificateResponse, error) {
	return &paperspb.GetCertificateResponse{}, nil
}
