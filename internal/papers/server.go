package papers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	paperspb "github.com/larwef/papers-please/api/papers/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	paperspb.UnimplementedPaperServiceServer

	caKey         crypto.PrivateKey
	caCrtPem      []byte
	caCertificate *x509.Certificate
}

// Helper function making poc easier.
func NewWithGeneratedKeyPair() (*Server, error) {
	caKey, caCrt, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return New(caKey, caCrt)
}

// Helper function making poc easier.
func GenerateKeyPair() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	caCertTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 7),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caCerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caCerPrivateKey.PublicKey, caCerPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, err
	}
	return caCerPrivateKey, caCert, nil
}

func New(key crypto.PrivateKey, crt *x509.Certificate) (*Server, error) {
	return &Server{
		caKey: key,
		caCrtPem: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		}),
		caCertificate: crt,
	}, nil
}

func (s *Server) GetCertificate(ctx context.Context, req *paperspb.GetCertificateRequest) (*paperspb.GetCertificateResponse, error) {
	if req.GetCertificateSigningRequest() == nil {
		return nil, status.Error(codes.InvalidArgument, "missing certificate signing request")
	}
	csr, err := x509.ParseCertificateRequest(req.GetCertificateSigningRequest())
	if err != nil {
		return nil, err
	}
	template, err := csrToTemplate(csr)
	if err != nil {
		return nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, s.caCertificate, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, err
	}
	return &paperspb.GetCertificateResponse{
		Certificate: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}),
		CaCertificates: [][]byte{s.caCrtPem},
	}, nil
}

func csrToTemplate(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     csr.DNSNames,
	}, nil
}
