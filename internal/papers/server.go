package papers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	paperspb "github.com/larwef/papers-please/api/papers/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
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

	// Fetching, parsing and validating token from metadata.
	md, b := metadata.FromIncomingContext(ctx)
	if !b {
		return nil, status.Error(codes.InvalidArgument, "missing metadata")
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	var claims CustomClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	// Parse CSR, create a certificate and return the certificate to the client.
	csr, err := x509.ParseCertificateRequest(req.GetCertificateSigningRequest())
	if err != nil {
		return nil, err
	}
	template, err := csrToTemplate(csr, claims.Email)
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

func csrToTemplate(csr *x509.CertificateRequest, email string) (*x509.Certificate, error) {
	return &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour * 24),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:       csr.DNSNames,
		EmailAddresses: []string{email},
	}, nil
}

type CustomClaims struct {
	jwt.RegisteredClaims
	Email string `json:"email,omitempty"`
}

func (c *CustomClaims) Valid() error {
	if err := c.RegisteredClaims.Valid(); err != nil {
		return err
	}
	if c.Email == "" {
		return fmt.Errorf("Email is required")
	}
	return nil
}
