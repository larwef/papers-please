package papers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	paperspb "github.com/larwef/papers-please/api/papers/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	conn         *grpc.ClientConn
	papersClient paperspb.PaperServiceClient
}

func NewClient(addr string, email string) (*Client, error) {
	conn, err := grpc.Dial(addr,
		// Keeping it simple fo now, but should do something other than insecure.
		// There's no secret data in the payload, but we want to protect the
		// token.
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(&perRpcCreds{email: email}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial papers: %w", err)
	}
	return &Client{
		conn:         conn,
		papersClient: paperspb.NewPaperServiceClient(conn),
	}, nil
}

func (c *Client) GetTLSConfig(ctx context.Context, csrTemplate *x509.CertificateRequest, expectedEmails []string) (*tls.Config, error) {
	// Currently we don't need the client after the first certificate is issued.
	// Needs to be changed in the future if supporting certificate renewal.
	defer c.conn.Close()
	// Generate private key. Will not be sent over the network.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate CSR and send to the certificate service.
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}
	res, err := c.papersClient.GetCertificate(ctx, &paperspb.GetCertificateRequest{
		CertificateSigningRequest: csr,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Need to do some massaging here to provide the format tls pkg expects.
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(res.Certificate, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
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
		RootCAs: certPool,
		// This is called AFTER normal certificate verification. Doesn't
		// override the default.
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			leaf := verifiedChains[0][0]
			if len(leaf.EmailAddresses) != 1 {
				return fmt.Errorf("expected certificate to contain a single email but got %d", len(leaf.EmailAddresses))
			}
			if !contains(leaf.EmailAddresses[0], expectedEmails) {
				return fmt.Errorf("email address %s does not match any expected emails: %v", leaf.EmailAddresses[0], expectedEmails)
			}
			return nil
		},
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func contains(elem string, slice []string) bool {
	for _, s := range slice {
		if s == elem {
			return true
		}
	}
	return false
}

// Simple implementation of some per RPC credentials.
type perRpcCreds struct {
	email string
}

func (p *perRpcCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": p.email,
	})
	bearer, err := token.SignedString([]byte("secret"))
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}
	return map[string]string{
		"authorization": "Bearer " + bearer,
	}, nil
}

func (p *perRpcCreds) RequireTransportSecurity() bool {
	return false // Should be true in an actual implementation.
}
