package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	// Generate root certificate
	rootPriv, rootCert, err := generateCert(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
	}, nil, nil, elliptic.P256())
	if err != nil {
		log.Fatalf("failed to generate root certificate: %v", err)
	}
	if err := encodeKeyPair("root", rootPriv, rootCert); err != nil {
		log.Fatalf("failed to encode root key pair: %v", err)
	}

	// Generate intermediate certificate
	intermediateParent, err := x509.ParseCertificate(rootCert)
	if err != nil {
		log.Fatalf("failed to parse parent certificate: %v", err)
	}
	intermediatePriv, intermediateCert, err := generateCert(&x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
	}, intermediateParent, rootPriv, elliptic.P256())
	if err != nil {
		log.Fatalf("failed to generate intermediate certificate: %v", err)
	}
	if err := encodeKeyPair("intermediate", intermediatePriv, intermediateCert); err != nil {
		log.Fatalf("failed to encode intermediate key pair: %v", err)
	}

	parent, err := x509.ParseCertificate(intermediateCert)

	// Generate a server certificate
	if err != nil {
		log.Fatalf("failed to parse parent certificate: %v", err)
	}
	serverPriv, serverCert, err := generateCert(&x509.Certificate{
		SerialNumber:   big.NewInt(3),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour * 3),
		IsCA:           false,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		MaxPathLenZero: true,
		DNSNames:       []string{"localhost", "server"},
	}, parent, intermediatePriv, elliptic.P256())
	if err != nil {
		log.Fatalf("failed to generate client certificate: %v", err)
	}
	if err := encodeKeyPair("server", serverPriv, serverCert); err != nil {
		log.Fatalf("failed to encode client key pair: %v", err)
	}

	// Generate a client certificate
	clientPriv, clientCert, err := generateCert(&x509.Certificate{
		SerialNumber:   big.NewInt(4),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour * 3),
		IsCA:           false,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		MaxPathLenZero: true,
	}, parent, intermediatePriv, elliptic.P256())
	if err != nil {
		log.Fatalf("failed to generate client certificate: %v", err)
	}
	if err := encodeKeyPair("client", clientPriv, clientCert); err != nil {
		log.Fatalf("failed to encode client key pair: %v", err)
	}
}

func generateCert(template *x509.Certificate, parent *x509.Certificate, parentKey crypto.PrivateKey, c elliptic.Curve) (crypto.PrivateKey, []byte, error) {
	privKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	if parent == nil || parentKey == nil {
		if parent != nil || parentKey != nil {
			return nil, nil, fmt.Errorf("parent certificate and key must be provided if either is provided")
		}
		parent = template
		parentKey = privKey
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &privKey.PublicKey, parentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	return privKey, certBytes, nil
}

func encodeKeyPair(name string, privKey crypto.PrivateKey, certBytes []byte) error {
	// Write private key
	ecdsaPriv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not an ECDSA key")
	}
	keyBytes, err := x509.MarshalECPrivateKey(ecdsaPriv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyFile, err := os.Create(fmt.Sprintf("%s.key", name))
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}
	// Write certificate
	certFile, err := os.Create(fmt.Sprintf("%s.crt", name))
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}
	return nil
}
