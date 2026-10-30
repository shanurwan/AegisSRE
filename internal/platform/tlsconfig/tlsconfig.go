// Package tlsconfig builds the mutually authenticated TLS configurations used
// at AegisSRE's internal transport boundaries.
package tlsconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxCredentialFileSize = 1 << 20

// Files identifies one workload's leaf certificate, private key, and the
// independent CA bundle it trusts. The CA bundle must not be read from another
// workload's leaf-certificate Secret because that would also expose its key.
type Files struct {
	Certificate string
	PrivateKey  string
	CA          string
	// Identity is the exact URI SAN expected in this workload's own leaf
	// certificate. Requiring it prevents a valid certificate for another
	// AegisSRE role from being mounted under the wrong Deployment.
	Identity string
}

// LoadServer returns a TLS 1.3 configuration that requires and verifies a
// client certificate. HTTP-level authorization must additionally restrict the
// verified certificate's URI SAN to the exact workload roles allowed at the
// endpoint.
func LoadServer(files Files) (*tls.Config, error) {
	certificate, leaf, err := loadCertificate(files)
	if err != nil {
		return nil, err
	}
	if err := requireUsage(leaf, x509.ExtKeyUsageServerAuth); err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	clientCAs, err := loadCAPool(files.CA)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

// LoadClient returns a TLS 1.3 configuration with a client certificate. The
// normal Go verifier still validates the server DNS/IP name and chain; the
// additional callback binds that certificate to one exact workload URI SAN.
func LoadClient(files Files, expectedServerIdentity string) (*tls.Config, error) {
	expected, err := validateIdentity(expectedServerIdentity)
	if err != nil {
		return nil, fmt.Errorf("expected server identity: %w", err)
	}
	certificate, leaf, err := loadCertificate(files)
	if err != nil {
		return nil, err
	}
	if err := requireUsage(leaf, x509.ExtKeyUsageClientAuth); err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	roots, err := loadCAPool(files.CA)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
		VerifyConnection: func(state tls.ConnectionState) error {
			identity, err := VerifiedPeerIdentity(state)
			if err != nil {
				return err
			}
			if identity != expected {
				return errors.New("TLS peer workload identity is not trusted")
			}
			return nil
		},
	}, nil
}

// VerifiedPeerIdentity extracts the one exact URI SAN from a certificate chain
// already verified by crypto/tls. PeerCertificates alone is deliberately not
// accepted because it says nothing about trust in the issuer.
func VerifiedPeerIdentity(state tls.ConnectionState) (string, error) {
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", errors.New("TLS peer certificate chain was not verified")
	}
	return CertificateIdentity(state.VerifiedChains[0][0])
}

// CertificateIdentity returns a certificate's sole, canonical workload URI
// SAN. Multiple identities, URI decorations, relative URIs, and identity via a
// Common Name are rejected to avoid ambiguous authorization.
func CertificateIdentity(certificate *x509.Certificate) (string, error) {
	if certificate == nil {
		return "", errors.New("TLS peer certificate is missing")
	}
	if len(certificate.URIs) != 1 {
		return "", errors.New("TLS peer certificate must contain exactly one URI SAN")
	}
	identity := certificate.URIs[0]
	if identity == nil || identity.Scheme == "" ||
		identity.User != nil || identity.RawQuery != "" || identity.Fragment != "" {
		return "", errors.New("TLS peer certificate URI SAN is not a workload identity")
	}
	value := identity.String()
	if _, err := validateIdentity(value); err != nil {
		return "", fmt.Errorf("TLS peer certificate URI SAN: %w", err)
	}
	return value, nil
}

func validateIdentity(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 512 {
		return "", errors.New("workload identity URI is invalid")
	}
	identity, err := url.Parse(value)
	if err != nil || identity.Scheme == "" || identity.User != nil ||
		identity.RawQuery != "" || identity.Fragment != "" || identity.String() != value {
		return "", errors.New("workload identity URI is invalid")
	}
	return value, nil
}

func loadCertificate(files Files) (tls.Certificate, *x509.Certificate, error) {
	if strings.TrimSpace(files.Certificate) == "" || strings.TrimSpace(files.PrivateKey) == "" {
		return tls.Certificate{}, nil, errors.New("TLS certificate and private-key files are required")
	}
	expectedIdentity, err := validateIdentity(files.Identity)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("local workload identity: %w", err)
	}
	certificatePEM, err := readBounded(files.Certificate)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("read TLS certificate: %w", err)
	}
	privateKeyPEM, err := readBounded(files.PrivateKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("read TLS private key: %w", err)
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("TLS certificate and private key are invalid or do not match")
	}
	if len(pair.Certificate) == 0 {
		return tls.Certificate{}, nil, errors.New("TLS certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, errors.New("TLS leaf certificate is invalid")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return tls.Certificate{}, nil, errors.New("TLS leaf certificate is outside its validity interval")
	}
	identity, err := CertificateIdentity(leaf)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if identity != expectedIdentity {
		return tls.Certificate{}, nil, errors.New("TLS leaf certificate does not match the configured workload identity")
	}
	pair.Leaf = leaf
	return pair, leaf, nil
}

func requireUsage(certificate *x509.Certificate, required x509.ExtKeyUsage) error {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == required || usage == x509.ExtKeyUsageAny {
			return nil
		}
	}
	return errors.New("required extended key usage is missing")
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("TLS CA bundle file is required")
	}
	data, err := readBounded(path)
	if err != nil {
		return nil, fmt.Errorf("read TLS CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	remaining := data
	count := 0
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			if len(bytes.TrimSpace(remaining)) != 0 {
				return nil, errors.New("TLS CA bundle contains invalid PEM data")
			}
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("TLS CA bundle contains a non-certificate PEM block")
		}
		certificates, err := x509.ParseCertificates(block.Bytes)
		if err != nil || len(certificates) != 1 {
			return nil, errors.New("TLS CA bundle contains an invalid certificate")
		}
		certificate := certificates[0]
		if !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("TLS CA bundle contains a certificate that is not a signing CA")
		}
		pool.AddCert(certificate)
		count++
	}
	if count == 0 {
		return nil, errors.New("TLS CA bundle contains no certificates")
	}
	return pool, nil
}

func readBounded(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxCredentialFileSize {
		return nil, errors.New("credential file is empty, oversized, or not regular")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path, never request input
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxCredentialFileSize {
		return nil, errors.New("credential file is empty or oversized")
	}
	return data, nil
}
