package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMutualTLSAuthenticatesExactWorkloadIdentities(t *testing.T) {
	t.Parallel()
	caCertificate, caKey, caPEM := testCA(t)
	serverFiles := testLeafFiles(t, caCertificate, caKey, caPEM, leafOptions{
		identity: "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-investigator",
		server:   true, dnsNames: []string{"localhost"}, ipAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	})
	clientIdentity := "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-monitor"
	clientFiles := testLeafFiles(t, caCertificate, caKey, caPEM, leafOptions{
		identity: clientIdentity, client: true,
	})

	serverTLS, err := LoadServer(serverFiles)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity, err := VerifiedPeerIdentity(*request.TLS)
		if err != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(writer, identity)
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	clientTLS, err := LoadClient(serverFilesForClient(clientFiles), "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-investigator")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{TLSClientConfig: clientTLS},
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("mutually authenticated request failed: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != clientIdentity {
		t.Fatalf("server observed identity %q, want %q", body, clientIdentity)
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS version = %#v, want TLS 1.3", response.TLS)
	}

	anonymousTLS := clientTLS.Clone()
	anonymousTLS.Certificates = nil
	anonymous := &http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{TLSClientConfig: anonymousTLS},
	}
	anonymousResponse, err := anonymous.Get(server.URL)
	if anonymousResponse != nil {
		anonymousResponse.Body.Close()
	}
	if err == nil {
		t.Fatal("server accepted a client without a certificate")
	}
}

func TestClientRejectsWrongServerWorkloadIdentity(t *testing.T) {
	t.Parallel()
	caCertificate, caKey, caPEM := testCA(t)
	serverFiles := testLeafFiles(t, caCertificate, caKey, caPEM, leafOptions{
		identity: "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-operator",
		server:   true, ipAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	})
	clientFiles := testLeafFiles(t, caCertificate, caKey, caPEM, leafOptions{
		identity: "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-monitor", client: true,
	})
	serverTLS, err := LoadServer(serverFiles)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	clientTLS, err := LoadClient(serverFilesForClient(clientFiles), "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-investigator")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS}}
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "workload identity is not trusted") {
		t.Fatalf("wrong server identity error = %v", err)
	}
}

func TestTLSConfigurationFailsClosed(t *testing.T) {
	t.Parallel()
	caCertificate, caKey, caPEM := testCA(t)
	valid := testLeafFiles(t, caCertificate, caKey, caPEM, leafOptions{
		identity: "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-operator",
		server:   true, client: true,
	})

	t.Run("TLS 1.3 and client certificate required", func(t *testing.T) {
		server, err := LoadServer(valid)
		if err != nil {
			t.Fatal(err)
		}
		if server.MinVersion != tls.VersionTLS13 || server.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatalf("unsafe server TLS config: min=%d client_auth=%d", server.MinVersion, server.ClientAuth)
		}
	})
	t.Run("missing files", func(t *testing.T) {
		if _, err := LoadServer(Files{}); err == nil {
			t.Fatal("missing credential files were accepted")
		}
	})
	t.Run("leaf used as CA", func(t *testing.T) {
		changed := valid
		changed.CA = valid.Certificate
		if _, err := LoadServer(changed); err == nil || !strings.Contains(err.Error(), "not a signing CA") {
			t.Fatalf("leaf CA error = %v", err)
		}
	})
	t.Run("wrong extended usage", func(t *testing.T) {
		clientOnly := testLeafFiles(t, caCertificate, caKey, caPEM, leafOptions{
			identity: "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-operator", client: true,
		})
		if _, err := LoadServer(clientOnly); err == nil || !strings.Contains(err.Error(), "extended key usage") {
			t.Fatalf("server accepted client-only leaf: %v", err)
		}
	})
	t.Run("wrong local workload identity", func(t *testing.T) {
		changed := valid
		changed.Identity = "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-monitor"
		if _, err := LoadServer(changed); err == nil || !strings.Contains(err.Error(), "configured workload identity") {
			t.Fatalf("server accepted a certificate for another role: %v", err)
		}
	})
	t.Run("ambiguous URI SAN", func(t *testing.T) {
		certificate := validCertificate(t, valid.Certificate)
		second, _ := url.Parse("spiffe://aegissre.internal/ns/aegissre-system/sa/attacker")
		certificate.URIs = append(certificate.URIs, second)
		if _, err := CertificateIdentity(certificate); err == nil {
			t.Fatal("certificate with multiple identities was accepted")
		}
	})
	t.Run("unverified peer", func(t *testing.T) {
		if _, err := VerifiedPeerIdentity(tls.ConnectionState{}); err == nil {
			t.Fatal("unverified peer certificate was accepted")
		}
	})
}

type leafOptions struct {
	identity    string
	server      bool
	client      bool
	dnsNames    []string
	ipAddresses []net.IP
}

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AegisSRE test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testLeafFiles(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, caPEM []byte, options leafOptions) Files {
	t.Helper()
	identity, err := url.Parse(options.identity)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var usages []x509.ExtKeyUsage
	if options.server {
		usages = append(usages, x509.ExtKeyUsageServerAuth)
	}
	if options.client {
		usages = append(usages, x509.ExtKeyUsageClientAuth)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "ignored.example"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		URIs: []*url.URL{identity}, DNSNames: options.dnsNames, IPAddresses: options.ipAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "tls.crt")
	privateKeyPath := filepath.Join(directory, "tls.key")
	caPath := filepath.Join(directory, "ca.crt")
	writeTestFile(t, certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeTestFile(t, privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	writeTestFile(t, caPath, caPEM)
	return Files{Certificate: certificatePath, PrivateKey: privateKeyPath, CA: caPath, Identity: options.identity}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func validCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("test certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// Keep the client Files value semantically explicit in call sites where the
// same struct shape is used for a different TLS role.
func serverFilesForClient(files Files) Files { return files }
