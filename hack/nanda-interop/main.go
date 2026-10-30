// Command nanda-interop writes AegisSRE-signed AgentFacts and the matching
// public key, so verify.ts can check them with the NANDA Index's own
// TypeScript signing code. Signatures are only useful to the NANDA ecosystem
// if both implementations agree on the canonical bytes.
//
// usage: go run ./hack/nanda-interop <output-dir>
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shanurwan/AegisSRE/internal/adapters/nanda"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nanda-interop:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: nanda-interop <output-dir>")
	}
	output := os.Args[1]
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	modes := []string{"application/json"}
	// The description holds the characters whose JSON escaping differs
	// between encoding/json and JSON.stringify.
	signed, err := nanda.Sign(nanda.Facts{
		ID: "urn:air:aegis.example.org:agent:investigator", AgentName: "AegisSRE Investigator",
		Label: "AegisSRE Investigator", Version: "0.1.0",
		Description:  "Diagnoses <bounded> & typed \u2028 incidents, café \"quoted\" \\ \t",
		Provider:     nanda.Provider{Name: "AegisSRE", URL: "https://github.com/shanurwan/AegisSRE"},
		Endpoints:    nanda.Endpoints{Static: []string{"https://investigator.aegis.example.org/a2a"}},
		Capabilities: nanda.Capabilities{Modalities: modes, Authentication: nanda.Authentication{Methods: []string{"mtls"}}},
		Skills:       []nanda.Skill{{ID: "investigate-incident", Description: "Diagnose", InputModes: modes, OutputModes: modes}},
	}, private)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}
	// #nosec G703 -- the output directory is this CI tool's own argument.
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	// #nosec G703 -- fixed file names inside the caller's output directory.
	if err := os.WriteFile(filepath.Join(output, "facts.json"), signed, 0o600); err != nil {
		return err
	}
	// #nosec G703 -- fixed file names inside the caller's output directory.
	return os.WriteFile(filepath.Join(output, "public.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
}
