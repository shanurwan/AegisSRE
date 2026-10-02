package security

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

const (
	PublicKeyringVersion = "v1"
	maxTrustedPublicKeys = 16
	maxPublicKeyringSize = 64 << 10
	maxVerificationKeyID = 128
)

// PublicKeyRecord is one entry in the strict public verification keyring wire
// format. PublicKey is a base64-encoded Ed25519 public key.
type PublicKeyRecord struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type publicKeyringDocument struct {
	Version string            `json:"version"`
	Keys    []PublicKeyRecord `json:"keys"`
}

// KeyringVerifier supports an overlap window during signing-key rotation. It
// selects a public key only by the signed object's exact key ID and never falls
// back to another key, an embedded key, or a default key.
type KeyringVerifier struct {
	keys     map[string]ed25519.PublicKey
	audience model.AgentID
}

// NewKeyringVerifier defensively copies a bounded set of trusted keys.
func NewKeyringVerifier(keys map[string]ed25519.PublicKey, audience model.AgentID) (*KeyringVerifier, error) {
	if audience != model.AgentOperator && audience != model.AgentMCPAction {
		return nil, model.NewError(model.CodeInvalidInput, "verifier audience must be operator or MCP action")
	}
	if len(keys) == 0 || len(keys) > maxTrustedPublicKeys {
		return nil, model.NewError(model.CodeInvalidInput, "verification keyring size is outside its safe bound")
	}
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, key := range keys {
		if !validVerificationKeyID(keyID) || len(key) != ed25519.PublicKeySize {
			return nil, model.NewError(model.CodeInvalidInput, "verification keyring contains an invalid key")
		}
		keyCopy := make(ed25519.PublicKey, len(key))
		copy(keyCopy, key)
		copied[keyID] = keyCopy
	}
	return &KeyringVerifier{keys: copied, audience: audience}, nil
}

// Verify implements ports.GrantVerifier.
func (v *KeyringVerifier) Verify(grant model.DelegationGrant, now time.Time) error {
	if v == nil {
		return model.NewError(model.CodeInvalidInput, "verifier is required")
	}
	if err := grant.ValidateSigned(); err != nil {
		return err
	}
	key, trusted := v.keys[grant.Signature.KeyID]
	if !trusted {
		return model.NewError(model.CodeInvalidSignature, "delegation grant key ID is not trusted")
	}
	return VerifyGrant(key, grant.Signature.KeyID, v.audience, grant, now)
}

// VerifyReportRequest implements ports.ReportRequestVerifier. Report requests
// remain domain-separated from grants even when both use the same keyring.
func (v *KeyringVerifier) VerifyReportRequest(request model.IncidentReportRequest, now time.Time) error {
	if v == nil {
		return model.NewError(model.CodeInvalidInput, "verifier is required")
	}
	if err := request.ValidateSigned(); err != nil {
		return err
	}
	key, trusted := v.keys[request.Signature.KeyID]
	if !trusted {
		return model.NewError(model.CodeInvalidSignature, "incident report request key ID is not trusted")
	}
	return VerifyReportRequest(key, request.Signature.KeyID, v.audience, request, now)
}

// ParsePublicKeyringJSON decodes the rotation-safe public key bundle. Unknown
// fields, duplicate IDs, trailing JSON, malformed keys, and oversized bundles
// fail closed. Error messages never include public-key material.
func ParsePublicKeyringJSON(data []byte) (map[string]ed25519.PublicKey, error) {
	if len(data) == 0 || len(data) > maxPublicKeyringSize {
		return nil, errors.New("public verification keyring size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document publicKeyringDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("public verification keyring JSON is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("public verification keyring has trailing JSON")
	}
	if document.Version != PublicKeyringVersion {
		return nil, errors.New("public verification keyring version is unsupported")
	}
	if len(document.Keys) == 0 || len(document.Keys) > maxTrustedPublicKeys {
		return nil, errors.New("public verification keyring size is outside its safe bound")
	}
	keys := make(map[string]ed25519.PublicKey, len(document.Keys))
	for _, record := range document.Keys {
		if !validVerificationKeyID(record.KeyID) {
			return nil, errors.New("public verification keyring contains an invalid key ID")
		}
		if _, duplicate := keys[record.KeyID]; duplicate {
			return nil, errors.New("public verification keyring contains a duplicate key ID")
		}
		key, err := ParsePublicKeyBase64(record.PublicKey)
		if err != nil {
			return nil, errors.New("public verification keyring contains an invalid Ed25519 key")
		}
		keys[record.KeyID] = key
	}
	return keys, nil
}

// LoadPublicKeyringFile reads a regular, bounded file and parses it strictly.
func LoadPublicKeyringFile(path string) (map[string]ed25519.PublicKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("public verification keyring file is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read public verification keyring: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPublicKeyringSize {
		return nil, errors.New("public verification keyring file is empty, oversized, or not regular")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public verification keyring: %w", err)
	}
	return ParsePublicKeyringJSON(data)
}

func validVerificationKeyID(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxVerificationKeyID {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}
