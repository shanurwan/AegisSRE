package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

const (
	grantSignatureDomain  = "AegisSRE/delegation-grant/v1\x00"
	maxCanonicalGrantSize = 64 << 10
)

// CanonicalGrantBytes returns the only byte representation AegisSRE signs.
// Signature fields are excluded, audience ordering is normalized, and all
// timestamps are normalized to UTC. The schema deliberately avoids maps and
// floating point action parameters so encoding/json is deterministic here.
func CanonicalGrantBytes(grant model.DelegationGrant) ([]byte, error) {
	grant = normalizeGrant(grant)
	grant.Signature = model.GrantSignature{}
	if err := grant.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(grant)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical delegation grant: %w", err)
	}
	if len(data) > maxCanonicalGrantSize {
		return nil, model.NewError(model.CodeInvalidInput, "canonical delegation grant exceeds size limit")
	}
	return data, nil
}

func normalizeGrant(grant model.DelegationGrant) model.DelegationGrant {
	grant.IssuedAt = grant.IssuedAt.UTC()
	grant.NotBefore = grant.NotBefore.UTC()
	grant.ExpiresAt = grant.ExpiresAt.UTC()
	grant.Audiences = append([]model.AgentID(nil), grant.Audiences...)
	sort.Slice(grant.Audiences, func(i, j int) bool { return grant.Audiences[i] < grant.Audiences[j] })
	return grant
}

func signatureInput(keyID string, canonical []byte) []byte {
	input := make([]byte, 0, len(grantSignatureDomain)+len(keyID)+1+len(canonical))
	input = append(input, grantSignatureDomain...)
	input = append(input, keyID...)
	input = append(input, 0)
	input = append(input, canonical...)
	return input
}

// SignGrant signs an exact canonical grant and returns a signed copy.
func SignGrant(privateKey ed25519.PrivateKey, keyID string, grant model.DelegationGrant) (model.DelegationGrant, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return model.DelegationGrant{}, model.NewError(model.CodeInvalidInput, "invalid Ed25519 private key length")
	}
	if keyID == "" {
		return model.DelegationGrant{}, model.NewError(model.CodeInvalidInput, "signature key ID is required")
	}
	grant = normalizeGrant(grant)
	canonical, err := CanonicalGrantBytes(grant)
	if err != nil {
		return model.DelegationGrant{}, err
	}
	signature := ed25519.Sign(privateKey, signatureInput(keyID, canonical))
	grant.Signature = model.GrantSignature{
		Algorithm: model.SignatureAlgorithmEd25519,
		KeyID:     keyID,
		Value:     base64.RawURLEncoding.EncodeToString(signature),
	}
	if err := grant.ValidateSigned(); err != nil {
		return model.DelegationGrant{}, err
	}
	return grant, nil
}

// VerifyGrant verifies identity, canonical contents, audience, signature, and
// the grant's validity interval. Policy and replay checks remain independent
// so both Operator and the action MCP server can apply them explicitly.
func VerifyGrant(publicKey ed25519.PublicKey, expectedKeyID string, expectedAudience model.AgentID, grant model.DelegationGrant, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return model.NewError(model.CodeInvalidSignature, "invalid Ed25519 public key length")
	}
	if err := grant.ValidateSigned(); err != nil {
		return err
	}
	if expectedKeyID != "" && grant.Signature.KeyID != expectedKeyID {
		return model.NewError(model.CodeInvalidSignature, "delegation grant key ID is not trusted")
	}
	if !grant.HasAudience(expectedAudience) {
		return model.NewError(model.CodeDelegationRequired, "delegation grant does not include the expected audience")
	}
	if now.IsZero() {
		return model.NewError(model.CodeInvalidInput, "verification time is required")
	}
	now = now.UTC()
	if now.Before(grant.NotBefore) {
		return model.NewError(model.CodeGrantNotYetValid, "delegation grant is not active yet")
	}
	if !now.Before(grant.ExpiresAt) {
		return model.NewError(model.CodeGrantExpired, "delegation grant has expired")
	}
	signature, err := base64.RawURLEncoding.DecodeString(grant.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return model.NewError(model.CodeInvalidSignature, "delegation grant signature encoding is invalid")
	}
	canonical, err := CanonicalGrantBytes(grant)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, signatureInput(grant.Signature.KeyID, canonical), signature) {
		return model.NewError(model.CodeInvalidSignature, "delegation grant signature verification failed")
	}
	return nil
}

// MarshalCanonicalGrant is useful at protocol boundaries that carry the exact
// signed payload separately. It preserves the signed grant object shape while
// rejecting a non-canonical or unknown-field representation on decode.
func MarshalCanonicalGrant(grant model.DelegationGrant) ([]byte, error) {
	grant = normalizeGrant(grant)
	if err := grant.ValidateSigned(); err != nil {
		return nil, err
	}
	return json.Marshal(grant)
}

func UnmarshalCanonicalGrant(data []byte) (model.DelegationGrant, error) {
	if len(data) == 0 || len(data) > maxCanonicalGrantSize {
		return model.DelegationGrant{}, model.NewError(model.CodeInvalidInput, "delegation grant payload size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var grant model.DelegationGrant
	if err := decoder.Decode(&grant); err != nil {
		return model.DelegationGrant{}, model.WrapError(model.CodeInvalidInput, "decode delegation grant", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return model.DelegationGrant{}, model.NewError(model.CodeInvalidInput, "delegation grant has trailing JSON")
	}
	if err := grant.ValidateSigned(); err != nil {
		return model.DelegationGrant{}, err
	}
	encoded, err := MarshalCanonicalGrant(grant)
	if err != nil {
		return model.DelegationGrant{}, fmt.Errorf("re-marshal delegation grant: %w", err)
	}
	if subtle.ConstantTimeCompare(data, encoded) != 1 {
		return model.DelegationGrant{}, model.NewError(model.CodeInvalidInput, "delegation grant JSON is not canonical")
	}
	return grant, nil
}

// Signer implements ports.GrantSigner without exposing private key material.
type Signer struct {
	privateKey ed25519.PrivateKey
	keyID      string
}

func NewSigner(privateKey ed25519.PrivateKey, keyID string) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize || keyID == "" {
		return nil, model.NewError(model.CodeInvalidInput, "valid signing key and key ID are required")
	}
	keyCopy := make(ed25519.PrivateKey, len(privateKey))
	copy(keyCopy, privateKey)
	return &Signer{privateKey: keyCopy, keyID: keyID}, nil
}

func (s *Signer) Sign(grant *model.DelegationGrant) error {
	if s == nil || grant == nil {
		return model.NewError(model.CodeInvalidInput, "signer and delegation grant are required")
	}
	signed, err := SignGrant(s.privateKey, s.keyID, *grant)
	if err != nil {
		return err
	}
	*grant = signed
	return nil
}

// Verifier binds a public key to one service audience.
type Verifier struct {
	publicKey ed25519.PublicKey
	keyID     string
	audience  model.AgentID
}

func NewVerifier(publicKey ed25519.PublicKey, keyID string, audience model.AgentID) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize || keyID == "" {
		return nil, model.NewError(model.CodeInvalidInput, "valid verification key and key ID are required")
	}
	if audience != model.AgentOperator && audience != model.AgentMCPAction {
		return nil, model.NewError(model.CodeInvalidInput, "verifier audience must be operator or MCP action")
	}
	keyCopy := make(ed25519.PublicKey, len(publicKey))
	copy(keyCopy, publicKey)
	return &Verifier{publicKey: keyCopy, keyID: keyID, audience: audience}, nil
}

func (v *Verifier) Verify(grant model.DelegationGrant, now time.Time) error {
	if v == nil {
		return model.NewError(model.CodeInvalidInput, "verifier is required")
	}
	return VerifyGrant(v.publicKey, v.keyID, v.audience, grant, now)
}
