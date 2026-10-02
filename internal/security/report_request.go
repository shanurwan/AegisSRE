package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

const (
	reportRequestSignatureDomain  = "AegisSRE/incident-report-request/v2\x00"
	maxCanonicalReportRequestSize = 64 << 10
)

// CanonicalReportRequestBytes returns the only report authorization
// representation AegisSRE signs. Signature material is excluded and times are
// normalized to UTC. The dedicated domain prevents cross-protocol reuse of a
// delegation-grant signature made with the same Monitor key.
func CanonicalReportRequestBytes(request model.IncidentReportRequest) ([]byte, error) {
	request = normalizeReportRequest(request)
	request.Signature = model.ReportRequestSignature{}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical incident report request: %w", err)
	}
	if len(data) > maxCanonicalReportRequestSize {
		return nil, model.NewError(model.CodeInvalidInput, "canonical incident report request exceeds size limit")
	}
	return data, nil
}

func normalizeReportRequest(request model.IncidentReportRequest) model.IncidentReportRequest {
	request.ReportCreatedAt = request.ReportCreatedAt.UTC()
	request.RequestedAt = request.RequestedAt.UTC()
	request.ExpiresAt = request.ExpiresAt.UTC()
	return request
}

func reportRequestSignatureInput(keyID string, canonical []byte) []byte {
	input := make([]byte, 0, len(reportRequestSignatureDomain)+len(keyID)+1+len(canonical))
	input = append(input, reportRequestSignatureDomain...)
	input = append(input, keyID...)
	input = append(input, 0)
	input = append(input, canonical...)
	return input
}

// SignReportRequest authorizes one exact terminal-report request without
// granting any action-plane capability.
func SignReportRequest(privateKey ed25519.PrivateKey, keyID string, request model.IncidentReportRequest) (model.IncidentReportRequest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return model.IncidentReportRequest{}, model.NewError(model.CodeInvalidInput, "invalid Ed25519 private key length")
	}
	if keyID == "" {
		return model.IncidentReportRequest{}, model.NewError(model.CodeInvalidInput, "signature key ID is required")
	}
	request = normalizeReportRequest(request)
	canonical, err := CanonicalReportRequestBytes(request)
	if err != nil {
		return model.IncidentReportRequest{}, err
	}
	signature := ed25519.Sign(privateKey, reportRequestSignatureInput(keyID, canonical))
	request.Signature = model.ReportRequestSignature{
		Algorithm: model.SignatureAlgorithmEd25519,
		KeyID:     keyID,
		Value:     base64.RawURLEncoding.EncodeToString(signature),
	}
	if err := request.ValidateSigned(); err != nil {
		return model.IncidentReportRequest{}, err
	}
	return request, nil
}

// VerifyReportRequest authenticates the Monitor, Operator audience, complete
// request contents, key identity, and bounded validity interval.
func VerifyReportRequest(publicKey ed25519.PublicKey, expectedKeyID string, expectedAudience model.AgentID, request model.IncidentReportRequest, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return model.NewError(model.CodeInvalidSignature, "invalid Ed25519 public key length")
	}
	if err := request.ValidateSigned(); err != nil {
		return err
	}
	if expectedAudience != model.AgentOperator || request.Audience != expectedAudience {
		return model.NewError(model.CodeDelegationRequired, "incident report request does not include the expected audience")
	}
	if expectedKeyID != "" && request.Signature.KeyID != expectedKeyID {
		return model.NewError(model.CodeInvalidSignature, "incident report request key ID is not trusted")
	}
	if now.IsZero() {
		return model.NewError(model.CodeInvalidInput, "verification time is required")
	}
	now = now.UTC()
	if now.Before(request.RequestedAt) {
		return model.NewError(model.CodeGrantNotYetValid, "incident report request is not active yet")
	}
	if !now.Before(request.ExpiresAt) {
		return model.NewError(model.CodeGrantExpired, "incident report request has expired")
	}
	signature, err := base64.RawURLEncoding.DecodeString(request.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return model.NewError(model.CodeInvalidSignature, "incident report request signature encoding is invalid")
	}
	canonical, err := CanonicalReportRequestBytes(request)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, reportRequestSignatureInput(request.Signature.KeyID, canonical), signature) {
		return model.NewError(model.CodeInvalidSignature, "incident report request signature verification failed")
	}
	return nil
}

// SignReportRequest implements ports.ReportRequestSigner while retaining the
// existing, separately domain-separated delegation signing method.
func (s *Signer) SignReportRequest(request *model.IncidentReportRequest) error {
	if s == nil || request == nil {
		return model.NewError(model.CodeInvalidInput, "signer and incident report request are required")
	}
	signed, err := SignReportRequest(s.privateKey, s.keyID, *request)
	if err != nil {
		return err
	}
	*request = signed
	return nil
}

// VerifyReportRequest implements ports.ReportRequestVerifier. A Verifier
// composed for any audience except Operator fails closed.
func (v *Verifier) VerifyReportRequest(request model.IncidentReportRequest, now time.Time) error {
	if v == nil {
		return model.NewError(model.CodeInvalidInput, "verifier is required")
	}
	return VerifyReportRequest(v.publicKey, v.keyID, v.audience, request, now)
}
