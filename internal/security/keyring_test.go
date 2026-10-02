package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

func TestKeyringVerifierSupportsSafeRotationOverlap(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	oldPublic, oldPrivate := signingKeys(t)
	newPublic, newPrivate := signingKeys(t)
	overlap, err := NewKeyringVerifier(map[string]ed25519.PublicKey{
		"monitor-2026-q3": oldPublic,
		"monitor-2026-q4": newPublic,
	}, model.AgentOperator)
	if err != nil {
		t.Fatal(err)
	}

	oldGrant, err := SignGrant(oldPrivate, "monitor-2026-q3", testGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	newGrant := testGrant(now)
	newGrant.GrantID = "grant-new"
	newGrant.IdempotencyKey = "action-new"
	newGrant, err = SignGrant(newPrivate, "monitor-2026-q4", newGrant)
	if err != nil {
		t.Fatal(err)
	}
	for name, grant := range map[string]model.DelegationGrant{"old": oldGrant, "new": newGrant} {
		if err := overlap.Verify(grant, now.Add(time.Second)); err != nil {
			t.Fatalf("%s grant rejected during overlap: %v", name, err)
		}
	}

	oldReport, err := SignReportRequest(oldPrivate, "monitor-2026-q3", testReportRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	newReport := testReportRequest(now)
	newReport.RequestID = "report-request-new"
	newReport, err = SignReportRequest(newPrivate, "monitor-2026-q4", newReport)
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]model.IncidentReportRequest{"old": oldReport, "new": newReport} {
		if err := overlap.VerifyReportRequest(request, now.Add(time.Second)); err != nil {
			t.Fatalf("%s report request rejected during overlap: %v", name, err)
		}
	}

	newOnly, err := NewKeyringVerifier(map[string]ed25519.PublicKey{"monitor-2026-q4": newPublic}, model.AgentOperator)
	if err != nil {
		t.Fatal(err)
	}
	if err := newOnly.Verify(newGrant, now.Add(time.Second)); err != nil {
		t.Fatalf("new grant rejected after rotation: %v", err)
	}
	if err := newOnly.Verify(oldGrant, now.Add(time.Second)); errorCode(err) != model.CodeInvalidSignature {
		t.Fatalf("retired grant error=%v, want %s", err, model.CodeInvalidSignature)
	}
	if err := newOnly.VerifyReportRequest(oldReport, now.Add(time.Second)); errorCode(err) != model.CodeInvalidSignature {
		t.Fatalf("retired report request error=%v, want %s", err, model.CodeInvalidSignature)
	}
}

func TestKeyringVerifierRejectsUnknownKeyWithoutFallback(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	trustedPublic, _ := signingKeys(t)
	_, attackerPrivate := signingKeys(t)
	verifier, err := NewKeyringVerifier(
		map[string]ed25519.PublicKey{"trusted-key": trustedPublic},
		model.AgentOperator,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := SignGrant(attackerPrivate, "attacker-key", testGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	err = verifier.Verify(grant, now.Add(time.Second))
	if errorCode(err) != model.CodeInvalidSignature || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("unknown-key error=%v", err)
	}
}

func TestKeyringVerifierDefensivelyCopiesKeys(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	publicKey, privateKey := signingKeys(t)
	input := map[string]ed25519.PublicKey{"key-1": publicKey}
	verifier, err := NewKeyringVerifier(input, model.AgentOperator)
	if err != nil {
		t.Fatal(err)
	}
	for index := range publicKey {
		publicKey[index] = 0
	}
	delete(input, "key-1")
	grant, err := SignGrant(privateKey, "key-1", testGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(grant, now.Add(time.Second)); err != nil {
		t.Fatalf("mutating constructor input changed verifier: %v", err)
	}
}

func TestParsePublicKeyringJSONIsStrictAndBounded(t *testing.T) {
	t.Parallel()
	publicKey, _ := signingKeys(t)
	encoded := base64.RawStdEncoding.EncodeToString(publicKey)
	valid := fmt.Sprintf(`{"version":"v1","keys":[{"key_id":"key-old","public_key":"%s"},{"key_id":"key-new","public_key":"%s"}]}`, encoded, encoded)
	keys, err := ParsePublicKeyringJSON([]byte(valid))
	if err != nil || len(keys) != 2 {
		t.Fatalf("valid keyring keys=%d error=%v", len(keys), err)
	}

	tests := map[string]string{
		"empty":         `{"version":"v1","keys":[]}`,
		"unknown field": fmt.Sprintf(`{"version":"v1","keys":[{"key_id":"key","public_key":"%s","extra":true}]}`, encoded),
		"duplicate ID":  fmt.Sprintf(`{"version":"v1","keys":[{"key_id":"same","public_key":"%s"},{"key_id":"same","public_key":"%s"}]}`, encoded, encoded),
		"bad key":       `{"version":"v1","keys":[{"key_id":"key","public_key":"not-a-key"}]}`,
		"unsafe key ID": fmt.Sprintf(`{"version":"v1","keys":[{"key_id":"key\nvalue","public_key":"%s"}]}`, encoded),
		"trailing JSON": valid + `{}`,
		"wrong version": strings.Replace(valid, `"v1"`, `"v2"`, 1),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicKeyringJSON([]byte(document)); err == nil {
				t.Fatal("invalid keyring was accepted")
			}
		})
	}
	if _, err := ParsePublicKeyringJSON(make([]byte, maxPublicKeyringSize+1)); err == nil {
		t.Fatal("oversized keyring was accepted")
	}
}

func TestLoadPublicKeyringFile(t *testing.T) {
	t.Parallel()
	publicKey, _ := signingKeys(t)
	document := fmt.Sprintf(`{"version":"v1","keys":[{"key_id":"key-1","public_key":"%s"}]}`,
		base64.RawStdEncoding.EncodeToString(publicKey))
	path := filepath.Join(t.TempDir(), "trusted-public-keys.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadPublicKeyringFile(path)
	if err != nil || len(keys) != 1 {
		t.Fatalf("loaded keys=%d error=%v", len(keys), err)
	}
	if _, err := LoadPublicKeyringFile(""); err == nil {
		t.Fatal("empty keyring path was accepted")
	}
}

func TestNewKeyringVerifierRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	publicKey, _ := signingKeys(t)
	if _, err := NewKeyringVerifier(nil, model.AgentOperator); err == nil {
		t.Fatal("empty keyring was accepted")
	}
	if _, err := NewKeyringVerifier(map[string]ed25519.PublicKey{"bad/key": publicKey}, model.AgentOperator); err == nil {
		t.Fatal("unsafe key ID was accepted")
	}
	if _, err := NewKeyringVerifier(map[string]ed25519.PublicKey{"key": publicKey}, model.AgentInvestigator); err == nil {
		t.Fatal("invalid verifier audience was accepted")
	}
}

func errorCode(err error) model.ErrorCode {
	code, _ := model.ErrorCodeOf(err)
	return code
}
