package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

func testGrant(now time.Time) model.DelegationGrant {
	replicas := int32(2)
	return model.DelegationGrant{
		SchemaVersion:       model.SchemaVersionV1,
		GrantID:             "grant-1",
		Issuer:              model.AgentMonitor,
		Audiences:           []model.AgentID{model.AgentMCPAction, model.AgentOperator},
		IncidentID:          "incident-1",
		DiagnosisReportID:   "diagnosis-1",
		DiagnosisDigest:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DiagnosisConfidence: 0.95,
		EvidenceIDs:         []string{"evidence-1", "evidence-2"},
		ProposalID:          "proposal-1",
		Action: model.ActionSpec{
			Kind: model.ActionScaleDeployment,
			Target: model.ResourceTarget{
				APIVersion: "apps/v1", Kind: "Deployment",
				Namespace: "outage-arena", Name: "demo-api",
			},
			Parameters: model.ActionParameters{Replicas: &replicas},
		},
		Preconditions:  model.ActionPreconditions{ResourceVersion: "123", ExpectedReplicas: int32Pointer(1)},
		DryRun:         true,
		IdempotencyKey: "action-1",
		IssuedAt:       now,
		NotBefore:      now,
		ExpiresAt:      now.Add(2 * time.Minute),
	}
}

func int32Pointer(value int32) *int32 { return &value }

func signingKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func TestSignAndVerifyGrantForBothBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := signingKeys(t)
	grant, err := SignGrant(privateKey, "monitor-2026-09", testGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	for _, audience := range []model.AgentID{model.AgentOperator, model.AgentMCPAction} {
		if err := VerifyGrant(publicKey, "monitor-2026-09", audience, grant, now.Add(time.Second)); err != nil {
			t.Fatalf("audience %s rejected valid grant: %v", audience, err)
		}
	}
	*grant.Action.Parameters.Replicas = 3
	if err := VerifyGrant(publicKey, "monitor-2026-09", model.AgentOperator, grant, now.Add(time.Second)); err == nil {
		t.Fatal("tampered exact action unexpectedly verified")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeInvalidSignature {
		t.Fatalf("unexpected tamper error: %v", err)
	}
}

func TestGrantTimeAndAudienceChecks(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := signingKeys(t)
	grant, err := SignGrant(privateKey, "key-1", testGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyGrant(publicKey, "key-1", model.AgentInvestigator, grant, now.Add(time.Second)); err == nil {
		t.Fatal("unexpected audience accepted")
	}
	if err := VerifyGrant(publicKey, "key-1", model.AgentOperator, grant, grant.ExpiresAt); err == nil {
		t.Fatal("grant accepted at exclusive expiry")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeGrantExpired {
		t.Fatalf("unexpected expiry error: %v", err)
	}
}

func TestCanonicalGrantDoesNotDependOnAudienceOrderOrMutateInput(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	left := testGrant(now)
	right := testGrant(now)
	right.Audiences[0], right.Audiences[1] = right.Audiences[1], right.Audiences[0]
	originalFirst := right.Audiences[0]
	leftBytes, err := CanonicalGrantBytes(left)
	if err != nil {
		t.Fatal(err)
	}
	rightBytes, err := CanonicalGrantBytes(right)
	if err != nil {
		t.Fatal(err)
	}
	if string(leftBytes) != string(rightBytes) {
		t.Fatal("canonical bytes vary with audience ordering")
	}
	if right.Audiences[0] != originalFirst {
		t.Fatal("canonicalization mutated caller's grant")
	}
}

func TestBase64KeyParsing(t *testing.T) {
	publicKey, privateKey := signingKeys(t)
	parsedPublic, err := ParsePublicKeyBase64(base64.RawURLEncoding.EncodeToString(publicKey))
	if err != nil || !publicKey.Equal(parsedPublic) {
		t.Fatalf("public key parse failed: %v", err)
	}
	parsedPrivate, err := ParsePrivateKeyBase64(base64.StdEncoding.EncodeToString(privateKey.Seed()))
	if err != nil || !privateKey.Equal(parsedPrivate) {
		t.Fatalf("private seed parse failed: %v", err)
	}
	if _, err := ParsePublicKeyBase64(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("short public key unexpectedly accepted")
	}
}

func TestPolicyFailClosedAndExactProposalBinding(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	_, privateKey := signingKeys(t)
	grant, err := SignGrant(privateKey, "key-1", testGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionScaleDeployment},
		MinimumConfidence: 0.9, MinimumEvidence: 2,
		MaximumGrantTTL: 2 * time.Minute, RequireDryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision := policy.Authorize(grant, now.Add(time.Second)); !decision.Allowed {
		t.Fatalf("valid grant denied: %#v", decision)
	}
	mutation := grant
	mutation.Action.Target.Namespace = "kube-system"
	if decision := policy.Authorize(mutation, now.Add(time.Second)); decision.Allowed || decision.Code != model.CodeOutOfScope {
		t.Fatalf("cross-namespace grant not denied correctly: %#v", decision)
	}
	mutation = grant
	mutation.DryRun = false
	if decision := policy.Authorize(mutation, now.Add(time.Second)); decision.Allowed {
		t.Fatal("non-dry-run grant unexpectedly allowed")
	}

	report := model.DiagnosisReport{
		SchemaVersion: model.SchemaVersionV1, ID: grant.DiagnosisReportID,
		IncidentID: grant.IncidentID, Status: model.DiagnosisConfirmed,
		RootCause: "scaled to zero", Confidence: grant.DiagnosisConfidence,
		EvidenceIDs: append([]string(nil), grant.EvidenceIDs...), CreatedAt: now,
		Proposals: []model.ActionProposal{{
			ID: grant.ProposalID, Action: grant.Action, Rationale: "restore baseline",
			Confidence:      grant.DiagnosisConfidence,
			EvidenceIDs:     append([]string(nil), grant.EvidenceIDs...),
			SuccessCriteria: []string{"one available replica"},
		}},
	}
	if err := report.Seal(); err != nil {
		t.Fatal(err)
	}
	grant.DiagnosisDigest = report.Digest
	grant, err = SignGrant(privateKey, "key-1", grant)
	if err != nil {
		t.Fatal(err)
	}
	if decision := policy.AuthorizeProposal(report, grant, now.Add(time.Second)); !decision.Allowed {
		t.Fatalf("exact proposal binding denied: %#v", decision)
	}
	lowConfidence := report
	lowConfidence.Proposals = append([]model.ActionProposal(nil), report.Proposals...)
	lowConfidence.Proposals[0].Confidence = 0.01
	if err := lowConfidence.Seal(); err != nil {
		t.Fatal(err)
	}
	lowConfidenceGrant := grant
	lowConfidenceGrant.DiagnosisDigest = lowConfidence.Digest
	lowConfidenceGrant, err = SignGrant(privateKey, "key-1", lowConfidenceGrant)
	if err != nil {
		t.Fatal(err)
	}
	if decision := policy.AuthorizeProposal(lowConfidence, lowConfidenceGrant, now.Add(time.Second)); decision.Allowed {
		t.Fatal("low-confidence proposal under a high-confidence diagnosis was allowed")
	}
	*grant.Action.Parameters.Replicas = 3
	if decision := policy.AuthorizeProposal(report, grant, now.Add(time.Second)); decision.Allowed {
		t.Fatal("changed proposal action unexpectedly allowed")
	}
}

func TestPolicyBoundsAutonomousScaling(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	_, privateKey := signingKeys(t)
	grant, err := SignGrant(privateKey, "key-1", testGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionScaleDeployment},
		MinimumConfidence: 0.9, MinimumEvidence: 2,
		MaximumGrantTTL: 2 * time.Minute, RequireDryRun: true,
		MaximumReplicas: 10, MaximumReplicaIncrease: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, replicas := range map[string]int32{
		"scale down":    0,
		"no-op scale":   1,
		"over ceiling":  11,
		"over increase": 5,
	} {
		t.Run(name, func(t *testing.T) {
			candidate := grant
			candidate.Action.Parameters.Replicas = int32Pointer(replicas)
			if decision := policy.Authorize(candidate, now.Add(time.Second)); decision.Allowed {
				t.Fatalf("unsafe replica request %d was allowed", replicas)
			}
		})
	}
	allowed := grant
	allowed.Action.Parameters.Replicas = int32Pointer(4)
	if decision := policy.Authorize(allowed, now.Add(time.Second)); !decision.Allowed {
		t.Fatalf("bounded scale-up was denied: %#v", decision)
	}
	missingPrecondition := grant
	missingPrecondition.Preconditions.ExpectedReplicas = nil
	if decision := policy.Authorize(missingPrecondition, now.Add(time.Second)); decision.Allowed {
		t.Fatal("scale without expected replica precondition was allowed")
	}
}

func TestReplayGuardAllowsExactlyOneConcurrentConsumer(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	guard := NewMemoryReplayGuard()
	const goroutines = 32
	var successes atomic.Int32
	var failures atomic.Int32
	var wait sync.WaitGroup
	wait.Add(goroutines)
	for range goroutines {
		go func() {
			defer wait.Done()
			if err := guard.Consume("grant-1", now.Add(time.Minute), now); err == nil {
				successes.Add(1)
				return
			}
			failures.Add(1)
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || failures.Load() != goroutines-1 {
		t.Fatalf("got %d successes and %d failures", successes.Load(), failures.Load())
	}
	if removed := guard.Purge(now.Add(time.Minute)); removed != 1 || guard.Len() != 0 {
		t.Fatalf("expired replay entry not purged: removed=%d len=%d", removed, guard.Len())
	}
}
