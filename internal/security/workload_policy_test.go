package security

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

func TestExactWorkloadPolicyBindsTargetSignalAndGrantDigest(t *testing.T) {
	t.Parallel()
	target := model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "checkout"}
	policy, err := NewPolicy(PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment, model.ActionScaleDeployment},
		Workloads: []WorkloadPolicy{{
			Target: target, AllowedActions: []model.ActionKind{model.ActionRestartDeployment},
			AllowedSignalSources: []model.EvidenceSource{model.EvidenceMetrics},
			MaximumReplicas:      4, MaximumReplicaIncrease: 1,
		}},
		PolicyID: "production-v1", RequirePolicyBinding: true,
		MinimumConfidence: .8, MinimumEvidence: 1, MaximumGrantTTL: 2 * time.Minute,
		MaximumReplicas: 20, MaximumReplicaIncrease: 5,
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	if !policy.RequiresBinding() || len(policy.BindingDigest()) != 64 {
		t.Fatalf("policy binding = (%v, %q), want required SHA-256", policy.RequiresBinding(), policy.BindingDigest())
	}
	if !policy.AllowsSignal(target, model.EvidenceMetrics) {
		t.Fatal("exact metric signal was not allowed")
	}
	if policy.AllowsSignal(target, model.EvidenceLogs) {
		t.Fatal("untrusted log signal was allowed")
	}
	other := target
	other.Name = "payments"
	if policy.AllowsSignal(other, model.EvidenceMetrics) {
		t.Fatal("unlisted workload signal was allowed")
	}

	now := time.Date(2026, 10, 2, 1, 2, 3, 0, time.UTC)
	grant := testGrant(now)
	grant.Action.Target = target
	grant.Action.Kind = model.ActionRestartDeployment
	grant.Action.Parameters.Replicas = nil
	grant.PolicyDigest = policy.BindingDigest()
	grant.Signature = model.GrantSignature{Algorithm: model.SignatureAlgorithmEd25519, KeyID: "monitor-v1", Value: "test-signature"}
	if decision := policy.Authorize(grant, now); !decision.Allowed {
		t.Fatalf("Authorize() denied exact bound grant: %s", decision.Reason)
	}
	grant.PolicyDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if decision := policy.Authorize(grant, now); decision.Allowed || decision.Code != model.CodePolicyDenied {
		t.Fatalf("Authorize() drift decision = %+v, want policy denial", decision)
	}
	grant.PolicyDigest = policy.BindingDigest()
	grant.Action.Target = other
	if decision := policy.Authorize(grant, now); decision.Allowed || decision.Code != model.CodeOutOfScope {
		t.Fatalf("Authorize() unlisted target decision = %+v, want out of scope", decision)
	}
}

func TestLoadWorkloadPolicyIsStrictAndBounded(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	validPath := filepath.Join(directory, "policy.json")
	valid := `{"schema_version":"aegissre.io/workload-policy/v1","policy_id":"laboratory-canary-v1","workloads":[{"target":{"api_version":"apps/v1","kind":"Deployment","namespace":"outage-arena","name":"aegis-canary"},"allowed_actions":["restart_deployment"],"allowed_signal_sources":["metrics"],"maximum_replicas":2,"maximum_replica_increase":1}]}`
	if err := os.WriteFile(validPath, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := LoadWorkloadPolicy(validPath)
	if err != nil {
		t.Fatalf("LoadWorkloadPolicy() error = %v", err)
	}
	if document.PolicyID != "laboratory-canary-v1" || len(document.Workloads) != 1 {
		t.Fatalf("document = %+v", document)
	}

	unknownPath := filepath.Join(directory, "unknown.json")
	if err := os.WriteFile(unknownPath, []byte(valid[:len(valid)-1]+`,"allow_all":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWorkloadPolicy(unknownPath); err == nil {
		t.Fatal("LoadWorkloadPolicy() accepted an unknown field")
	}
}
