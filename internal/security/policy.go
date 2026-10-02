package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

type PolicyConfig struct {
	AllowedNamespaces      []string
	AllowedActions         []model.ActionKind
	Workloads              []WorkloadPolicy
	PolicyID               string
	RequirePolicyBinding   bool
	MinimumConfidence      float64
	MinimumEvidence        int
	MaximumGrantTTL        time.Duration
	RequireDryRun          bool
	MaximumReplicas        int32
	MaximumReplicaIncrease int32
}

// Policy is immutable after construction and safe for concurrent use.
type Policy struct {
	allowedNamespaces      map[string]struct{}
	allowedActions         map[model.ActionKind]struct{}
	minimumConfidence      float64
	minimumEvidence        int
	maximumGrantTTL        time.Duration
	requireDryRun          bool
	maximumReplicas        int32
	maximumReplicaIncrease int32
	workloads              map[string]workloadRule
	policyID               string
	digest                 string
	requirePolicyBinding   bool
}

type workloadRule struct {
	actions                map[model.ActionKind]struct{}
	signals                map[model.EvidenceSource]struct{}
	maximumReplicas        int32
	maximumReplicaIncrease int32
}

func NewPolicy(config PolicyConfig) (*Policy, error) {
	if len(config.AllowedNamespaces) == 0 || len(config.AllowedActions) == 0 {
		return nil, model.NewError(model.CodeInvalidInput, "policy must allow at least one namespace and action")
	}
	if math.IsNaN(config.MinimumConfidence) || config.MinimumConfidence < 0 || config.MinimumConfidence > 1 {
		return nil, model.NewError(model.CodeInvalidInput, "minimum confidence must be between 0 and 1")
	}
	if config.MinimumEvidence < 1 {
		return nil, model.NewError(model.CodeInvalidInput, "minimum evidence must be positive")
	}
	if config.MaximumGrantTTL <= 0 || config.MaximumGrantTTL > 5*time.Minute {
		return nil, model.NewError(model.CodeInvalidInput, "maximum grant TTL must be positive and no more than five minutes")
	}
	maximumReplicas := config.MaximumReplicas
	if maximumReplicas == 0 {
		maximumReplicas = 20
	}
	maximumReplicaIncrease := config.MaximumReplicaIncrease
	if maximumReplicaIncrease == 0 {
		maximumReplicaIncrease = 5
	}
	if maximumReplicas < 1 || maximumReplicaIncrease < 1 || maximumReplicaIncrease > maximumReplicas {
		return nil, model.NewError(model.CodeInvalidInput, "replica policy bounds are invalid")
	}
	policy := &Policy{
		allowedNamespaces:      make(map[string]struct{}, len(config.AllowedNamespaces)),
		allowedActions:         make(map[model.ActionKind]struct{}, len(config.AllowedActions)),
		minimumConfidence:      config.MinimumConfidence,
		minimumEvidence:        config.MinimumEvidence,
		maximumGrantTTL:        config.MaximumGrantTTL,
		requireDryRun:          config.RequireDryRun,
		maximumReplicas:        maximumReplicas,
		maximumReplicaIncrease: maximumReplicaIncrease,
		workloads:              make(map[string]workloadRule, len(config.Workloads)),
		policyID:               strings.TrimSpace(config.PolicyID),
		requirePolicyBinding:   config.RequirePolicyBinding || len(config.Workloads) > 0,
	}
	for _, namespace := range config.AllowedNamespaces {
		namespace = strings.TrimSpace(namespace)
		if namespace == "" {
			return nil, model.NewError(model.CodeInvalidInput, "allowed namespace is empty")
		}
		policy.allowedNamespaces[namespace] = struct{}{}
	}
	for _, action := range config.AllowedActions {
		if !action.Valid() {
			return nil, model.NewError(model.CodeInvalidInput, "allowed action is invalid")
		}
		policy.allowedActions[action] = struct{}{}
	}
	for _, configured := range config.Workloads {
		if err := configured.Validate(); err != nil {
			return nil, err
		}
		key := configured.Target.Key()
		if _, duplicate := policy.workloads[key]; duplicate {
			return nil, model.NewError(model.CodeInvalidInput, "workload policy contains a duplicate target")
		}
		rule := workloadRule{
			actions:                make(map[model.ActionKind]struct{}, len(configured.AllowedActions)),
			signals:                make(map[model.EvidenceSource]struct{}, len(configured.AllowedSignalSources)),
			maximumReplicas:        configured.MaximumReplicas,
			maximumReplicaIncrease: configured.MaximumReplicaIncrease,
		}
		for _, action := range configured.AllowedActions {
			rule.actions[action] = struct{}{}
		}
		for _, source := range configured.AllowedSignalSources {
			rule.signals[source] = struct{}{}
		}
		policy.workloads[key] = rule
	}
	digest, err := effectivePolicyDigest(config, maximumReplicas, maximumReplicaIncrease)
	if err != nil {
		return nil, err
	}
	policy.digest = digest
	return policy, nil
}

// Authorize evaluates the signed claims but does not cryptographically verify
// them. Call Verifier.Verify first at each trust boundary.
func (p *Policy) Authorize(grant model.DelegationGrant, now time.Time) model.PolicyDecision {
	if p == nil {
		return model.Deny(model.CodePolicyDenied, "policy is unavailable")
	}
	if err := grant.ValidateSigned(); err != nil {
		code, ok := model.ErrorCodeOf(err)
		if !ok {
			code = model.CodePolicyDenied
		}
		return model.Deny(code, err.Error())
	}
	if now.IsZero() {
		return model.Deny(model.CodeInvalidInput, "authorization time is required")
	}
	now = now.UTC()
	if now.Before(grant.NotBefore) {
		return model.Deny(model.CodeGrantNotYetValid, "delegation grant is not active yet")
	}
	if !now.Before(grant.ExpiresAt) {
		return model.Deny(model.CodeGrantExpired, "delegation grant has expired")
	}
	if ttl := grant.ExpiresAt.Sub(grant.IssuedAt); ttl <= 0 || ttl > p.maximumGrantTTL {
		return model.Deny(model.CodePolicyDenied, fmt.Sprintf("grant TTL %s exceeds policy", ttl))
	}
	if p.requirePolicyBinding && grant.PolicyDigest != p.digest {
		return model.Deny(model.CodePolicyDenied, "delegation grant policy digest does not match the active workload policy")
	}
	if _, ok := p.allowedNamespaces[grant.Action.Target.Namespace]; !ok {
		return model.Deny(model.CodeOutOfScope, "target namespace is not allowed")
	}
	if _, ok := p.allowedActions[grant.Action.Kind]; !ok {
		return model.Deny(model.CodePolicyDenied, "action is not allowed")
	}
	maximumReplicas := p.maximumReplicas
	maximumReplicaIncrease := p.maximumReplicaIncrease
	if len(p.workloads) > 0 {
		rule, ok := p.workloads[grant.Action.Target.Key()]
		if !ok {
			return model.Deny(model.CodeOutOfScope, "target is not present in the exact workload policy")
		}
		if _, ok := rule.actions[grant.Action.Kind]; !ok {
			return model.Deny(model.CodePolicyDenied, "action is not allowed for the exact workload")
		}
		maximumReplicas = rule.maximumReplicas
		maximumReplicaIncrease = rule.maximumReplicaIncrease
	}
	if strings.TrimSpace(grant.Preconditions.ResourceVersion) == "" {
		return model.Deny(model.CodePolicyDenied, "mutation requires a resourceVersion precondition")
	}
	if grant.Action.Kind == model.ActionScaleDeployment {
		if grant.Action.Parameters.Replicas == nil || grant.Preconditions.ExpectedReplicas == nil {
			return model.Deny(model.CodePolicyDenied, "scale action requires an expected replica precondition")
		}
		requested := *grant.Action.Parameters.Replicas
		expected := *grant.Preconditions.ExpectedReplicas
		if requested <= expected {
			return model.Deny(model.CodePolicyDenied, "autonomous scaling must increase the expected replica count")
		}
		if requested > maximumReplicas || requested-expected > maximumReplicaIncrease {
			return model.Deny(model.CodePolicyDenied, "scale action exceeds replica policy bounds")
		}
	}
	if grant.DiagnosisConfidence < p.minimumConfidence {
		return model.Deny(model.CodePolicyDenied, "diagnosis confidence is below policy")
	}
	if len(grant.EvidenceIDs) < p.minimumEvidence {
		return model.Deny(model.CodePolicyDenied, "evidence count is below policy")
	}
	if p.requireDryRun && !grant.DryRun {
		return model.Deny(model.CodePolicyDenied, "policy requires dry-run")
	}
	return model.Allow()
}

// BindingDigest is the SHA-256 digest Monitor seals into grants when exact
// workload policy is enabled. Operator and action MCP independently require
// the same digest before authorizing a side effect.
func (p *Policy) BindingDigest() string {
	if p == nil {
		return ""
	}
	return p.digest
}

// RequiresBinding reports whether grants without the exact effective policy
// digest must be rejected. Legacy in-memory fixture policies remain usable
// only when no exact workload list was configured.
func (p *Policy) RequiresBinding() bool {
	return p != nil && p.requirePolicyBinding
}

// AllowsSignal ensures a Monitor sample belongs to a configured target and
// that the signal source is trusted for autonomous coordination.
func (p *Policy) AllowsSignal(target model.ResourceTarget, source model.EvidenceSource) bool {
	if p == nil || !source.Valid() {
		return false
	}
	if len(p.workloads) == 0 {
		_, allowed := p.allowedNamespaces[target.Namespace]
		return allowed
	}
	rule, ok := p.workloads[target.Key()]
	if !ok {
		return false
	}
	_, allowed := rule.signals[source]
	return allowed
}

type effectivePolicy struct {
	PolicyID               string             `json:"policy_id,omitempty"`
	AllowedNamespaces      []string           `json:"allowed_namespaces"`
	AllowedActions         []model.ActionKind `json:"allowed_actions"`
	Workloads              []WorkloadPolicy   `json:"workloads,omitempty"`
	MinimumConfidence      float64            `json:"minimum_confidence"`
	MinimumEvidence        int                `json:"minimum_evidence"`
	MaximumGrantTTL        string             `json:"maximum_grant_ttl"`
	RequireDryRun          bool               `json:"require_dry_run"`
	MaximumReplicas        int32              `json:"maximum_replicas"`
	MaximumReplicaIncrease int32              `json:"maximum_replica_increase"`
}

func effectivePolicyDigest(config PolicyConfig, maximumReplicas, maximumReplicaIncrease int32) (string, error) {
	value := effectivePolicy{
		PolicyID:          strings.TrimSpace(config.PolicyID),
		AllowedNamespaces: append([]string(nil), config.AllowedNamespaces...),
		AllowedActions:    append([]model.ActionKind(nil), config.AllowedActions...),
		Workloads:         cloneWorkloadPolicies(config.Workloads),
		MinimumConfidence: config.MinimumConfidence, MinimumEvidence: config.MinimumEvidence,
		MaximumGrantTTL: config.MaximumGrantTTL.String(), RequireDryRun: config.RequireDryRun,
		MaximumReplicas: maximumReplicas, MaximumReplicaIncrease: maximumReplicaIncrease,
	}
	for index := range value.AllowedNamespaces {
		value.AllowedNamespaces[index] = strings.TrimSpace(value.AllowedNamespaces[index])
	}
	slices.Sort(value.AllowedNamespaces)
	slices.Sort(value.AllowedActions)
	slices.SortFunc(value.Workloads, func(left, right WorkloadPolicy) int {
		return strings.Compare(left.Target.Key(), right.Target.Key())
	})
	for index := range value.Workloads {
		slices.Sort(value.Workloads[index].AllowedActions)
		slices.Sort(value.Workloads[index].AllowedSignalSources)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal effective workload policy: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// AuthorizeProposal ensures the grant is an exact delegation of a sealed
// diagnosis proposal before applying the runtime policy.
func (p *Policy) AuthorizeProposal(report model.DiagnosisReport, grant model.DelegationGrant, now time.Time) model.PolicyDecision {
	if err := report.VerifyDigest(); err != nil {
		return model.Deny(model.CodePolicyDenied, err.Error())
	}
	if report.Status != model.DiagnosisConfirmed || report.IncidentID != grant.IncidentID ||
		report.ID != grant.DiagnosisReportID || report.Digest != grant.DiagnosisDigest ||
		report.Confidence != grant.DiagnosisConfidence {
		return model.Deny(model.CodePolicyDenied, "grant is not bound to the diagnosis report")
	}
	proposal, ok := report.Proposal(grant.ProposalID)
	if !ok || !proposal.Action.Equal(grant.Action) {
		return model.Deny(model.CodePolicyDenied, "grant action does not exactly match its proposal")
	}
	if proposal.Confidence < p.minimumConfidence {
		return model.Deny(model.CodePolicyDenied, "proposal confidence is below policy")
	}
	if !sameStringSet(proposal.EvidenceIDs, grant.EvidenceIDs) {
		return model.Deny(model.CodePolicyDenied, "grant evidence does not exactly match its proposal")
	}
	return p.Authorize(grant, now)
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]struct{}, len(left))
	for _, value := range left {
		values[value] = struct{}{}
	}
	for _, value := range right {
		if _, ok := values[value]; !ok {
			return false
		}
	}
	return true
}
