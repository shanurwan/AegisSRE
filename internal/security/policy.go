package security

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

type PolicyConfig struct {
	AllowedNamespaces      []string
	AllowedActions         []model.ActionKind
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
	if _, ok := p.allowedNamespaces[grant.Action.Target.Namespace]; !ok {
		return model.Deny(model.CodeOutOfScope, "target namespace is not allowed")
	}
	if _, ok := p.allowedActions[grant.Action.Kind]; !ok {
		return model.Deny(model.CodePolicyDenied, "action is not allowed")
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
		if requested > p.maximumReplicas || requested-expected > p.maximumReplicaIncrease {
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
