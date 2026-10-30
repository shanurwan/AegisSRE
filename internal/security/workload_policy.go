package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

const (
	WorkloadPolicySchemaV1 = "aegissre.io/workload-policy/v1"
	maxWorkloadPolicyBytes = 256 << 10
)

// WorkloadPolicy is an exact, pattern-free authorization rule. It is shared
// by Monitor, Operator, and action MCP; its effective digest is sealed into
// every grant so independently deployed components fail closed on drift.
type WorkloadPolicy struct {
	Target                 model.ResourceTarget   `json:"target"`
	AllowedActions         []model.ActionKind     `json:"allowed_actions"`
	AllowedSignalSources   []model.EvidenceSource `json:"allowed_signal_sources"`
	MaximumReplicas        int32                  `json:"maximum_replicas"`
	MaximumReplicaIncrease int32                  `json:"maximum_replica_increase"`
}

func (p WorkloadPolicy) Validate() error {
	if err := p.Target.Validate(); err != nil {
		return model.WrapError(model.CodeInvalidInput, "validate workload policy target", err)
	}
	if p.Target.APIVersion != "apps/v1" || p.Target.Kind != "Deployment" {
		return model.NewError(model.CodeOutOfScope, "workload policy supports only apps/v1 Deployments")
	}
	if len(p.AllowedActions) == 0 {
		return model.NewError(model.CodeInvalidInput, "workload policy must allow at least one action")
	}
	actions := make(map[model.ActionKind]struct{}, len(p.AllowedActions))
	for _, action := range p.AllowedActions {
		if !action.Valid() {
			return model.NewError(model.CodeInvalidInput, "workload policy contains an invalid action")
		}
		if _, duplicate := actions[action]; duplicate {
			return model.NewError(model.CodeInvalidInput, "workload policy contains a duplicate action")
		}
		actions[action] = struct{}{}
	}
	if len(p.AllowedSignalSources) == 0 {
		return model.NewError(model.CodeInvalidInput, "workload policy must allow at least one signal source")
	}
	sources := make(map[model.EvidenceSource]struct{}, len(p.AllowedSignalSources))
	for _, source := range p.AllowedSignalSources {
		if !source.Valid() || source == model.EvidenceKubernetes {
			return model.NewError(model.CodeInvalidInput, "workload policy contains an invalid detection signal source")
		}
		if _, duplicate := sources[source]; duplicate {
			return model.NewError(model.CodeInvalidInput, "workload policy contains a duplicate signal source")
		}
		sources[source] = struct{}{}
	}
	if p.MaximumReplicas < 1 || p.MaximumReplicaIncrease < 1 || p.MaximumReplicaIncrease > p.MaximumReplicas {
		return model.NewError(model.CodeInvalidInput, "workload replica bounds are invalid")
	}
	return nil
}

type WorkloadPolicyDocument struct {
	SchemaVersion string           `json:"schema_version"`
	PolicyID      string           `json:"policy_id"`
	Workloads     []WorkloadPolicy `json:"workloads"`
}

func (d WorkloadPolicyDocument) Validate() error {
	if d.SchemaVersion != WorkloadPolicySchemaV1 {
		return model.NewError(model.CodeInvalidInput, "unsupported workload policy schema version")
	}
	if strings.TrimSpace(d.PolicyID) == "" || len(d.PolicyID) > 128 {
		return model.NewError(model.CodeInvalidInput, "workload policy ID is required and must be bounded")
	}
	if len(d.Workloads) == 0 || len(d.Workloads) > 1024 {
		return model.NewError(model.CodeInvalidInput, "workload policy must contain 1..1024 exact targets")
	}
	seen := make(map[string]struct{}, len(d.Workloads))
	for _, workload := range d.Workloads {
		if err := workload.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[workload.Target.Key()]; duplicate {
			return model.NewError(model.CodeInvalidInput, "workload policy contains a duplicate target")
		}
		seen[workload.Target.Key()] = struct{}{}
	}
	return nil
}

// LoadWorkloadPolicy reads one bounded strict-JSON policy file. Unknown fields
// and trailing JSON are rejected because a misspelled safety field must never
// silently weaken authorization.
func LoadWorkloadPolicy(path string) (WorkloadPolicyDocument, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return WorkloadPolicyDocument{}, model.NewError(model.CodeInvalidInput, "workload policy path is required")
	}
	file, err := os.Open(path) // #nosec G304 -- operator-configured path, never request input
	if err != nil {
		return WorkloadPolicyDocument{}, fmt.Errorf("open workload policy: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxWorkloadPolicyBytes+1))
	if err != nil {
		return WorkloadPolicyDocument{}, fmt.Errorf("read workload policy: %w", err)
	}
	if len(data) == 0 || len(data) > maxWorkloadPolicyBytes {
		return WorkloadPolicyDocument{}, model.NewError(model.CodeInvalidInput, "workload policy size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document WorkloadPolicyDocument
	if err := decoder.Decode(&document); err != nil {
		return WorkloadPolicyDocument{}, model.WrapError(model.CodeInvalidInput, "decode workload policy", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return WorkloadPolicyDocument{}, model.NewError(model.CodeInvalidInput, "workload policy contains trailing JSON")
	}
	if err := document.Validate(); err != nil {
		return WorkloadPolicyDocument{}, err
	}
	return document, nil
}

func cloneWorkloadPolicies(input []WorkloadPolicy) []WorkloadPolicy {
	result := make([]WorkloadPolicy, len(input))
	for index, policy := range input {
		result[index] = policy
		result[index].AllowedActions = append([]model.ActionKind(nil), policy.AllowedActions...)
		result[index].AllowedSignalSources = append([]model.EvidenceSource(nil), policy.AllowedSignalSources...)
	}
	return result
}

func normalizedWorkloadPolicies(input []WorkloadPolicy) []WorkloadPolicy {
	result := cloneWorkloadPolicies(input)
	for index := range result {
		slices.Sort(result[index].AllowedActions)
		slices.Sort(result[index].AllowedSignalSources)
	}
	slices.SortFunc(result, func(left, right WorkloadPolicy) int {
		return strings.Compare(left.Target.Key(), right.Target.Key())
	})
	return result
}
