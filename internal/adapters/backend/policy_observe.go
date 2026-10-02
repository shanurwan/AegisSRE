package backend

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

const maxPolicyReadFanout = 50

// PodOwnerResolver resolves the current Kubernetes controller chain for a Pod.
// Production implementations must fail closed unless the chain terminates at
// one exact apps/v1 Deployment. It is deliberately separate from log storage:
// neither a caller-supplied pod name nor telemetry labels establish ownership.
type PodOwnerResolver interface {
	ResolvePodDeployment(context.Context, string, string) (model.ResourceTarget, error)
}

type readRule struct {
	target  model.ResourceTarget
	signals map[model.EvidenceSource]struct{}
}

// PolicyObserve is the final authorization boundary in front of read MCP. It
// converts namespace scans into exact workload-scoped backend calls and
// validates result identities before returning any telemetry to an agent.
type PolicyObserve struct {
	next      ports.ObserveBackend
	podOwners PodOwnerResolver
	rules     map[string]readRule
	bySignal  map[string]map[model.EvidenceSource][]model.ResourceTarget
}

// NewPolicyObserve constructs an immutable, pattern-free read policy. The
// workload rules come from the same strict document used to bind delegation
// grants, but action permissions and replica bounds have no read-side effect.
func NewPolicyObserve(
	next ports.ObserveBackend,
	workloads []security.WorkloadPolicy,
	podOwners PodOwnerResolver,
) (*PolicyObserve, error) {
	if next == nil {
		return nil, model.NewError(model.CodeInvalidInput, "read MCP backend is required")
	}
	if len(workloads) == 0 {
		return nil, model.NewError(model.CodeInvalidInput, "read MCP workload policy is required")
	}
	result := &PolicyObserve{
		next: next, podOwners: podOwners,
		rules:    make(map[string]readRule, len(workloads)),
		bySignal: make(map[string]map[model.EvidenceSource][]model.ResourceTarget),
	}
	logsAllowed := false
	for _, workload := range workloads {
		if err := workload.Validate(); err != nil {
			return nil, model.WrapError(model.CodeInvalidInput, "validate read MCP workload policy", err)
		}
		key := workload.Target.Key()
		if _, duplicate := result.rules[key]; duplicate {
			return nil, model.NewError(model.CodeInvalidInput, "read MCP workload policy contains a duplicate target")
		}
		rule := readRule{target: workload.Target, signals: make(map[model.EvidenceSource]struct{}, len(workload.AllowedSignalSources))}
		for _, source := range workload.AllowedSignalSources {
			rule.signals[source] = struct{}{}
			if source == model.EvidenceLogs {
				logsAllowed = true
			}
			if result.bySignal[workload.Target.Namespace] == nil {
				result.bySignal[workload.Target.Namespace] = make(map[model.EvidenceSource][]model.ResourceTarget)
			}
			result.bySignal[workload.Target.Namespace][source] = append(
				result.bySignal[workload.Target.Namespace][source], workload.Target,
			)
		}
		result.rules[key] = rule
	}
	if logsAllowed && podOwners == nil {
		return nil, model.NewError(model.CodeInvalidInput, "read MCP log policy requires a pod ownership resolver")
	}
	for _, signals := range result.bySignal {
		for source, targets := range signals {
			if len(targets) > maxPolicyReadFanout {
				return nil, model.NewError(model.CodeInvalidInput, "read MCP workload policy exceeds the per-signal fanout bound")
			}
			sort.Slice(targets, func(i, j int) bool { return targets[i].Key() < targets[j].Key() })
			signals[source] = targets
		}
	}
	return result, nil
}

func (p *PolicyObserve) QueryMetrics(ctx context.Context, input toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error) {
	// These are the only metric templates whose results carry the exact
	// Deployment identity and whose underlying PromQL applies Workload.
	switch input.TemplateID {
	case toolapi.MetricDeploymentUnavailable, toolapi.MetricDeploymentAvailable:
	default:
		return toolapi.QueryMetricsOutput{}, model.NewError(model.CodePolicyDenied, "metric template cannot be bound to an exact workload")
	}
	targets, err := p.authorizedTargets(input.Namespace, input.Workload, model.EvidenceMetrics)
	if err != nil {
		return toolapi.QueryMetricsOutput{}, err
	}
	result := toolapi.QueryMetricsOutput{TemplateID: input.TemplateID}
	for _, target := range targets {
		scoped := input
		scoped.Workload = target.Name
		output, err := p.next.QueryMetrics(ctx, scoped)
		if err != nil {
			return toolapi.QueryMetricsOutput{}, err
		}
		if output.TemplateID != input.TemplateID {
			return toolapi.QueryMetricsOutput{}, errors.New("policy-scoped metric result changed the requested template")
		}
		for _, sample := range output.Samples {
			if sample.Labels["namespace"] != target.Namespace || sample.Labels["deployment"] != target.Name {
				return toolapi.QueryMetricsOutput{}, model.NewError(model.CodeOutOfScope, "metric result is not bound to the authorized workload")
			}
		}
		if len(result.Samples)+len(output.Samples) > maxPolicyReadFanout {
			return toolapi.QueryMetricsOutput{}, errors.New("policy-scoped metric result exceeds its workload bound")
		}
		result.Samples = append(result.Samples, output.Samples...)
		if output.ObservedAt.After(result.ObservedAt) {
			result.ObservedAt = output.ObservedAt
		}
	}
	result.Query = "policy-scoped:" + input.TemplateID
	return result, nil
}

func (p *PolicyObserve) QueryLogSignals(ctx context.Context, input toolapi.QueryLogSignalsInput) (toolapi.QueryLogSignalsOutput, error) {
	targets, err := p.authorizedTargets(input.Namespace, input.Workload, model.EvidenceLogs)
	if err != nil {
		return toolapi.QueryLogSignalsOutput{}, err
	}
	result := toolapi.QueryLogSignalsOutput{TemplateID: input.TemplateID}
	for _, target := range targets {
		scoped := input
		scoped.Workload = target.Name
		output, err := p.next.QueryLogSignals(ctx, scoped)
		if err != nil {
			return toolapi.QueryLogSignalsOutput{}, err
		}
		if err := validateDetectionOutput(input.TemplateID, target, output.TemplateID, output.Samples); err != nil {
			return toolapi.QueryLogSignalsOutput{}, err
		}
		if len(result.Samples)+len(output.Samples) > maxPolicyReadFanout {
			return toolapi.QueryLogSignalsOutput{}, errors.New("policy-scoped log result exceeds its workload bound")
		}
		mergeDetectionWindow(&result.WindowStart, &result.WindowEnd, output.WindowStart, output.WindowEnd)
		result.Samples = append(result.Samples, output.Samples...)
	}
	return result, nil
}

func (p *PolicyObserve) QueryTraceSignals(ctx context.Context, input toolapi.QueryTraceSignalsInput) (toolapi.QueryTraceSignalsOutput, error) {
	targets, err := p.authorizedTargets(input.Namespace, input.Workload, model.EvidenceTraces)
	if err != nil {
		return toolapi.QueryTraceSignalsOutput{}, err
	}
	result := toolapi.QueryTraceSignalsOutput{TemplateID: input.TemplateID}
	for _, target := range targets {
		scoped := input
		scoped.Workload = target.Name
		output, err := p.next.QueryTraceSignals(ctx, scoped)
		if err != nil {
			return toolapi.QueryTraceSignalsOutput{}, err
		}
		if err := validateDetectionOutput(input.TemplateID, target, output.TemplateID, output.Samples); err != nil {
			return toolapi.QueryTraceSignalsOutput{}, err
		}
		if len(result.Samples)+len(output.Samples) > maxPolicyReadFanout {
			return toolapi.QueryTraceSignalsOutput{}, errors.New("policy-scoped trace result exceeds its workload bound")
		}
		mergeDetectionWindow(&result.WindowStart, &result.WindowEnd, output.WindowStart, output.WindowEnd)
		result.Samples = append(result.Samples, output.Samples...)
	}
	return result, nil
}

func (p *PolicyObserve) SearchLogs(ctx context.Context, input toolapi.SearchLogsInput) (toolapi.SearchLogsOutput, error) {
	if strings.TrimSpace(input.Pod) == "" {
		return toolapi.SearchLogsOutput{}, model.NewError(model.CodeOutOfScope, "policy-scoped log search requires an exact pod")
	}
	if _, err := p.authorizePod(ctx, input.Namespace, input.Pod); err != nil {
		return toolapi.SearchLogsOutput{}, err
	}
	return p.next.SearchLogs(ctx, input)
}

func (p *PolicyObserve) GetWorkloadSnapshot(ctx context.Context, input toolapi.GetWorkloadSnapshotInput) (toolapi.GetWorkloadSnapshotOutput, error) {
	target := model.ResourceTarget{APIVersion: "apps/v1", Kind: input.Kind, Namespace: input.Namespace, Name: input.Name}
	if !p.allowsTarget(target) {
		return toolapi.GetWorkloadSnapshotOutput{}, model.NewError(model.CodeOutOfScope, "workload snapshot target is outside the exact workload policy")
	}
	output, err := p.next.GetWorkloadSnapshot(ctx, input)
	if err != nil {
		return toolapi.GetWorkloadSnapshotOutput{}, err
	}
	if !output.Snapshot.Target.Equal(target) {
		return toolapi.GetWorkloadSnapshotOutput{}, model.NewError(model.CodeOutOfScope, "workload snapshot result changed the authorized target")
	}
	if len(output.Snapshot.Pods) > 100 {
		return toolapi.GetWorkloadSnapshotOutput{}, errors.New("workload snapshot exceeds its pod bound")
	}
	ownedPods := make(map[string]struct{}, len(output.Snapshot.Pods))
	for _, pod := range output.Snapshot.Pods {
		owner, err := p.resolvePod(ctx, input.Namespace, pod.Name)
		if err != nil {
			return toolapi.GetWorkloadSnapshotOutput{}, err
		}
		if !owner.Equal(target) {
			return toolapi.GetWorkloadSnapshotOutput{}, model.NewError(model.CodeOutOfScope, "workload snapshot contains a pod outside the authorized Deployment")
		}
		ownedPods[pod.Name] = struct{}{}
	}
	for _, event := range output.Snapshot.Events {
		parts := strings.SplitN(event.Object, "/", 2)
		if len(parts) != 2 {
			return toolapi.GetWorkloadSnapshotOutput{}, model.NewError(model.CodeOutOfScope, "workload snapshot contains an event without an exact object identity")
		}
		switch strings.ToLower(parts[0]) {
		case "deployment":
			if parts[1] != target.Name {
				return toolapi.GetWorkloadSnapshotOutput{}, model.NewError(model.CodeOutOfScope, "workload snapshot contains an event for another Deployment")
			}
		case "pod":
			if _, ok := ownedPods[parts[1]]; !ok {
				return toolapi.GetWorkloadSnapshotOutput{}, model.NewError(model.CodeOutOfScope, "workload snapshot contains an event for an unauthorized pod")
			}
		default:
			return toolapi.GetWorkloadSnapshotOutput{}, model.NewError(model.CodeOutOfScope, "workload snapshot contains an event for an unauthorized object kind")
		}
	}
	return output, nil
}

func (p *PolicyObserve) GetPodLogs(ctx context.Context, input toolapi.GetPodLogsInput) (toolapi.GetPodLogsOutput, error) {
	if _, err := p.authorizePod(ctx, input.Namespace, input.Pod); err != nil {
		return toolapi.GetPodLogsOutput{}, err
	}
	return p.next.GetPodLogs(ctx, input)
}

func (p *PolicyObserve) authorizedTargets(namespace, workload string, source model.EvidenceSource) ([]model.ResourceTarget, error) {
	if strings.TrimSpace(namespace) == "" || !source.Valid() || source == model.EvidenceKubernetes {
		return nil, model.NewError(model.CodeInvalidInput, "read MCP signal scope is invalid")
	}
	if workload != "" {
		target := model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: namespace, Name: workload}
		rule, ok := p.rules[target.Key()]
		if !ok {
			return nil, model.NewError(model.CodeOutOfScope, "signal target is outside the exact workload policy")
		}
		if _, ok := rule.signals[source]; !ok {
			return nil, model.NewError(model.CodePolicyDenied, "signal source is not allowed for the exact workload")
		}
		return []model.ResourceTarget{rule.target}, nil
	}
	targets := p.bySignal[namespace][source]
	if len(targets) == 0 {
		return nil, model.NewError(model.CodeOutOfScope, "signal namespace and source are outside the exact workload policy")
	}
	return targets, nil
}

func (p *PolicyObserve) allowsTarget(target model.ResourceTarget) bool {
	if target.APIVersion != "apps/v1" || target.Kind != "Deployment" {
		return false
	}
	_, ok := p.rules[target.Key()]
	return ok
}

func (p *PolicyObserve) authorizePod(ctx context.Context, namespace, pod string) (model.ResourceTarget, error) {
	if len(p.bySignal[namespace][model.EvidenceLogs]) == 0 {
		return model.ResourceTarget{}, model.NewError(model.CodePolicyDenied, "logs are not allowed in the exact workload policy")
	}
	owner, err := p.resolvePod(ctx, namespace, pod)
	if err != nil {
		return model.ResourceTarget{}, err
	}
	rule, ok := p.rules[owner.Key()]
	if !ok {
		return model.ResourceTarget{}, model.NewError(model.CodeOutOfScope, "pod owner is outside the exact workload policy")
	}
	if _, ok := rule.signals[model.EvidenceLogs]; !ok {
		return model.ResourceTarget{}, model.NewError(model.CodePolicyDenied, "logs are not allowed for the pod's exact workload")
	}
	return owner, nil
}

func (p *PolicyObserve) resolvePod(ctx context.Context, namespace, pod string) (model.ResourceTarget, error) {
	if p.podOwners == nil {
		return model.ResourceTarget{}, model.NewError(model.CodePolicyDenied, "pod ownership cannot be verified")
	}
	owner, err := p.podOwners.ResolvePodDeployment(ctx, namespace, pod)
	if err != nil {
		return model.ResourceTarget{}, model.WrapError(model.CodeOutOfScope, "verify pod ownership", err)
	}
	if err := owner.Validate(); err != nil || owner.APIVersion != "apps/v1" || owner.Kind != "Deployment" || owner.Namespace != namespace {
		return model.ResourceTarget{}, model.NewError(model.CodeOutOfScope, "pod ownership did not resolve to an exact Deployment")
	}
	return owner, nil
}

func validateDetectionOutput(
	requestedTemplate string,
	target model.ResourceTarget,
	returnedTemplate string,
	samples []toolapi.DetectionSample,
) error {
	if returnedTemplate != requestedTemplate {
		return errors.New("policy-scoped detection result changed the requested template")
	}
	for _, sample := range samples {
		if sample.Namespace != target.Namespace || sample.Workload != target.Name {
			return model.NewError(model.CodeOutOfScope, "detection result is not bound to the authorized workload")
		}
	}
	return nil
}

func mergeDetectionWindow(resultStart, resultEnd *time.Time, start, end time.Time) {
	if resultStart.IsZero() || start.Before(*resultStart) {
		*resultStart = start
	}
	if end.After(*resultEnd) {
		*resultEnd = end
	}
}

var _ ports.ObserveBackend = (*PolicyObserve)(nil)
