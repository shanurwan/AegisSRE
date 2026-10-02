package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type Data struct {
	Metrics      map[string][]toolapi.MetricSample    `json:"metrics"`
	LogSignals   map[string][]toolapi.DetectionSample `json:"log_signals,omitempty"`
	TraceSignals map[string][]toolapi.DetectionSample `json:"trace_signals,omitempty"`
	Snapshot     toolapi.WorkloadSnapshot             `json:"snapshot"`
	PodLogs      map[string]string                    `json:"pod_logs"`
	Logs         []toolapi.LogLine                    `json:"logs"`
}

type Backend struct {
	mu             sync.Mutex
	data           Data
	Verifier       ports.GrantVerifier
	Policy         ports.GrantAuthorizer
	Replay         ports.ReplayGuard
	Clock          ports.Clock
	IDs            ports.IDGenerator
	AllowMutations bool
	receipts       map[string]model.ActionReceipt
	receiptGrants  map[string]model.DelegationGrant
	applied        map[string]bool
}

const maxFixtureDetectionCount = 1<<53 - 1

func Load(path string) (*Backend, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fixture %s: %w", path, err)
	}
	var data Data
	if err := json.Unmarshal(contents, &data); err != nil {
		return nil, fmt.Errorf("decode fixture %s: %w", path, err)
	}
	if err := data.Snapshot.Target.Validate(); err != nil {
		return nil, fmt.Errorf("fixture target: %w", err)
	}
	return &Backend{
		data: data, receipts: make(map[string]model.ActionReceipt),
		receiptGrants: make(map[string]model.DelegationGrant), applied: make(map[string]bool),
	}, nil
}

func (b *Backend) QueryMetrics(_ context.Context, input toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if input.Namespace != b.data.Snapshot.Target.Namespace {
		return toolapi.QueryMetricsOutput{}, model.NewError(model.CodeOutOfScope, "fixture namespace is not allowed")
	}
	samples, ok := b.data.Metrics[input.TemplateID]
	if !ok {
		return toolapi.QueryMetricsOutput{}, fmt.Errorf("fixture has no metric template %q", input.TemplateID)
	}
	copySamples := append([]toolapi.MetricSample(nil), samples...)
	return toolapi.QueryMetricsOutput{
		TemplateID: input.TemplateID, Query: "fixture:" + input.TemplateID,
		Samples: copySamples, ObservedAt: b.now(),
	}, nil
}

func (b *Backend) QueryLogSignals(_ context.Context, input toolapi.QueryLogSignalsInput) (toolapi.QueryLogSignalsOutput, error) {
	if !validLogTemplate(input.TemplateID) {
		return toolapi.QueryLogSignalsOutput{}, fmt.Errorf("unsupported log detection template %q", input.TemplateID)
	}
	start, end, samples, err := b.queryDetectionSignals(input.TemplateID, input.Namespace, input.Workload, b.data.LogSignals)
	if err != nil {
		return toolapi.QueryLogSignalsOutput{}, err
	}
	return toolapi.QueryLogSignalsOutput{
		TemplateID: input.TemplateID, WindowStart: start, WindowEnd: end, Samples: samples,
	}, nil
}

func (b *Backend) QueryTraceSignals(_ context.Context, input toolapi.QueryTraceSignalsInput) (toolapi.QueryTraceSignalsOutput, error) {
	if !validTraceTemplate(input.TemplateID) {
		return toolapi.QueryTraceSignalsOutput{}, fmt.Errorf("unsupported trace detection template %q", input.TemplateID)
	}
	start, end, samples, err := b.queryDetectionSignals(input.TemplateID, input.Namespace, input.Workload, b.data.TraceSignals)
	if err != nil {
		return toolapi.QueryTraceSignalsOutput{}, err
	}
	return toolapi.QueryTraceSignalsOutput{
		TemplateID: input.TemplateID, WindowStart: start, WindowEnd: end, Samples: samples,
	}, nil
}

func (b *Backend) queryDetectionSignals(
	templateID, namespace, workload string,
	source map[string][]toolapi.DetectionSample,
) (time.Time, time.Time, []toolapi.DetectionSample, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if namespace != b.data.Snapshot.Target.Namespace {
		return time.Time{}, time.Time{}, nil, model.NewError(model.CodeOutOfScope, "fixture namespace is not allowed")
	}
	if workload != "" && workload != b.data.Snapshot.Target.Name {
		return time.Time{}, time.Time{}, nil, model.NewError(model.CodeOutOfScope, "fixture workload is not allowed")
	}
	configured := source[templateID]
	end := b.now()
	start := end.Add(-5 * time.Minute)
	samples := make([]toolapi.DetectionSample, 0, len(configured))
	seen := make(map[string]struct{}, len(configured))
	for _, sample := range configured {
		if sample.Namespace != namespace || sample.Workload == "" || sample.Workload != b.data.Snapshot.Target.Name {
			return time.Time{}, time.Time{}, nil, model.NewError(model.CodeOutOfScope, "fixture detection sample has no exact namespace/workload mapping")
		}
		if workload != "" && sample.Workload != workload {
			return time.Time{}, time.Time{}, nil, model.NewError(model.CodeOutOfScope, "fixture detection sample targets another workload")
		}
		if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value < 0 || sample.Value > maxFixtureDetectionCount || math.Trunc(sample.Value) != sample.Value {
			return time.Time{}, time.Time{}, nil, errors.New("fixture detection sample value is invalid")
		}
		if sample.Timestamp.IsZero() {
			sample.Timestamp = end
		} else {
			sample.Timestamp = sample.Timestamp.UTC()
		}
		if sample.Timestamp.Before(start) || sample.Timestamp.After(end) {
			continue
		}
		key := sample.Namespace + "\x00" + sample.Workload
		if _, duplicate := seen[key]; duplicate {
			return time.Time{}, time.Time{}, nil, errors.New("fixture detection samples contain a duplicate identity")
		}
		seen[key] = struct{}{}
		samples = append(samples, sample)
	}
	if len(samples) > 50 {
		return time.Time{}, time.Time{}, nil, errors.New("fixture detection result exceeds its group limit")
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Namespace != samples[j].Namespace {
			return samples[i].Namespace < samples[j].Namespace
		}
		return samples[i].Workload < samples[j].Workload
	})
	return start, end, samples, nil
}

func validLogTemplate(templateID string) bool {
	return templateID == toolapi.LogErrorBurst5m || templateID == toolapi.LogDependencyTimeoutBurst5m
}

func validTraceTemplate(templateID string) bool {
	return templateID == toolapi.TraceErrorCount5m || templateID == toolapi.TraceSlowServerCount5m
}

func (b *Backend) SearchLogs(_ context.Context, input toolapi.SearchLogsInput) (toolapi.SearchLogsOutput, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if input.Namespace != b.data.Snapshot.Target.Namespace {
		return toolapi.SearchLogsOutput{}, model.NewError(model.CodeOutOfScope, "fixture namespace is not allowed")
	}
	limit := input.Limit
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	lines := append([]toolapi.LogLine(nil), b.data.Logs...)
	truncated := len(lines) > limit
	if truncated {
		lines = lines[:limit]
	}
	return toolapi.SearchLogsOutput{Lines: lines, Truncated: truncated}, nil
}

func (b *Backend) GetWorkloadSnapshot(_ context.Context, input toolapi.GetWorkloadSnapshotInput) (toolapi.GetWorkloadSnapshotOutput, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if input.Namespace != b.data.Snapshot.Target.Namespace || input.Kind != b.data.Snapshot.Target.Kind || input.Name != b.data.Snapshot.Target.Name {
		return toolapi.GetWorkloadSnapshotOutput{}, model.NewError(model.CodeOutOfScope, "fixture target does not match")
	}
	return toolapi.GetWorkloadSnapshotOutput{Snapshot: b.data.Snapshot}, nil
}

func (b *Backend) GetPodLogs(_ context.Context, input toolapi.GetPodLogsInput) (toolapi.GetPodLogsOutput, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if input.Namespace != b.data.Snapshot.Target.Namespace {
		return toolapi.GetPodLogsOutput{}, model.NewError(model.CodeOutOfScope, "fixture namespace is not allowed")
	}
	logs, ok := b.data.PodLogs[input.Pod]
	if !ok {
		return toolapi.GetPodLogsOutput{}, fmt.Errorf("fixture has no logs for pod %q", input.Pod)
	}
	maxBytes := input.MaxBytes
	if maxBytes <= 0 || maxBytes > 131072 {
		maxBytes = 32768
	}
	truncated := len(logs) > maxBytes
	if truncated {
		logs = logs[:maxBytes]
	}
	return toolapi.GetPodLogsOutput{Pod: input.Pod, Container: input.Container, Logs: logs, Truncated: truncated}, nil
}

// ResolvePodDeployment gives the policy-enforcing read adapter the fixture's
// explicit pod-to-workload relationship. Production uses Kubernetes owner
// references; fixture snapshots intentionally model a single Deployment.
func (b *Backend) ResolvePodDeployment(_ context.Context, namespace, podName string) (model.ResourceTarget, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if namespace != b.data.Snapshot.Target.Namespace {
		return model.ResourceTarget{}, model.NewError(model.CodeOutOfScope, "fixture pod namespace is not allowed")
	}
	for _, pod := range b.data.Snapshot.Pods {
		if pod.Name == podName {
			return b.data.Snapshot.Target, nil
		}
	}
	return model.ResourceTarget{}, model.NewError(model.CodeOutOfScope, "fixture pod is outside the workload snapshot")
}

func (b *Backend) ExecuteRemediation(_ context.Context, input toolapi.ExecuteRemediationInput) (toolapi.ExecuteRemediationOutput, error) {
	if b.Verifier == nil || b.Policy == nil || b.Replay == nil || b.Clock == nil || b.IDs == nil {
		return toolapi.ExecuteRemediationOutput{}, errors.New("fixture action security dependencies are incomplete")
	}
	now := b.now()
	grant := input.Grant
	if err := b.Verifier.Verify(grant, now); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	decision := b.Policy.Authorize(grant, now)
	if !decision.Allowed {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(decision.Code, decision.Reason)
	}
	if input.DryRun != grant.DryRun {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodePolicyDenied, "tool dry-run mode differs from signed grant")
	}
	if !grant.DryRun && !b.AllowMutations {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodePolicyDenied, "fixture mutation switch is disabled")
	}
	b.mu.Lock()
	if receipt, ok := b.receipts[grant.GrantID]; ok {
		storedGrant, exact := b.receiptGrants[grant.GrantID]
		b.mu.Unlock()
		if !exact || !sameFixtureGrant(storedGrant, grant) {
			return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeInvalidInput, "grant ID was reused with different signed contents")
		}
		return toolapi.ExecuteRemediationOutput{Receipt: receipt}, nil
	}
	b.mu.Unlock()
	if err := b.Replay.ConsumeGrant(grant, now); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if !grant.Action.Target.Equal(b.data.Snapshot.Target) {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeOutOfScope, "fixture action target does not match")
	}
	if grant.Preconditions.ResourceVersion != "" && grant.Preconditions.ResourceVersion != b.data.Snapshot.ResourceVersion {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeStalePrecondition, "fixture resourceVersion changed")
	}
	if expected := grant.Preconditions.ExpectedReplicas; expected != nil && *expected != b.data.Snapshot.DesiredReplicas {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeStalePrecondition, "fixture replicas changed")
	}
	before := fixtureResourceSnapshot(b.data.Snapshot)
	after := before
	if !grant.DryRun {
		if b.applied == nil {
			b.applied = make(map[string]bool)
		}
		switch grant.Action.Kind {
		case model.ActionRestartDeployment:
			b.data.Snapshot.Generation++
			b.data.Snapshot.ObservedGeneration = b.data.Snapshot.Generation
			b.data.Snapshot.ReadyReplicas = b.data.Snapshot.DesiredReplicas
			b.data.Snapshot.AvailableReplicas = b.data.Snapshot.DesiredReplicas
			b.data.Snapshot.UnavailableReplicas = 0
			b.data.Snapshot.ResourceVersion = "fixture-rv-after"
			for i := range b.data.Snapshot.Pods {
				b.data.Snapshot.Pods[i].Ready = true
				for j := range b.data.Snapshot.Pods[i].Containers {
					b.data.Snapshot.Pods[i].Containers[j].Ready = true
					b.data.Snapshot.Pods[i].Containers[j].Reason = ""
				}
			}
		case model.ActionScaleDeployment:
			b.data.Snapshot.DesiredReplicas = *grant.Action.Parameters.Replicas
			b.data.Snapshot.ReadyReplicas = *grant.Action.Parameters.Replicas
			b.data.Snapshot.AvailableReplicas = *grant.Action.Parameters.Replicas
			b.data.Snapshot.UnavailableReplicas = 0
			b.data.Snapshot.ResourceVersion = "fixture-rv-after"
		}
		b.applied[grant.GrantID] = true
		after = fixtureResourceSnapshot(b.data.Snapshot)
	}
	outcome := model.ActionSucceeded
	if grant.DryRun {
		outcome = model.ActionDryRun
	}
	receipt := model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1, ReceiptID: "receipt-" + b.IDs.NewID(),
		GrantID: grant.GrantID, IncidentID: grant.IncidentID, Action: grant.Action,
		Outcome: outcome, DryRun: grant.DryRun, StartedAt: now, CompletedAt: b.now(),
		Before: &before, After: &after, AuditRef: "audit-" + b.IDs.NewID(),
	}
	if err := receipt.Validate(); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	if b.receipts == nil {
		b.receipts = make(map[string]model.ActionReceipt)
	}
	if b.receiptGrants == nil {
		b.receiptGrants = make(map[string]model.DelegationGrant)
	}
	b.receipts[grant.GrantID] = receipt
	b.receiptGrants[grant.GrantID] = grant
	return toolapi.ExecuteRemediationOutput{Receipt: receipt}, nil
}

// GetRemediationResult performs an exact, read-only lookup of a previously
// completed fixture execution. It does not invoke the verifier or policy, so
// an accepted result remains recoverable after expiry without extending the
// grant's authority.
func (b *Backend) GetRemediationResult(
	_ context.Context,
	input toolapi.GetRemediationResultInput,
) (toolapi.GetRemediationResultOutput, error) {
	if err := input.Grant.ValidateSigned(); err != nil {
		return toolapi.GetRemediationResultOutput{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	receipt, found := b.receipts[input.Grant.GrantID]
	if !found {
		return toolapi.GetRemediationResultOutput{State: toolapi.RemediationNotFound}, nil
	}
	storedGrant, exact := b.receiptGrants[input.Grant.GrantID]
	if !exact || !sameFixtureGrant(storedGrant, input.Grant) {
		return toolapi.GetRemediationResultOutput{}, model.NewError(model.CodeInvalidInput, "grant ID was reused with different signed contents")
	}
	copy := receipt
	if receipt.Action.Parameters.Replicas != nil {
		value := *receipt.Action.Parameters.Replicas
		copy.Action.Parameters.Replicas = &value
	}
	if receipt.Before != nil {
		value := *receipt.Before
		copy.Before = &value
	}
	if receipt.After != nil {
		value := *receipt.After
		copy.After = &value
	}
	return toolapi.GetRemediationResultOutput{State: toolapi.RemediationCompleted, Receipt: &copy}, nil
}

func (b *Backend) GetRemediationStatus(_ context.Context, input toolapi.GetRemediationStatusInput) (toolapi.GetRemediationStatusOutput, error) {
	if b.Verifier == nil || b.Policy == nil || b.Clock == nil {
		return toolapi.GetRemediationStatusOutput{}, errors.New("fixture action security dependencies are incomplete")
	}
	if err := b.Verifier.Verify(input.Grant, b.now()); err != nil {
		return toolapi.GetRemediationStatusOutput{}, err
	}
	decision := b.Policy.Authorize(input.Grant, b.now())
	if !decision.Allowed {
		return toolapi.GetRemediationStatusOutput{}, model.NewError(decision.Code, decision.Reason)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	rolloutAvailable := b.data.Snapshot.AvailableReplicas >= b.data.Snapshot.DesiredReplicas
	satisfied := false
	detail := "fixture workload has not reached the delegated remediation postcondition"
	if b.applied[input.Grant.GrantID] {
		switch input.Grant.Action.Kind {
		case model.ActionRestartDeployment:
			satisfied = rolloutAvailable
		case model.ActionScaleDeployment:
			satisfied = rolloutAvailable && input.Grant.Action.Parameters.Replicas != nil &&
				b.data.Snapshot.DesiredReplicas == *input.Grant.Action.Parameters.Replicas
		}
	}
	if satisfied {
		detail = "fixture workload meets the exact delegated remediation postcondition"
	}
	return toolapi.GetRemediationStatusOutput{Snapshot: b.data.Snapshot, Satisfied: satisfied, Detail: detail}, nil
}

func (b *Backend) now() time.Time {
	if b.Clock != nil {
		return b.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func fixtureResourceSnapshot(value toolapi.WorkloadSnapshot) model.ResourceSnapshot {
	return model.ResourceSnapshot{
		ResourceVersion: value.ResourceVersion, DesiredReplicas: value.DesiredReplicas,
		ReadyReplicas: value.ReadyReplicas, AvailableReplicas: value.AvailableReplicas,
	}
}

func sameFixtureGrant(left, right model.DelegationGrant) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}
