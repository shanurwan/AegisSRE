package backend

import (
	"context"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type policyObserveStub struct {
	metricInputs []toolapi.QueryMetricsInput
	logInputs    []toolapi.QueryLogSignalsInput
	traceInputs  []toolapi.QueryTraceSignalsInput
	searchInputs []toolapi.SearchLogsInput
	snapshotIn   []toolapi.GetWorkloadSnapshotInput
	podLogInputs []toolapi.GetPodLogsInput

	foreignMetric bool
	foreignLog    bool
	snapshot      toolapi.WorkloadSnapshot
}

func (s *policyObserveStub) QueryMetrics(_ context.Context, input toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error) {
	s.metricInputs = append(s.metricInputs, input)
	workload := input.Workload
	if s.foreignMetric {
		workload = "foreign"
	}
	return toolapi.QueryMetricsOutput{
		TemplateID: input.TemplateID,
		Samples: []toolapi.MetricSample{{
			Labels:    map[string]string{"namespace": input.Namespace, "deployment": workload},
			Timestamp: time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC), Value: 1,
		}},
		ObservedAt: time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC),
	}, nil
}

func (s *policyObserveStub) QueryLogSignals(_ context.Context, input toolapi.QueryLogSignalsInput) (toolapi.QueryLogSignalsOutput, error) {
	s.logInputs = append(s.logInputs, input)
	workload := input.Workload
	if s.foreignLog {
		workload = "foreign"
	}
	end := time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)
	return toolapi.QueryLogSignalsOutput{
		TemplateID: input.TemplateID, WindowStart: end.Add(-5 * time.Minute), WindowEnd: end,
		Samples: []toolapi.DetectionSample{{Namespace: input.Namespace, Workload: workload, Timestamp: end, Value: 1}},
	}, nil
}

func (s *policyObserveStub) QueryTraceSignals(_ context.Context, input toolapi.QueryTraceSignalsInput) (toolapi.QueryTraceSignalsOutput, error) {
	s.traceInputs = append(s.traceInputs, input)
	end := time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)
	return toolapi.QueryTraceSignalsOutput{
		TemplateID: input.TemplateID, WindowStart: end.Add(-5 * time.Minute), WindowEnd: end,
		Samples: []toolapi.DetectionSample{{Namespace: input.Namespace, Workload: input.Workload, Timestamp: end, Value: 1}},
	}, nil
}

func (s *policyObserveStub) SearchLogs(_ context.Context, input toolapi.SearchLogsInput) (toolapi.SearchLogsOutput, error) {
	s.searchInputs = append(s.searchInputs, input)
	return toolapi.SearchLogsOutput{Lines: []toolapi.LogLine{{Message: "bounded"}}}, nil
}

func (s *policyObserveStub) GetWorkloadSnapshot(_ context.Context, input toolapi.GetWorkloadSnapshotInput) (toolapi.GetWorkloadSnapshotOutput, error) {
	s.snapshotIn = append(s.snapshotIn, input)
	return toolapi.GetWorkloadSnapshotOutput{Snapshot: s.snapshot}, nil
}

func (s *policyObserveStub) GetPodLogs(_ context.Context, input toolapi.GetPodLogsInput) (toolapi.GetPodLogsOutput, error) {
	s.podLogInputs = append(s.podLogInputs, input)
	return toolapi.GetPodLogsOutput{Pod: input.Pod, Logs: "bounded"}, nil
}

type podOwnerStub struct {
	owners map[string]model.ResourceTarget
}

func (s podOwnerStub) ResolvePodDeployment(_ context.Context, namespace, pod string) (model.ResourceTarget, error) {
	target, ok := s.owners[namespace+"/"+pod]
	if !ok {
		return model.ResourceTarget{}, model.NewError(model.CodeOutOfScope, "pod has no trusted owner chain")
	}
	return target, nil
}

func TestPolicyObserveFansOutNamespaceScanToExactWorkloads(t *testing.T) {
	t.Parallel()
	stub := &policyObserveStub{}
	policy, err := NewPolicyObserve(stub, []security.WorkloadPolicy{
		readWorkload("outage-arena", "beta", model.EvidenceMetrics),
		readWorkload("outage-arena", "alpha", model.EvidenceMetrics),
	}, podOwnerStub{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := policy.QueryMetrics(context.Background(), toolapi.QueryMetricsInput{
		TemplateID: toolapi.MetricDeploymentUnavailable, Namespace: "outage-arena",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stub.metricInputs) != 2 || stub.metricInputs[0].Workload != "alpha" || stub.metricInputs[1].Workload != "beta" {
		t.Fatalf("exact metric calls = %#v", stub.metricInputs)
	}
	if len(output.Samples) != 2 || output.Query != "policy-scoped:"+toolapi.MetricDeploymentUnavailable {
		t.Fatalf("policy-scoped metric output = %#v", output)
	}

	_, err = policy.QueryMetrics(context.Background(), toolapi.QueryMetricsInput{
		TemplateID: toolapi.MetricDeploymentUnavailable, Namespace: "outage-arena", Workload: "foreign",
	})
	assertModelCode(t, err, model.CodeOutOfScope)
	if len(stub.metricInputs) != 2 {
		t.Fatal("unauthorized workload reached the telemetry backend")
	}
}

func TestPolicyObserveRejectsUnscopedTemplatesSourcesAndForeignResults(t *testing.T) {
	t.Parallel()
	stub := &policyObserveStub{foreignMetric: true}
	policy, err := NewPolicyObserve(stub, []security.WorkloadPolicy{
		readWorkload("outage-arena", "demo-api", model.EvidenceMetrics),
	}, podOwnerStub{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = policy.QueryMetrics(context.Background(), toolapi.QueryMetricsInput{
		TemplateID: toolapi.MetricDeploymentUnavailable, Namespace: "outage-arena", Workload: "demo-api",
	})
	assertModelCode(t, err, model.CodeOutOfScope)

	_, err = policy.QueryMetrics(context.Background(), toolapi.QueryMetricsInput{
		TemplateID: toolapi.MetricPodCrashLoop, Namespace: "outage-arena", Workload: "demo-api",
	})
	assertModelCode(t, err, model.CodePolicyDenied)
	if len(stub.metricInputs) != 1 {
		t.Fatal("unscopable pod metric reached the telemetry backend")
	}

	_, err = policy.QueryLogSignals(context.Background(), toolapi.QueryLogSignalsInput{
		TemplateID: toolapi.LogErrorBurst5m, Namespace: "outage-arena", Workload: "demo-api",
	})
	assertModelCode(t, err, model.CodePolicyDenied)
	if len(stub.logInputs) != 0 {
		t.Fatal("disallowed log source reached the telemetry backend")
	}
}

func TestPolicyObserveRejectsForeignDetectionIdentity(t *testing.T) {
	t.Parallel()
	stub := &policyObserveStub{foreignLog: true}
	policy, err := NewPolicyObserve(stub, []security.WorkloadPolicy{
		readWorkload("outage-arena", "demo-api", model.EvidenceLogs),
	}, podOwnerStub{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = policy.QueryLogSignals(context.Background(), toolapi.QueryLogSignalsInput{
		TemplateID: toolapi.LogErrorBurst5m, Namespace: "outage-arena", Workload: "demo-api",
	})
	assertModelCode(t, err, model.CodeOutOfScope)
}

func TestPolicyObserveRequiresExactOwnedPodForRawLogs(t *testing.T) {
	t.Parallel()
	allowed := readTarget("outage-arena", "demo-api")
	foreign := readTarget("outage-arena", "foreign")
	stub := &policyObserveStub{}
	policy, err := NewPolicyObserve(stub, []security.WorkloadPolicy{
		readWorkload("outage-arena", "demo-api", model.EvidenceLogs),
	}, podOwnerStub{owners: map[string]model.ResourceTarget{
		"outage-arena/demo-api-abc": allowed,
		"outage-arena/foreign-abc":  foreign,
	}})
	if err != nil {
		t.Fatal(err)
	}

	_, err = policy.SearchLogs(context.Background(), toolapi.SearchLogsInput{Namespace: "outage-arena"})
	assertModelCode(t, err, model.CodeOutOfScope)
	_, err = policy.GetPodLogs(context.Background(), toolapi.GetPodLogsInput{Namespace: "outage-arena", Pod: "foreign-abc"})
	assertModelCode(t, err, model.CodeOutOfScope)
	if len(stub.searchInputs) != 0 || len(stub.podLogInputs) != 0 {
		t.Fatal("unauthorized raw-log request reached its backend")
	}

	if _, err := policy.SearchLogs(context.Background(), toolapi.SearchLogsInput{
		Namespace: "outage-arena", Pod: "demo-api-abc",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.GetPodLogs(context.Background(), toolapi.GetPodLogsInput{
		Namespace: "outage-arena", Pod: "demo-api-abc",
	}); err != nil {
		t.Fatal(err)
	}
	if len(stub.searchInputs) != 1 || len(stub.podLogInputs) != 1 {
		t.Fatal("authorized raw-log request was not forwarded exactly once")
	}
}

func TestPolicyObserveValidatesSnapshotTargetPodsAndEvents(t *testing.T) {
	t.Parallel()
	target := readTarget("outage-arena", "demo-api")
	stub := &policyObserveStub{snapshot: toolapi.WorkloadSnapshot{
		Target: target,
		Pods:   []toolapi.PodSnapshot{{Name: "demo-api-abc"}},
		Events: []toolapi.EventSnapshot{{Object: "deployment/demo-api"}, {Object: "pod/demo-api-abc"}},
	}}
	owners := podOwnerStub{owners: map[string]model.ResourceTarget{"outage-arena/demo-api-abc": target}}
	policy, err := NewPolicyObserve(stub, []security.WorkloadPolicy{
		readWorkload("outage-arena", "demo-api", model.EvidenceMetrics),
	}, owners)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.GetWorkloadSnapshot(context.Background(), toolapi.GetWorkloadSnapshotInput{
		Namespace: "outage-arena", Kind: "Deployment", Name: "demo-api",
	}); err != nil {
		t.Fatal(err)
	}

	_, err = policy.GetWorkloadSnapshot(context.Background(), toolapi.GetWorkloadSnapshotInput{
		Namespace: "outage-arena", Kind: "Deployment", Name: "foreign",
	})
	assertModelCode(t, err, model.CodeOutOfScope)
	if len(stub.snapshotIn) != 1 {
		t.Fatal("unauthorized snapshot request reached Kubernetes")
	}

	stub.snapshot.Events = append(stub.snapshot.Events, toolapi.EventSnapshot{Object: "pod/foreign"})
	_, err = policy.GetWorkloadSnapshot(context.Background(), toolapi.GetWorkloadSnapshotInput{
		Namespace: "outage-arena", Kind: "Deployment", Name: "demo-api",
	})
	assertModelCode(t, err, model.CodeOutOfScope)
}

func TestPolicyObserveRequiresOwnershipResolverWhenLogsAreAllowed(t *testing.T) {
	t.Parallel()
	_, err := NewPolicyObserve(&policyObserveStub{}, []security.WorkloadPolicy{
		readWorkload("outage-arena", "demo-api", model.EvidenceLogs),
	}, nil)
	assertModelCode(t, err, model.CodeInvalidInput)
}

func readWorkload(namespace, name string, sources ...model.EvidenceSource) security.WorkloadPolicy {
	return security.WorkloadPolicy{
		Target:               readTarget(namespace, name),
		AllowedActions:       []model.ActionKind{model.ActionRestartDeployment},
		AllowedSignalSources: sources,
		MaximumReplicas:      5, MaximumReplicaIncrease: 1,
	}
}

func readTarget(namespace, name string) model.ResourceTarget {
	return model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: namespace, Name: name}
}

func assertModelCode(t *testing.T, err error, want model.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", want)
	}
	got, ok := model.ErrorCodeOf(err)
	if !ok || got != want {
		t.Fatalf("error = %v, code = %q, want %q", err, got, want)
	}
}
