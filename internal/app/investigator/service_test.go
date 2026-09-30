package investigator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

func TestInvestigateHonorsEvidenceAndToolCallBudgets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		maxToolCalls  int
		maxEvidence   int
		wantToolCalls int
		wantEvidence  int
	}{
		{name: "tool call budget stops pod log collection", maxToolCalls: 1, maxEvidence: 4, wantToolCalls: 1, wantEvidence: 1},
		{name: "evidence budget stops pod log collection", maxToolCalls: 4, maxEvidence: 2, wantToolCalls: 2, wantEvidence: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 9, 30, 4, 0, 0, 0, time.UTC)
			tools := &investigatorToolFake{snapshot: unhealthySnapshot(now)}
			reasoner := &capturingReasoner{}
			ids := &investigatorIDs{}
			service := &Service{
				Tools: tools, Reasoner: reasoner, Clock: investigatorClock{now: now}, IDs: ids,
				MaxLogBytes: 4096,
			}
			request := investigationRequest(t, now, tt.maxToolCalls, tt.maxEvidence)

			report, err := service.Investigate(context.Background(), request)
			if err != nil {
				t.Fatalf("Investigate() error = %v", err)
			}
			if err := report.VerifyDigest(); err != nil {
				t.Fatalf("returned diagnosis is not sealed: %v", err)
			}
			if got := len(tools.calls); got != tt.wantToolCalls {
				t.Fatalf("tool calls = %d, want %d (%v)", got, tt.wantToolCalls, tools.calls)
			}
			if got := len(reasoner.evidence); got != tt.wantEvidence {
				t.Fatalf("evidence count = %d, want %d", got, tt.wantEvidence)
			}
			for _, name := range tools.calls {
				switch name {
				case toolapi.ToolGetWorkloadSnapshot, toolapi.ToolGetPodLogs:
					// These are the only read-only tools used by this investigation path.
				default:
					t.Fatalf("Investigator called non-read or unexpected tool %q", name)
				}
			}
			if tools.calls[0] != toolapi.ToolGetWorkloadSnapshot {
				t.Fatalf("first tool = %q, want workload snapshot", tools.calls[0])
			}
		})
	}
}

type investigatorToolFake struct {
	calls    []string
	snapshot toolapi.WorkloadSnapshot
}

func (f *investigatorToolFake) Discover(context.Context) ([]string, error) {
	return []string{toolapi.ToolGetWorkloadSnapshot, toolapi.ToolGetPodLogs}, nil
}

func (f *investigatorToolFake) Call(_ context.Context, name string, input, output any) error {
	f.calls = append(f.calls, name)
	switch name {
	case toolapi.ToolGetWorkloadSnapshot:
		request, ok := input.(toolapi.GetWorkloadSnapshotInput)
		if !ok {
			return fmt.Errorf("unexpected snapshot input %T", input)
		}
		if request.Namespace != "outage-arena" || request.Kind != "Deployment" || request.Name != "demo-api" {
			return fmt.Errorf("snapshot escaped requested target: %#v", request)
		}
		result, ok := output.(*toolapi.GetWorkloadSnapshotOutput)
		if !ok {
			return fmt.Errorf("unexpected snapshot output %T", output)
		}
		result.Snapshot = f.snapshot
		return nil
	case toolapi.ToolGetPodLogs:
		request, ok := input.(toolapi.GetPodLogsInput)
		if !ok {
			return fmt.Errorf("unexpected pod log input %T", input)
		}
		if request.Namespace != "outage-arena" || request.MaxBytes != 4096 {
			return fmt.Errorf("pod log request exceeded bounds: %#v", request)
		}
		result, ok := output.(*toolapi.GetPodLogsOutput)
		if !ok {
			return fmt.Errorf("unexpected pod log output %T", output)
		}
		result.Pod = request.Pod
		result.Container = request.Container
		result.Logs = "bounded fixture log"
		return nil
	default:
		return fmt.Errorf("unexpected tool %q", name)
	}
}

func (*investigatorToolFake) Close() error { return nil }

type capturingReasoner struct {
	evidence []model.EvidenceItem
}

func (r *capturingReasoner) Diagnose(_ context.Context, _ model.InvestigationRequest, evidence []model.EvidenceItem) (model.DiagnosisReport, error) {
	r.evidence = append([]model.EvidenceItem(nil), evidence...)
	evidenceIDs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		evidenceIDs = append(evidenceIDs, item.ID)
	}
	return model.DiagnosisReport{
		Status: model.DiagnosisInconclusive, Confidence: 0.4, EvidenceIDs: evidenceIDs,
	}, nil
}

type investigatorClock struct{ now time.Time }

func (c investigatorClock) Now() time.Time { return c.now }

type investigatorIDs struct{ next int }

func (g *investigatorIDs) NewID() string {
	g.next++
	return fmt.Sprintf("id-%d", g.next)
}

func investigationRequest(t *testing.T, now time.Time, maxToolCalls, maxEvidence int) model.InvestigationRequest {
	t.Helper()
	signal := model.IncidentSignal{
		ID: "signal-1", Source: "test", RuleID: "deployment-unavailable",
		Fingerprint: "fingerprint-1", Summary: "deployment unavailable",
		Severity: model.SeverityCritical, ObservedAt: now,
	}
	incident, err := model.NewIncident("incident-1", signal, now)
	if err != nil {
		t.Fatalf("NewIncident() error = %v", err)
	}
	for _, state := range []model.IncidentState{model.IncidentVerifying, model.IncidentVerified, model.IncidentInvestigating} {
		if err := incident.Transition(state, now); err != nil {
			t.Fatalf("Transition(%s) error = %v", state, err)
		}
	}
	target := model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api"}
	return model.InvestigationRequest{
		SchemaVersion: model.SchemaVersionV1,
		Incident:      incident,
		Scope:         model.InvestigationScope{Namespaces: []string{"outage-arena"}, Targets: []model.ResourceTarget{target}},
		Budget:        model.InvestigationBudget{MaxToolCalls: maxToolCalls, MaxEvidence: maxEvidence, Timeout: time.Second},
		RequestedAt:   now,
	}
}

func unhealthySnapshot(now time.Time) toolapi.WorkloadSnapshot {
	target := model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api"}
	pods := make([]toolapi.PodSnapshot, 0, 3)
	for i := 1; i <= 3; i++ {
		pods = append(pods, toolapi.PodSnapshot{
			Name: fmt.Sprintf("demo-api-%d", i), Phase: "Running", Ready: false, CreatedAt: now,
			Containers: []toolapi.ContainerSnapshot{{Name: "demo-api", Ready: false, Reason: "ReadinessProbeFailed"}},
		})
	}
	return toolapi.WorkloadSnapshot{
		Target: target, ResourceVersion: "rv-1", Generation: 1, ObservedGeneration: 1,
		DesiredReplicas: 3, ReadyReplicas: 0, AvailableReplicas: 0, UnavailableReplicas: 3,
		Pods: pods, ObservedAt: now,
	}
}
