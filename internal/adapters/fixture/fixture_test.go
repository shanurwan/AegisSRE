package fixture

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type detectorClock struct{ now time.Time }

func (c detectorClock) Now() time.Time { return c.now }

func TestFixtureDetectionTemplatesReturnBoundedNormalizedSamples(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 4, 0, 0, 0, time.UTC)
	backend := detectionFixtureBackend(now)
	backend.data.LogSignals = map[string][]toolapi.DetectionSample{
		toolapi.LogErrorBurst5m: {
			{Namespace: "outage-arena", Workload: "demo-api", Value: 6},
			{Namespace: "outage-arena", Workload: "demo-api", Timestamp: now.Add(-10 * time.Minute), Value: 99},
		},
	}
	output, err := backend.QueryLogSignals(context.Background(), toolapi.QueryLogSignalsInput{
		TemplateID: toolapi.LogErrorBurst5m, Namespace: "outage-arena", Workload: "demo-api",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !output.WindowStart.Equal(now.Add(-5*time.Minute)) || !output.WindowEnd.Equal(now) || len(output.Samples) != 1 {
		t.Fatalf("unexpected fixture detection window/result: %#v", output)
	}
	if sample := output.Samples[0]; sample.Value != 6 || !sample.Timestamp.Equal(now) {
		t.Fatalf("unexpected normalized fixture sample: %#v", sample)
	}
}

func TestFixtureDetectionTemplatesFailClosedOnIdentityMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 4, 30, 0, 0, time.UTC)
	backend := detectionFixtureBackend(now)
	backend.data.TraceSignals = map[string][]toolapi.DetectionSample{
		toolapi.TraceErrorCount5m: {
			{Namespace: "another-namespace", Workload: "demo-api", Timestamp: now, Value: 3},
		},
	}
	_, err := backend.QueryTraceSignals(context.Background(), toolapi.QueryTraceSignalsInput{
		TemplateID: toolapi.TraceErrorCount5m, Namespace: "outage-arena",
	})
	if err == nil || !strings.Contains(err.Error(), "exact namespace/workload mapping") {
		t.Fatalf("unmapped fixture identity was not rejected: %v", err)
	}
}

func TestFixtureDetectionTemplatesRequireConfiguredServerTemplate(t *testing.T) {
	t.Parallel()
	backend := detectionFixtureBackend(time.Date(2026, 10, 1, 5, 0, 0, 0, time.UTC))
	_, err := backend.QueryLogSignals(context.Background(), toolapi.QueryLogSignalsInput{
		TemplateID: "caller_supplied_query", Namespace: "outage-arena",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported log detection template") {
		t.Fatalf("caller-supplied fixture template was not rejected: %v", err)
	}
}

func TestFixtureKnownDetectionTemplateMayHaveNoSamples(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 5, 30, 0, 0, time.UTC)
	backend := detectionFixtureBackend(now)
	output, err := backend.QueryTraceSignals(context.Background(), toolapi.QueryTraceSignalsInput{
		TemplateID: toolapi.TraceErrorCount5m, Namespace: "outage-arena", Workload: "demo-api",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !output.WindowStart.Equal(now.Add(-5*time.Minute)) || !output.WindowEnd.Equal(now) || len(output.Samples) != 0 {
		t.Fatalf("unexpected empty fixture detection result: %#v", output)
	}
}

func TestFixtureDetectionTemplatesRejectFractionalCounts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	backend := detectionFixtureBackend(now)
	backend.data.TraceSignals = map[string][]toolapi.DetectionSample{
		toolapi.TraceErrorCount5m: {
			{Namespace: "outage-arena", Workload: "demo-api", Timestamp: now, Value: 1.5},
		},
	}
	_, err := backend.QueryTraceSignals(context.Background(), toolapi.QueryTraceSignalsInput{
		TemplateID: toolapi.TraceErrorCount5m, Namespace: "outage-arena",
	})
	if err == nil || !strings.Contains(err.Error(), "value is invalid") {
		t.Fatalf("fractional fixture detection count was not rejected: %v", err)
	}
}

func detectionFixtureBackend(now time.Time) *Backend {
	return &Backend{
		Clock: detectorClock{now: now},
		data: Data{Snapshot: toolapi.WorkloadSnapshot{Target: model.ResourceTarget{
			APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api",
		}}},
	}
}
