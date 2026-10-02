package integration_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	backendadapter "github.com/shanurwan/AegisSRE/internal/adapters/backend"
	"github.com/shanurwan/AegisSRE/internal/adapters/fixture"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
	mcptransport "github.com/shanurwan/AegisSRE/internal/transport/mcp"
)

// This crosses the real MCP HTTP transport and proves that caller-controlled
// tool arguments cannot expand the workload policy enforced by the backend.
func TestE2EReadMCPEnforcesExactWorkloadPolicy(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fixtureBackend, err := fixture.Load(filepath.Join("..", "..", "testdata", "fixtures", "unavailable-deployment.json"))
	if err != nil {
		t.Fatal(err)
	}
	target := model.ResourceTarget{
		APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api",
	}
	readBackend, err := backendadapter.NewPolicyObserve(
		fixtureBackend,
		[]security.WorkloadPolicy{{
			Target:               target,
			AllowedActions:       []model.ActionKind{model.ActionRestartDeployment},
			AllowedSignalSources: []model.EvidenceSource{model.EvidenceMetrics},
			MaximumReplicas:      5, MaximumReplicaIncrease: 1,
		}},
		fixtureBackend,
	)
	if err != nil {
		t.Fatal(err)
	}
	client := startMCPClient(t, ctx, "e2e-policy-read-client", mcptransport.HTTPHandler(mcptransport.NewReadServer(readBackend)))

	var metrics toolapi.QueryMetricsOutput
	if err := client.Call(ctx, toolapi.ToolQueryMetrics, toolapi.QueryMetricsInput{
		TemplateID: toolapi.MetricDeploymentUnavailable, Namespace: "outage-arena",
	}, &metrics); err != nil {
		t.Fatalf("authorized namespace scan: %v", err)
	}
	if len(metrics.Samples) != 1 || metrics.Samples[0].Labels["deployment"] != "demo-api" {
		t.Fatalf("authorized metric output = %#v", metrics)
	}

	for name, call := range map[string]func() error{
		"foreign workload": func() error {
			return client.Call(ctx, toolapi.ToolQueryMetrics, toolapi.QueryMetricsInput{
				TemplateID: toolapi.MetricDeploymentUnavailable,
				Namespace:  "outage-arena",
				Workload:   "foreign",
			}, &toolapi.QueryMetricsOutput{})
		},
		"foreign namespace": func() error {
			return client.Call(ctx, toolapi.ToolGetWorkloadSnapshot, toolapi.GetWorkloadSnapshotInput{
				Namespace: "kube-system", Kind: "Deployment", Name: "demo-api",
			}, &toolapi.GetWorkloadSnapshotOutput{})
		},
		"disallowed signal": func() error {
			return client.Call(ctx, toolapi.ToolQueryLogSignals, toolapi.QueryLogSignalsInput{
				TemplateID: toolapi.LogErrorBurst5m,
				Namespace:  "outage-arena",
				Workload:   "demo-api",
			}, &toolapi.QueryLogSignalsOutput{})
		},
		"unowned raw log search": func() error {
			return client.Call(ctx, toolapi.ToolSearchLogs, toolapi.SearchLogsInput{
				Namespace: "outage-arena", Pod: "foreign-pod",
			}, &toolapi.SearchLogsOutput{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("out-of-policy MCP call succeeded")
			}
		})
	}
}
