package backend

import (
	"context"

	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type MetricsLogs interface {
	QueryMetrics(context.Context, toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error)
	SearchLogs(context.Context, toolapi.SearchLogsInput) (toolapi.SearchLogsOutput, error)
}

type KubernetesRead interface {
	GetWorkloadSnapshot(context.Context, toolapi.GetWorkloadSnapshotInput) (toolapi.GetWorkloadSnapshotOutput, error)
	GetPodLogs(context.Context, toolapi.GetPodLogsInput) (toolapi.GetPodLogsOutput, error)
}

type Observe struct {
	Telemetry  MetricsLogs
	Kubernetes KubernetesRead
}

func (o Observe) QueryMetrics(ctx context.Context, input toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error) {
	return o.Telemetry.QueryMetrics(ctx, input)
}

func (o Observe) SearchLogs(ctx context.Context, input toolapi.SearchLogsInput) (toolapi.SearchLogsOutput, error) {
	return o.Telemetry.SearchLogs(ctx, input)
}

func (o Observe) GetWorkloadSnapshot(ctx context.Context, input toolapi.GetWorkloadSnapshotInput) (toolapi.GetWorkloadSnapshotOutput, error) {
	return o.Kubernetes.GetWorkloadSnapshot(ctx, input)
}

func (o Observe) GetPodLogs(ctx context.Context, input toolapi.GetPodLogsInput) (toolapi.GetPodLogsOutput, error) {
	return o.Kubernetes.GetPodLogs(ctx, input)
}
