// Package toolapi contains the narrow typed contracts exposed by MCP.
package toolapi

import (
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

const (
	ToolQueryMetrics         = "metrics_query_template"
	ToolQueryLogSignals      = "logs_query_template"
	ToolQueryTraceSignals    = "traces_query_template"
	ToolSearchLogs           = "logs_search"
	ToolGetWorkloadSnapshot  = "k8s_get_workload_snapshot"
	ToolGetPodLogs           = "k8s_get_pod_logs"
	ToolExecuteRemediation   = "k8s_execute_remediation"
	ToolGetRemediationStatus = "k8s_get_remediation_status"
)

const (
	MetricDeploymentUnavailable = "deployment_unavailable"
	MetricDeploymentAvailable   = "deployment_available"
	MetricPodCrashLoop          = "pod_crashloop"
	MetricContainerRestarts     = "container_restarts_5m"
	MetricPodNotReady           = "pod_not_ready"
)

const (
	LogErrorBurst5m             = "log_error_burst_5m"
	LogDependencyTimeoutBurst5m = "log_dependency_timeout_burst_5m"
	TraceErrorCount5m           = "trace_error_count_5m"
	TraceSlowServerCount5m      = "trace_slow_server_count_5m"
)

type QueryMetricsInput struct {
	TemplateID string `json:"template_id" jsonschema:"one of the advertised bounded metric templates"`
	Namespace  string `json:"namespace" jsonschema:"Kubernetes namespace"`
	Workload   string `json:"workload,omitempty" jsonschema:"optional deployment name"`
}

type MetricSample struct {
	Labels    map[string]string `json:"labels"`
	Timestamp time.Time         `json:"timestamp"`
	Value     float64           `json:"value"`
}

type QueryMetricsOutput struct {
	TemplateID string         `json:"template_id"`
	Query      string         `json:"query"`
	Samples    []MetricSample `json:"samples"`
	ObservedAt time.Time      `json:"observed_at"`
}

// DetectionSample is the normalized result shared by server-owned log and
// trace detection templates. Workload always names a Deployment in Namespace.
type DetectionSample struct {
	Namespace string    `json:"namespace"`
	Workload  string    `json:"workload"`
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

type QueryLogSignalsInput struct {
	TemplateID string `json:"template_id" jsonschema:"one of the advertised bounded log detection templates"`
	Namespace  string `json:"namespace" jsonschema:"Kubernetes namespace"`
	Workload   string `json:"workload,omitempty" jsonschema:"optional deployment name"`
}

type QueryLogSignalsOutput struct {
	TemplateID  string            `json:"template_id"`
	WindowStart time.Time         `json:"window_start"`
	WindowEnd   time.Time         `json:"window_end"`
	Samples     []DetectionSample `json:"samples"`
}

type QueryTraceSignalsInput struct {
	TemplateID string `json:"template_id" jsonschema:"one of the advertised bounded trace detection templates"`
	Namespace  string `json:"namespace" jsonschema:"Kubernetes namespace"`
	Workload   string `json:"workload,omitempty" jsonschema:"optional deployment name"`
}

type QueryTraceSignalsOutput struct {
	TemplateID  string            `json:"template_id"`
	WindowStart time.Time         `json:"window_start"`
	WindowEnd   time.Time         `json:"window_end"`
	Samples     []DetectionSample `json:"samples"`
}

type SearchLogsInput struct {
	Namespace       string `json:"namespace"`
	Pod             string `json:"pod,omitempty"`
	Contains        string `json:"contains,omitempty"`
	LookbackMinutes int    `json:"lookback_minutes,omitempty"`
	Limit           int    `json:"limit,omitempty"`
}

type LogLine struct {
	Timestamp time.Time         `json:"timestamp"`
	Message   string            `json:"message"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type SearchLogsOutput struct {
	Lines     []LogLine `json:"lines"`
	Truncated bool      `json:"truncated"`
}

type GetWorkloadSnapshotInput struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
}

type ContainerSnapshot struct {
	Name         string `json:"name"`
	Ready        bool   `json:"ready"`
	RestartCount int32  `json:"restart_count"`
	Reason       string `json:"reason,omitempty"`
	Message      string `json:"message,omitempty"`
	LastReason   string `json:"last_reason,omitempty"`
}

type PodSnapshot struct {
	Name       string              `json:"name"`
	Phase      string              `json:"phase"`
	Ready      bool                `json:"ready"`
	Node       string              `json:"node,omitempty"`
	CreatedAt  time.Time           `json:"created_at"`
	Containers []ContainerSnapshot `json:"containers"`
}

type EventSnapshot struct {
	Type     string    `json:"type"`
	Reason   string    `json:"reason"`
	Message  string    `json:"message"`
	Object   string    `json:"object"`
	Count    int32     `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

type WorkloadSnapshot struct {
	Target              model.ResourceTarget `json:"target"`
	ResourceVersion     string               `json:"resource_version"`
	Generation          int64                `json:"generation"`
	ObservedGeneration  int64                `json:"observed_generation"`
	DesiredReplicas     int32                `json:"desired_replicas"`
	ReadyReplicas       int32                `json:"ready_replicas"`
	AvailableReplicas   int32                `json:"available_replicas"`
	UnavailableReplicas int32                `json:"unavailable_replicas"`
	Selector            string               `json:"selector"`
	Pods                []PodSnapshot        `json:"pods"`
	Events              []EventSnapshot      `json:"events"`
	ObservedAt          time.Time            `json:"observed_at"`
}

type GetWorkloadSnapshotOutput struct {
	Snapshot WorkloadSnapshot `json:"snapshot"`
}

type GetPodLogsInput struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container,omitempty"`
	TailLines int64  `json:"tail_lines,omitempty"`
	Previous  bool   `json:"previous,omitempty"`
	MaxBytes  int    `json:"max_bytes,omitempty"`
}

type GetPodLogsOutput struct {
	Pod       string `json:"pod"`
	Container string `json:"container,omitempty"`
	Logs      string `json:"logs"`
	Truncated bool   `json:"truncated"`
}

type ExecuteRemediationInput struct {
	Grant  model.DelegationGrant `json:"grant"`
	DryRun bool                  `json:"dry_run"`
}

type ExecuteRemediationOutput struct {
	Receipt model.ActionReceipt `json:"receipt"`
}

type GetRemediationStatusInput struct {
	Grant model.DelegationGrant `json:"grant"`
}

type GetRemediationStatusOutput struct {
	Snapshot  WorkloadSnapshot `json:"snapshot"`
	Satisfied bool             `json:"satisfied"`
	Detail    string           `json:"detail"`
}
