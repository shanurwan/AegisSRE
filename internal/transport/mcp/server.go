package mcptransport

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

func NewReadServer(backend ports.ObserveBackend) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "aegissre-observe", Version: "v0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolQueryMetrics,
		Description: "Run one bounded, allowlisted Kubernetes health metric template. This tool is read-only and cannot accept raw PromQL.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.QueryMetricsInput) (*mcp.CallToolResult, toolapi.QueryMetricsOutput, error) {
		output, err := backend.QueryMetrics(ctx, input)
		return nil, output, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolSearchLogs,
		Description: "Search a bounded time window of namespaced pod logs. This tool is read-only and caps rows, bytes, and lookback.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.SearchLogsInput) (*mcp.CallToolResult, toolapi.SearchLogsOutput, error) {
		output, err := backend.SearchLogs(ctx, input)
		return nil, output, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolGetWorkloadSnapshot,
		Description: "Read deployment status, selected pods, and related warning events in the allowed namespace.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.GetWorkloadSnapshotInput) (*mcp.CallToolResult, toolapi.GetWorkloadSnapshotOutput, error) {
		output, err := backend.GetWorkloadSnapshot(ctx, input)
		return nil, output, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolGetPodLogs,
		Description: "Read a bounded tail of logs from one pod in the allowed namespace; Secrets and exec are never exposed.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.GetPodLogsInput) (*mcp.CallToolResult, toolapi.GetPodLogsOutput, error) {
		output, err := backend.GetPodLogs(ctx, input)
		return nil, output, err
	})
	return server
}

func NewActionServer(backend ports.OperateBackend) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "aegissre-action", Version: "v0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolExecuteRemediation,
		Description: "Execute or Kubernetes-dry-run the exact action in a valid, signed, unexpired AegisSRE delegation grant. Arbitrary patches, shell, exec, delete, and Secrets are not supported.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.ExecuteRemediationInput) (*mcp.CallToolResult, toolapi.ExecuteRemediationOutput, error) {
		output, err := backend.ExecuteRemediation(ctx, input)
		return nil, output, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolGetRemediationStatus,
		Description: "Read the postcondition of the workload named in a valid signed delegation grant.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.GetRemediationStatusInput) (*mcp.CallToolResult, toolapi.GetRemediationStatusOutput, error) {
		output, err := backend.GetRemediationStatus(ctx, input)
		return nil, output, err
	})
	return server
}

func HTTPHandler(server *mcp.Server) http.Handler {
	return mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			Stateless:           true,
			JSONResponse:        true,
			MaxRequestBodyBytes: 1 << 20,
		},
	)
}
