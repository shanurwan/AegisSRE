package mcptransport

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/shanurwan/AegisSRE/internal/core/model"
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
		return toolResponse(output, err)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolQueryLogSignals,
		Description: "Run one bounded, server-owned namespaced log detection template. This tool cannot accept raw LogsQL, search text, time ranges, or thresholds.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.QueryLogSignalsInput) (*mcp.CallToolResult, toolapi.QueryLogSignalsOutput, error) {
		output, err := backend.QueryLogSignals(ctx, input)
		return toolResponse(output, err)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolQueryTraceSignals,
		Description: "Run one bounded, server-owned namespaced trace detection template. This tool cannot accept raw LogsQL, TraceQL, tags, time ranges, or thresholds.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.QueryTraceSignalsInput) (*mcp.CallToolResult, toolapi.QueryTraceSignalsOutput, error) {
		output, err := backend.QueryTraceSignals(ctx, input)
		return toolResponse(output, err)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolSearchLogs,
		Description: "Search a bounded time window of namespaced pod logs. This tool is read-only and caps rows, bytes, and lookback.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.SearchLogsInput) (*mcp.CallToolResult, toolapi.SearchLogsOutput, error) {
		output, err := backend.SearchLogs(ctx, input)
		return toolResponse(output, err)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolGetWorkloadSnapshot,
		Description: "Read deployment status, selected pods, and related warning events in the allowed namespace.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.GetWorkloadSnapshotInput) (*mcp.CallToolResult, toolapi.GetWorkloadSnapshotOutput, error) {
		output, err := backend.GetWorkloadSnapshot(ctx, input)
		return toolResponse(output, err)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolGetPodLogs,
		Description: "Read a bounded tail of logs from one pod in the allowed namespace; Secrets and exec are never exposed.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.GetPodLogsInput) (*mcp.CallToolResult, toolapi.GetPodLogsOutput, error) {
		output, err := backend.GetPodLogs(ctx, input)
		return toolResponse(output, err)
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
		return toolResponse(output, err)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolGetRemediationResult,
		Description: "Read the durable action result for the exact signed grant fingerprint. This lookup never reserves, authorizes, or mutates and may recover a completed receipt after grant expiry.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.GetRemediationResultInput) (*mcp.CallToolResult, toolapi.GetRemediationResultOutput, error) {
		output, err := backend.GetRemediationResult(ctx, input)
		return toolResponse(output, err)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolapi.ToolGetRemediationStatus,
		Description: "Read the postcondition of the workload named in a valid signed delegation grant.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input toolapi.GetRemediationStatusInput) (*mcp.CallToolResult, toolapi.GetRemediationStatusOutput, error) {
		output, err := backend.GetRemediationStatus(ctx, input)
		return toolResponse(output, err)
	})
	return server
}

const toolErrorSchemaV1 = "aegissre.io/mcp-error/v1"

type toolFailure struct {
	SchemaVersion string          `json:"schema_version"`
	Code          model.ErrorCode `json:"code"`
	Message       string          `json:"message"`
}

func toolResponse[T any](output T, err error) (*mcp.CallToolResult, T, error) {
	if err == nil {
		return nil, output, nil
	}
	code, ok := model.ErrorCodeOf(err)
	if !ok || !knownToolErrorCode(code) {
		code = model.CodeExecutionFailed
	}
	failure := toolFailure{
		SchemaVersion: toolErrorSchemaV1,
		Code:          code,
		// Do not serialize adapter or provider error strings across the trust
		// boundary; they may contain endpoints or credentials. The stable code is
		// the protocol contract and the server keeps the detailed error locally.
		Message: "constrained MCP tool returned " + string(code),
	}
	payload, marshalErr := json.Marshal(failure)
	if marshalErr != nil {
		return nil, output, marshalErr
	}
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: string(payload)}},
	}, output, nil
}

func knownToolErrorCode(code model.ErrorCode) bool {
	switch code {
	case model.CodeInvalidInput,
		model.CodeInvalidStateTransition,
		model.CodeOutOfScope,
		model.CodeDelegationRequired,
		model.CodePolicyDenied,
		model.CodeInvalidSignature,
		model.CodeGrantNotYetValid,
		model.CodeGrantExpired,
		model.CodeReplayedGrant,
		model.CodeExecutionPending,
		model.CodeStalePrecondition,
		model.CodeToolBudgetExceeded,
		model.CodeInconclusiveDiagnosis,
		model.CodeExecutionFailed:
		return true
	default:
		return false
	}
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
