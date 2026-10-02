package mcptransport

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type observeStub struct{}

func (observeStub) QueryMetrics(_ context.Context, input toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error) {
	return toolapi.QueryMetricsOutput{TemplateID: input.TemplateID}, nil
}

type failingObserveStub struct{ observeStub }

func (failingObserveStub) QueryMetrics(context.Context, toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error) {
	return toolapi.QueryMetricsOutput{}, model.NewError(model.CodeOutOfScope, "caller-selected workload is outside policy")
}
func (observeStub) QueryLogSignals(_ context.Context, input toolapi.QueryLogSignalsInput) (toolapi.QueryLogSignalsOutput, error) {
	return toolapi.QueryLogSignalsOutput{TemplateID: input.TemplateID}, nil
}
func (observeStub) QueryTraceSignals(_ context.Context, input toolapi.QueryTraceSignalsInput) (toolapi.QueryTraceSignalsOutput, error) {
	return toolapi.QueryTraceSignalsOutput{TemplateID: input.TemplateID}, nil
}
func (observeStub) SearchLogs(context.Context, toolapi.SearchLogsInput) (toolapi.SearchLogsOutput, error) {
	return toolapi.SearchLogsOutput{}, nil
}
func (observeStub) GetWorkloadSnapshot(context.Context, toolapi.GetWorkloadSnapshotInput) (toolapi.GetWorkloadSnapshotOutput, error) {
	return toolapi.GetWorkloadSnapshotOutput{}, nil
}
func (observeStub) GetPodLogs(context.Context, toolapi.GetPodLogsInput) (toolapi.GetPodLogsOutput, error) {
	return toolapi.GetPodLogsOutput{}, nil
}

type detectorDispatchStub struct {
	observeStub
	logInputs   chan toolapi.QueryLogSignalsInput
	traceInputs chan toolapi.QueryTraceSignalsInput
}

func (s *detectorDispatchStub) QueryLogSignals(_ context.Context, input toolapi.QueryLogSignalsInput) (toolapi.QueryLogSignalsOutput, error) {
	s.logInputs <- input
	return toolapi.QueryLogSignalsOutput{TemplateID: input.TemplateID}, nil
}

func (s *detectorDispatchStub) QueryTraceSignals(_ context.Context, input toolapi.QueryTraceSignalsInput) (toolapi.QueryTraceSignalsOutput, error) {
	s.traceInputs <- input
	return toolapi.QueryTraceSignalsOutput{TemplateID: input.TemplateID}, nil
}

func TestReadServerExposesNoMutationTools(t *testing.T) {
	t.Parallel()
	server := NewReadServer(observeStub{})
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := make(map[string]bool, len(tools.Tools))
	for _, tool := range tools.Tools {
		found[tool.Name] = true
		if tool.Name == toolapi.ToolExecuteRemediation {
			t.Fatal("read MCP server exposed a mutation tool")
		}
	}
	for _, name := range []string{toolapi.ToolQueryLogSignals, toolapi.ToolQueryTraceSignals} {
		if !found[name] {
			t.Fatalf("read MCP server did not expose %q", name)
		}
	}
}

func TestReadServerDispatchesDetectionTools(t *testing.T) {
	t.Parallel()
	backend := &detectorDispatchStub{
		logInputs: make(chan toolapi.QueryLogSignalsInput, 1), traceInputs: make(chan toolapi.QueryTraceSignalsInput, 1),
	}
	server := NewReadServer(backend)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	logInput := toolapi.QueryLogSignalsInput{
		TemplateID: toolapi.LogErrorBurst5m, Namespace: "outage-arena", Workload: "demo-api",
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: toolapi.ToolQueryLogSignals, Arguments: logInput})
	if err != nil || result.IsError {
		t.Fatalf("call log detector: result=%#v err=%v", result, err)
	}
	if got := <-backend.logInputs; got != logInput {
		t.Fatalf("log detector input = %#v, want %#v", got, logInput)
	}

	traceInput := toolapi.QueryTraceSignalsInput{
		TemplateID: toolapi.TraceErrorCount5m, Namespace: "outage-arena", Workload: "demo-api",
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: toolapi.ToolQueryTraceSignals, Arguments: traceInput})
	if err != nil || result.IsError {
		t.Fatalf("call trace detector: result=%#v err=%v", result, err)
	}
	if got := <-backend.traceInputs; got != traceInput {
		t.Fatalf("trace detector input = %#v, want %#v", got, traceInput)
	}
}

func TestClientPreservesStructuredToolErrorCode(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(HTTPHandler(NewReadServer(failingObserveStub{})))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := Connect(ctx, server.URL, "structured-error-test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	err = client.Call(ctx, toolapi.ToolQueryMetrics, toolapi.QueryMetricsInput{
		TemplateID: toolapi.MetricDeploymentUnavailable,
		Namespace:  "outside-policy",
	}, &toolapi.QueryMetricsOutput{})
	if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeOutOfScope {
		t.Fatalf("Call() error = %v, code = %q, want %q", err, code, model.CodeOutOfScope)
	}
}
