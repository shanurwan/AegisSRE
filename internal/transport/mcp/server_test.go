package mcptransport

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type observeStub struct{}

func (observeStub) QueryMetrics(_ context.Context, input toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error) {
	return toolapi.QueryMetricsOutput{TemplateID: input.TemplateID}, nil
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
	for _, tool := range tools.Tools {
		if tool.Name == toolapi.ToolExecuteRemediation {
			t.Fatal("read MCP server exposed a mutation tool")
		}
	}
}
