package backend

import (
	"context"
	"testing"

	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type detectorTelemetryStub struct {
	logInput   toolapi.QueryLogSignalsInput
	traceInput toolapi.QueryTraceSignalsInput
}

func (s *detectorTelemetryStub) QueryMetrics(context.Context, toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error) {
	return toolapi.QueryMetricsOutput{}, nil
}

func (s *detectorTelemetryStub) QueryLogSignals(_ context.Context, input toolapi.QueryLogSignalsInput) (toolapi.QueryLogSignalsOutput, error) {
	s.logInput = input
	return toolapi.QueryLogSignalsOutput{TemplateID: input.TemplateID}, nil
}

func (s *detectorTelemetryStub) QueryTraceSignals(_ context.Context, input toolapi.QueryTraceSignalsInput) (toolapi.QueryTraceSignalsOutput, error) {
	s.traceInput = input
	return toolapi.QueryTraceSignalsOutput{TemplateID: input.TemplateID}, nil
}

func (s *detectorTelemetryStub) SearchLogs(context.Context, toolapi.SearchLogsInput) (toolapi.SearchLogsOutput, error) {
	return toolapi.SearchLogsOutput{}, nil
}

func TestObserveForwardsDetectionTemplates(t *testing.T) {
	t.Parallel()
	telemetry := &detectorTelemetryStub{}
	observe := Observe{Telemetry: telemetry}
	logInput := toolapi.QueryLogSignalsInput{
		TemplateID: toolapi.LogErrorBurst5m, Namespace: "outage-arena", Workload: "demo-api",
	}
	logOutput, err := observe.QueryLogSignals(context.Background(), logInput)
	if err != nil {
		t.Fatal(err)
	}
	if telemetry.logInput != logInput || logOutput.TemplateID != logInput.TemplateID {
		t.Fatalf("log detector was not forwarded exactly: input=%#v output=%#v", telemetry.logInput, logOutput)
	}

	traceInput := toolapi.QueryTraceSignalsInput{
		TemplateID: toolapi.TraceErrorCount5m, Namespace: "outage-arena", Workload: "demo-api",
	}
	traceOutput, err := observe.QueryTraceSignals(context.Background(), traceInput)
	if err != nil {
		t.Fatal(err)
	}
	if telemetry.traceInput != traceInput || traceOutput.TemplateID != traceInput.TemplateID {
		t.Fatalf("trace detector was not forwarded exactly: input=%#v output=%#v", telemetry.traceInput, traceOutput)
	}
}
