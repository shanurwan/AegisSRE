package a2atransport

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

func TestStructuredA2ARoundTrip(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	handler, _, err := NewHandler(CardConfig{
		Name: "test", Description: "test structured agent", PublicURL: "placeholder",
		SkillID: "test", SkillName: "Test",
	}, func(_ context.Context, in model.Envelope) (model.Envelope, error) {
		return model.NewEnvelope("response", in.IncidentID, in.CorrelationID, in.MessageID,
			model.AgentInvestigator, model.AgentMonitor, model.MessageDiagnosisReport, time.Now(), map[string]string{"ok": "true"})
	})
	if err != nil {
		t.Fatal(err)
	}
	server = httptest.NewServer(handler)
	defer server.Close()

	// Rebuild so the published card points at the actual same-origin endpoint.
	handler, _, err = NewHandler(CardConfig{
		Name: "test", Description: "test structured agent", PublicURL: server.URL,
		SkillID: "test", SkillName: "Test",
	}, func(_ context.Context, in model.Envelope) (model.Envelope, error) {
		return model.NewEnvelope("response", in.IncidentID, in.CorrelationID, in.MessageID,
			model.AgentInvestigator, model.AgentMonitor, model.MessageDiagnosisReport, time.Now(), map[string]string{"ok": "true"})
	})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler

	input, err := model.NewEnvelope("request", "incident", "correlation", "", model.AgentMonitor,
		model.AgentInvestigator, model.MessageInvestigationRequest, time.Now(), map[string]string{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	var output model.Envelope
	if err := NewClient(5*time.Second).Send(context.Background(), server.URL, input, &output); err != nil {
		t.Fatal(err)
	}
	if output.Kind != model.MessageDiagnosisReport || output.CausationID != input.MessageID {
		t.Fatalf("unexpected response: %#v", output)
	}
}
