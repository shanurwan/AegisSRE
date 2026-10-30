package a2atransport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2asrv"

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

// The Agent Card is a public discovery document. A cross-origin read must get
// the wildcard, never the caller's origin echoed back with credentials.
func TestAgentCardNeverGrantsCredentialedCrossOriginReads(t *testing.T) {
	t.Parallel()
	handler, _, err := NewHandler(CardConfig{
		Name: "test", Description: "test structured agent", PublicURL: "https://agent.example",
		SkillID: "test", SkillName: "Test",
	}, func(context.Context, model.Envelope) (model.Envelope, error) {
		return model.Envelope{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		request := httptest.NewRequest(method, a2asrv.WellKnownAgentCardPath, nil)
		request.Header.Set("Origin", "https://attacker.example")
		request.Header.Set("Access-Control-Request-Method", http.MethodGet)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("%s Access-Control-Allow-Origin = %q, want *", method, got)
		}
		if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Fatalf("%s Access-Control-Allow-Credentials = %q, want unset", method, got)
		}
	}
}

func TestAgentFactsAreServedBesideTheCardOnlyWhenConfigured(t *testing.T) {
	t.Parallel()
	handle := func(context.Context, model.Envelope) (model.Envelope, error) { return model.Envelope{}, nil }
	config := CardConfig{
		Name: "test", Description: "test structured agent", PublicURL: "https://agent.example",
		SkillID: "test", SkillName: "Test",
	}
	without, _, err := NewHandler(config, handle)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	without.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, AgentFactsPath, nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("AgentFacts served without configuration: HTTP %d", recorder.Code)
	}

	config.AgentFacts = []byte(`{"id":"urn:air:agent.example:agent:test"}`)
	with, _, err := NewHandler(config, handle)
	if err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	with.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, AgentFactsPath, nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != string(config.AgentFacts) {
		t.Fatalf("AgentFacts = HTTP %d %q", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
}
