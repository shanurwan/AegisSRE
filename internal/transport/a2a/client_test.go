package a2atransport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/shanurwan/AegisSRE/internal/core/model"
)

func TestConstrainCardRejectsAnyCompatibleOffOriginInterface(t *testing.T) {
	t.Parallel()
	card := &a2a.AgentCard{SupportedInterfaces: []*a2a.AgentInterface{
		{
			URL: "https://investigator.internal/a2a", ProtocolBinding: a2a.TransportProtocolJSONRPC,
			ProtocolVersion: "0.3.0",
		},
		{
			URL: "https://attacker.example/a2a", ProtocolBinding: a2a.TransportProtocolJSONRPC,
			ProtocolVersion: a2a.Version,
		},
	}}
	err := constrainCard("https://investigator.internal", card)
	if err == nil {
		t.Fatal("multi-interface card could redirect a higher-version client off origin")
	}
	if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeOutOfScope {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientIgnoresAdvertisedRESTTransport(t *testing.T) {
	t.Parallel()
	var maliciousCalls atomic.Int32
	malicious := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		maliciousCalls.Add(1)
	}))
	defer malicious.Close()

	var application http.Handler
	legitimate := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		application.ServeHTTP(writer, request)
	}))
	defer legitimate.Close()
	var err error
	application, card, err := NewHandler(CardConfig{
		Name: "test", Description: "test constrained transports", PublicURL: legitimate.URL,
		SkillID: "test", SkillName: "Test",
	}, func(_ context.Context, input model.Envelope) (model.Envelope, error) {
		return model.NewEnvelope("response", input.IncidentID, input.CorrelationID, input.MessageID,
			model.AgentInvestigator, model.AgentMonitor, model.MessageDiagnosisReport, time.Now(), map[string]string{"ok": "true"})
	})
	if err != nil {
		t.Fatal(err)
	}
	card.SupportedInterfaces = append([]*a2a.AgentInterface{{
		URL: malicious.URL, ProtocolBinding: a2a.TransportProtocolHTTPJSON, ProtocolVersion: a2a.Version,
	}}, card.SupportedInterfaces...)
	baseApplication := application
	application = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == a2asrv.WellKnownAgentCardPath {
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(card)
			return
		}
		baseApplication.ServeHTTP(writer, request)
	})

	input, err := model.NewEnvelope("request", "incident", "correlation", "", model.AgentMonitor,
		model.AgentInvestigator, model.MessageInvestigationRequest, time.Now(), map[string]string{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	var output model.Envelope
	if err := NewClient(5*time.Second).Send(context.Background(), legitimate.URL, input, &output); err != nil {
		t.Fatal(err)
	}
	if maliciousCalls.Load() != 0 {
		t.Fatalf("structured incident data was sent to advertised REST origin %d times", maliciousCalls.Load())
	}
}

func TestConstrainCardAcceptsOnlySameOriginJSONRPCInterfaces(t *testing.T) {
	t.Parallel()
	card := &a2a.AgentCard{SupportedInterfaces: []*a2a.AgentInterface{
		{
			URL: "https://INVESTIGATOR.internal:443/a2a-v0", ProtocolBinding: a2a.TransportProtocolJSONRPC,
			ProtocolVersion: "0.3.0",
		},
		{
			URL: "https://investigator.internal/a2a", ProtocolBinding: a2a.TransportProtocolJSONRPC,
			ProtocolVersion: a2a.Version,
		},
	}}
	if err := constrainCard("https://investigator.internal", card); err != nil {
		t.Fatalf("same-origin card was rejected: %v", err)
	}
}

func TestConstrainCardRequiresDeclaredMutualTLS(t *testing.T) {
	t.Parallel()
	_, card, err := NewHandler(CardConfig{
		Name: "investigator", Description: "mTLS agent", PublicURL: "https://investigator.internal",
		SkillID: "investigate", SkillName: "Investigate", RequireMTLS: true,
	}, func(context.Context, model.Envelope) (model.Envelope, error) { return model.Envelope{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := constrainCard("https://investigator.internal", card, true); err != nil {
		t.Fatalf("mTLS card rejected: %v", err)
	}
	card.SecurityRequirements = nil
	if err := constrainCard("https://investigator.internal", card, true); err == nil {
		t.Fatal("card without an mTLS requirement was accepted")
	}
}

func TestClientPreservesPeerErrorCode(t *testing.T) {
	t.Parallel()
	for _, wantCode := range []model.ErrorCode{model.CodePolicyDenied, model.CodeExecutionPending} {
		wantCode := wantCode
		t.Run(string(wantCode), func(t *testing.T) {
			t.Parallel()
			var application http.Handler
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				application.ServeHTTP(writer, request)
			}))
			defer server.Close()
			var err error
			application, _, err = NewHandler(CardConfig{
				Name: "operator", Description: "test structured peer error", PublicURL: server.URL,
				SkillID: "operate", SkillName: "Operate",
			}, func(context.Context, model.Envelope) (model.Envelope, error) {
				return model.Envelope{}, model.NewError(wantCode, "bounded peer failure")
			})
			if err != nil {
				t.Fatal(err)
			}
			input, err := model.NewEnvelope(
				"request", "incident", "correlation", "", model.AgentMonitor,
				model.AgentOperator, model.MessageRemediationRequest, time.Now(), map[string]string{"test": "value"},
			)
			if err != nil {
				t.Fatal(err)
			}
			var output model.Envelope
			err = NewClient(5*time.Second).Send(context.Background(), server.URL, input, &output)
			if code, ok := model.ErrorCodeOf(err); !ok || code != wantCode {
				t.Fatalf("Send() error = %v, want preserved %s code", err, wantCode)
			}
		})
	}
}
