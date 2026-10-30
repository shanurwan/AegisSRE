package a2atransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/transport/authn"
)

type Handler func(context.Context, model.Envelope) (model.Envelope, error)

type CardConfig struct {
	Name        string
	Description string
	PublicURL   string
	SkillID     string
	SkillName   string
	Examples    []string
	RequireMTLS bool
	// AgentFacts, when set, is a signed AgentFacts document served beside the
	// Agent Card at AgentFactsPath for NANDA discovery.
	AgentFacts []byte
}

// AgentFactsPath is where a signed AgentFacts document is published.
const AgentFactsPath = "/agentfacts.json"

type executor struct {
	handle      Handler
	requireMTLS bool
}

func (e *executor) Execute(ctx context.Context, execCtx *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		if execCtx == nil || execCtx.Message == nil {
			yield(nil, fmt.Errorf("A2A request omitted a message"))
			return
		}
		if !yield(a2a.NewSubmittedTask(execCtx, execCtx.Message), nil) {
			return
		}
		if !yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateWorking,
			a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("processing structured request"))), nil) {
			return
		}
		envelope, err := envelopeFromParts(execCtx.Message.Parts)
		if err != nil {
			e.fail(execCtx, err, yield)
			return
		}
		if e.requireMTLS {
			if err := authn.RequireAgent(ctx, envelope.Sender); err != nil {
				e.fail(execCtx, err, yield)
				return
			}
		}
		response, err := e.handle(ctx, envelope)
		if err != nil {
			e.fail(execCtx, err, yield)
			return
		}
		data, err := structuredData(response)
		if err != nil {
			e.fail(execCtx, err, yield)
			return
		}
		artifact := a2a.NewArtifactEvent(execCtx, a2a.NewDataPart(data))
		artifact.LastChunk = true
		if !yield(artifact, nil) {
			return
		}
		yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateCompleted,
			a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("completed"))), nil)
	}
}

func structuredData(value any) (map[string]any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, model.WrapError(model.CodeInvalidInput, "encode A2A structured data", err)
	}
	var data map[string]any
	if err := json.Unmarshal(encoded, &data); err != nil {
		return nil, model.WrapError(model.CodeInvalidInput, "normalize A2A structured data", err)
	}
	return data, nil
}

func (e *executor) Cancel(_ context.Context, execCtx *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateCanceled, nil), nil)
	}
}

func (*executor) fail(execCtx *a2asrv.ExecutorContext, err error, yield func(a2a.Event, error) bool) {
	code, ok := model.ErrorCodeOf(err)
	if !ok {
		code = model.CodeExecutionFailed
	}
	// Keep the artifact in the same structured-data representation as normal
	// A2A envelopes. The SDK's task processor deep-copies this value and does
	// not register map[string]string as an interface-backed gob type.
	payload := map[string]any{"code": string(code), "message": err.Error()}
	artifact := a2a.NewArtifactEvent(execCtx, a2a.NewDataPart(payload))
	artifact.LastChunk = true
	if !yield(artifact, nil) {
		return
	}
	yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateFailed,
		a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart(string(code)))), nil)
}

func NewHandler(config CardConfig, handle Handler) (http.Handler, *a2a.AgentCard, error) {
	if config.Name == "" || config.Description == "" || config.PublicURL == "" || config.SkillID == "" || config.SkillName == "" || handle == nil {
		return nil, nil, fmt.Errorf("A2A card config and handler are required")
	}
	card := &a2a.AgentCard{
		Name: config.Name, Description: config.Description, Version: "0.1.0",
		SupportedInterfaces: []*a2a.AgentInterface{
			a2a.NewAgentInterface(config.PublicURL+"/a2a", a2a.TransportProtocolJSONRPC),
		},
		Capabilities:       a2a.AgentCapabilities{Streaming: false},
		DefaultInputModes:  []string{"application/json"},
		DefaultOutputModes: []string{"application/json"},
		Skills: []a2a.AgentSkill{{
			ID: config.SkillID, Name: config.SkillName, Description: config.Description,
			Tags:     []string{"sre", "reliability", "aegissre", "structured-data"},
			Examples: config.Examples, InputModes: []string{"application/json"}, OutputModes: []string{"application/json"},
		}},
	}
	if config.RequireMTLS {
		const schemeName a2a.SecuritySchemeName = "mtls"
		card.SecuritySchemes = a2a.NamedSecuritySchemes{
			schemeName: a2a.MutualTLSSecurityScheme{Description: "AegisSRE workload-bound mutual TLS"},
		}
		card.SecurityRequirements = a2a.SecurityRequirementsOptions{
			a2a.SecurityRequirements{schemeName: a2a.SecuritySchemeScopes{}},
		}
	}
	requestHandler := a2asrv.NewHandler(
		&executor{handle: handle, requireMTLS: config.RequireMTLS},
		a2asrv.WithAgentInactivityTimeout(2*time.Minute),
		a2asrv.WithCapabilityChecks(&card.Capabilities),
	)
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, publicDocument(a2asrv.NewStaticAgentCardHandler(card)))
	if len(config.AgentFacts) > 0 {
		facts := append([]byte(nil), config.AgentFacts...)
		mux.Handle("GET "+AgentFactsPath, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Access-Control-Allow-Origin", "*")
			_, _ = writer.Write(facts)
		}))
	}
	rpc := a2asrv.NewJSONRPCHandler(requestHandler)
	mux.Handle("/a2a", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, 1<<20)
		rpc.ServeHTTP(writer, request)
	}))
	return mux, card, nil
}

// publicDocument serves a discovery document to any origin without
// credentials. The SDK echoes a request Origin together with
// Access-Control-Allow-Credentials: true; without an Origin it answers with
// the wildcard, which browsers never combine with credentials.
func publicDocument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request = request.Clone(request.Context())
		request.Header.Del("Origin")
		next.ServeHTTP(writer, request)
	})
}

func envelopeFromParts(parts a2a.ContentParts) (model.Envelope, error) {
	if len(parts) != 1 || parts[0] == nil || parts[0].Data() == nil {
		return model.Envelope{}, model.NewError(model.CodeInvalidInput, "exactly one structured A2A data part is required")
	}
	data, err := json.Marshal(parts[0].Data())
	if err != nil {
		return model.Envelope{}, model.WrapError(model.CodeInvalidInput, "encode A2A data part", err)
	}
	var envelope model.Envelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return model.Envelope{}, model.WrapError(model.CodeInvalidInput, "decode A2A envelope", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return model.Envelope{}, model.NewError(model.CodeInvalidInput, "A2A envelope has trailing JSON")
	}
	if err := envelope.Validate(); err != nil {
		return model.Envelope{}, err
	}
	return envelope, nil
}
