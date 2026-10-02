package a2atransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/platform/httpclient"
	"github.com/shanurwan/AegisSRE/internal/platform/observability"
)

type Client struct {
	HTTPClient      *http.Client
	PeerHTTPClients map[model.AgentID]*http.Client
	RequireMTLS     bool
}

func NewClient(timeout time.Duration) *Client {
	return &Client{HTTPClient: observability.HTTPClient(httpclient.Direct(timeout))}
}

func NewAuthenticatedClient(peers map[model.AgentID]*http.Client) *Client {
	copy := make(map[model.AgentID]*http.Client, len(peers))
	for role, client := range peers {
		copy[role] = client
	}
	return &Client{PeerHTTPClients: copy, RequireMTLS: true}
}

func (c *Client) Send(ctx context.Context, endpoint string, envelope model.Envelope, response any) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	if response == nil {
		return errors.New("A2A response destination is required")
	}
	httpClient := c.HTTPClient
	if c.RequireMTLS {
		httpClient = c.PeerHTTPClients[envelope.Recipient]
		if httpClient == nil {
			return model.NewError(model.CodeOutOfScope, "no authenticated A2A route exists for the requested recipient")
		}
	}
	if httpClient == nil {
		httpClient = observability.HTTPClient(httpclient.Direct(30 * time.Second))
	}
	resolver := agentcard.NewResolver(httpClient)
	card, err := resolver.Resolve(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("resolve A2A agent card: %w", err)
	}
	if err := constrainCard(endpoint, card, c.RequireMTLS); err != nil {
		return err
	}
	client, err := a2aclient.NewFromCard(ctx, card,
		a2aclient.WithDefaultsDisabled(),
		a2aclient.WithJSONRPCTransport(httpClient),
	)
	if err != nil {
		return fmt.Errorf("create A2A client: %w", err)
	}
	defer client.Destroy()
	data, err := structuredData(envelope)
	if err != nil {
		return err
	}
	message := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewDataPart(data))
	result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: message})
	if err != nil {
		return fmt.Errorf("send A2A message: %w", err)
	}
	part, state, err := resultPart(result)
	if err != nil {
		return err
	}
	if state == a2a.TaskStateFailed || state == a2a.TaskStateRejected || state == a2a.TaskStateCanceled {
		var failure map[string]string
		if decodeDataPart(part, &failure) == nil && failure["message"] != "" {
			if code := model.ErrorCode(failure["code"]); knownPeerErrorCode(code) {
				return model.NewError(code, "peer A2A task "+string(state)+": "+failure["message"])
			}
			return fmt.Errorf("peer A2A task %s: %s", state, failure["message"])
		}
		return fmt.Errorf("peer A2A task ended in %s", state)
	}
	if err := decodeDataPart(part, response); err != nil {
		return err
	}
	return nil
}

func knownPeerErrorCode(code model.ErrorCode) bool {
	switch code {
	case model.CodeInvalidInput, model.CodeInvalidStateTransition, model.CodeOutOfScope,
		model.CodeDelegationRequired, model.CodePolicyDenied, model.CodeInvalidSignature,
		model.CodeGrantNotYetValid, model.CodeGrantExpired, model.CodeReplayedGrant,
		model.CodeExecutionPending,
		model.CodeStalePrecondition, model.CodeToolBudgetExceeded,
		model.CodeInconclusiveDiagnosis, model.CodeExecutionFailed:
		return true
	default:
		return false
	}
}

func constrainCard(endpoint string, card *a2a.AgentCard, requireMTLS ...bool) error {
	base, err := url.Parse(endpoint)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil {
		return model.NewError(model.CodeInvalidInput, "configured A2A endpoint is invalid")
	}
	if card == nil || len(card.SupportedInterfaces) == 0 {
		return model.NewError(model.CodeInvalidInput, "peer Agent Card has no interfaces")
	}
	if len(requireMTLS) > 0 && requireMTLS[0] && !cardRequiresMTLS(card) {
		return model.NewError(model.CodeDelegationRequired, "peer Agent Card does not require mutual TLS")
	}
	found := false
	for _, iface := range card.SupportedInterfaces {
		if iface == nil || iface.ProtocolBinding != a2a.TransportProtocolJSONRPC {
			continue
		}
		candidate, err := url.Parse(iface.URL)
		if err != nil || candidate.User != nil || !sameOrigin(base, candidate) {
			return model.NewError(model.CodeOutOfScope, "peer Agent Card redirects outside its configured origin")
		}
		found = true
	}
	if found {
		return nil
	}
	return model.NewError(model.CodeInvalidInput, "peer Agent Card does not expose JSON-RPC")
}

func cardRequiresMTLS(card *a2a.AgentCard) bool {
	if card == nil {
		return false
	}
	const schemeName a2a.SecuritySchemeName = "mtls"
	scheme, ok := card.SecuritySchemes[schemeName]
	if !ok {
		return false
	}
	if _, ok := scheme.(a2a.MutualTLSSecurityScheme); !ok {
		return false
	}
	for _, requirement := range card.SecurityRequirements {
		if _, required := requirement[schemeName]; required {
			return true
		}
	}
	return false
}

func sameOrigin(left, right *url.URL) bool {
	return left != nil && right != nil &&
		strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectivePort(left) == effectivePort(right)
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if strings.EqualFold(value.Scheme, "https") {
		return "443"
	}
	return "80"
}

func resultPart(result a2a.SendMessageResult) (*a2a.Part, a2a.TaskState, error) {
	switch value := result.(type) {
	case *a2a.Message:
		if len(value.Parts) != 1 {
			return nil, "", model.NewError(model.CodeInvalidInput, "peer message must contain one data part")
		}
		return value.Parts[0], a2a.TaskStateCompleted, nil
	case *a2a.Task:
		if len(value.Artifacts) == 0 {
			return nil, value.Status.State, model.NewError(model.CodeExecutionFailed, "peer task returned no artifact")
		}
		artifact := value.Artifacts[len(value.Artifacts)-1]
		if artifact == nil || len(artifact.Parts) != 1 {
			return nil, value.Status.State, model.NewError(model.CodeInvalidInput, "peer artifact must contain one data part")
		}
		return artifact.Parts[0], value.Status.State, nil
	default:
		return nil, "", model.NewError(model.CodeInvalidInput, "unsupported A2A result type")
	}
}

func decodeDataPart(part *a2a.Part, destination any) error {
	if part == nil || part.Data() == nil {
		return model.NewError(model.CodeInvalidInput, "peer response is not a structured data part")
	}
	data, err := json.Marshal(part.Data())
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return model.WrapError(model.CodeInvalidInput, "decode peer response", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return model.NewError(model.CodeInvalidInput, "peer response has trailing JSON")
	}
	return nil
}
