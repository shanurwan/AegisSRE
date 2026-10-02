package authn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

const (
	monitorIdentity      = "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-monitor"
	investigatorIdentity = "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-investigator"
	operatorIdentity     = "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-operator"
)

func TestRoleAuthorizerAuthenticatesBeforeBodyHandling(t *testing.T) {
	t.Parallel()
	authorizer, err := NewRoleAuthorizer(model.AgentOperator, testIdentities())
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		principal, ok := PrincipalFromContext(request.Context())
		if !ok || principal.Agent != model.AgentMonitor || principal.Identity != monitorIdentity {
			t.Errorf("unexpected principal: %#v, ok=%v", principal, ok)
		}
		_, _ = io.WriteString(writer, "ok")
	})

	allowedBody := &countingBody{Reader: strings.NewReader("authorized")}
	allowed := requestWithIdentity(allowedBody, monitorIdentity)
	allowedRecorder := httptest.NewRecorder()
	authorizer.Middleware(next).ServeHTTP(allowedRecorder, allowed)
	if allowedRecorder.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("allowed request status=%d calls=%d", allowedRecorder.Code, calls.Load())
	}

	deniedBody := &countingBody{Reader: strings.NewReader("must-not-be-read")}
	denied := requestWithIdentity(deniedBody, investigatorIdentity)
	deniedRecorder := httptest.NewRecorder()
	authorizer.Middleware(next).ServeHTTP(deniedRecorder, denied)
	if deniedRecorder.Code != http.StatusForbidden {
		t.Fatalf("denied request status=%d, want 403", deniedRecorder.Code)
	}
	if deniedBody.reads.Load() != 0 || calls.Load() != 1 {
		t.Fatalf("unauthorized body reads=%d handler calls=%d", deniedBody.reads.Load(), calls.Load())
	}
}

func TestRoleAuthorizerRejectsMissingOrUnverifiedTLS(t *testing.T) {
	t.Parallel()
	authorizer, err := NewRoleAuthorizer(model.AgentInvestigator, testIdentities())
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	handler := authorizer.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))

	for name, mutate := range map[string]func(*http.Request){
		"no TLS": func(request *http.Request) { request.TLS = nil },
		"unverified certificate": func(request *http.Request) {
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificateWithIdentity(t, monitorIdentity)}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://agent.internal/a2a", strings.NewReader("secret body"))
			mutate(request)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d, want 401", recorder.Code)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("unauthenticated requests reached handler %d times", calls.Load())
	}
}

func TestAllowedCallerMatrix(t *testing.T) {
	t.Parallel()
	want := map[model.AgentID][]model.AgentID{
		model.AgentMonitor:      nil,
		model.AgentInvestigator: {model.AgentMonitor},
		model.AgentOperator:     {model.AgentMonitor},
		model.AgentMCPObserve:   {model.AgentMonitor, model.AgentInvestigator},
		model.AgentMCPAction:    {model.AgentOperator},
	}
	for recipient, expected := range want {
		actual, err := AllowedCallers(recipient)
		if err != nil {
			t.Fatalf("recipient %s: %v", recipient, err)
		}
		if strings.Join(agentStrings(actual), ",") != strings.Join(agentStrings(expected), ",") {
			t.Fatalf("recipient %s callers=%v, want %v", recipient, actual, expected)
		}
	}
	if _, err := AllowedCallers(model.AgentID("attacker")); err == nil {
		t.Fatal("unknown destination received an allowlist")
	}
}

func TestRequireAgentBindsEnvelopeSenderToTransportIdentity(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), principalContextKey{}, Principal{
		Identity: monitorIdentity,
		Agent:    model.AgentMonitor,
	})
	if err := RequireAgent(ctx, model.AgentMonitor); err != nil {
		t.Fatalf("matching sender rejected: %v", err)
	}
	if err := RequireAgent(ctx, model.AgentInvestigator); err == nil {
		t.Fatal("mismatched A2A sender was accepted")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeDelegationRequired {
		t.Fatalf("mismatch error=%v", err)
	}
	if err := RequireAgent(context.Background(), model.AgentMonitor); err == nil {
		t.Fatal("sender without authenticated principal was accepted")
	}
}

func TestAuthorizerRejectsAmbiguousConfiguration(t *testing.T) {
	t.Parallel()
	identities := testIdentities()
	identities[model.AgentInvestigator] = monitorIdentity
	if _, err := NewAuthorizer(identities, model.AgentMonitor, model.AgentInvestigator); err == nil {
		t.Fatal("one URI assigned to multiple roles was accepted")
	}
	if _, err := NewAuthorizer(testIdentities(), model.AgentMonitor, model.AgentMonitor); err == nil {
		t.Fatal("duplicate role was accepted")
	}
	if _, err := NewAuthorizer(testIdentities(), model.AgentID("attacker")); err == nil {
		t.Fatal("unknown role was accepted")
	}
}

func testIdentities() map[model.AgentID]string {
	return map[model.AgentID]string{
		model.AgentMonitor:      monitorIdentity,
		model.AgentInvestigator: investigatorIdentity,
		model.AgentOperator:     operatorIdentity,
		model.AgentMCPObserve:   "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-mcp-read",
		model.AgentMCPAction:    "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-mcp-action",
	}
}

func requestWithIdentity(body io.ReadCloser, identity string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://agent.internal/a2a", body)
	certificate := certificateWithIdentity(nil, identity)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	return request
}

func certificateWithIdentity(t *testing.T, identity string) *x509.Certificate {
	parsed, err := url.Parse(identity)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return &x509.Certificate{URIs: []*url.URL{parsed}}
}

type countingBody struct {
	*strings.Reader
	reads atomic.Int32
}

func (b *countingBody) Read(buffer []byte) (int, error) {
	b.reads.Add(1)
	return b.Reader.Read(buffer)
}

func (*countingBody) Close() error { return nil }

func agentStrings(values []model.AgentID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}
