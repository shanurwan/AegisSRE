package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/platform/httpclient"
)

const testAccessToken = "test-whatsapp-access-token"

func TestWhatsAppNotifySendsOneBoundedTemplateParameter(t *testing.T) {
	report := testIncidentReport(t)
	receiptTimestamp := time.Date(2042, 11, 12, 13, 14, 15, 987654321, time.UTC)
	report.Execution.CompletedAt = receiptTimestamp
	if err := report.Seal(); err != nil {
		t.Fatal(err)
	}
	wantText, err := canonicalReportText(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(wantText, "completed_at=") ||
		strings.Contains(wantText, receiptTimestamp.Format(time.RFC3339Nano)) ||
		strings.Contains(wantText, report.Digest) {
		t.Fatalf("canonical notification exposed receipt-controlled data or its digest: %q", wantText)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v26.0/123456789/messages" {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+testAccessToken {
			t.Error("request omitted bearer authorization")
		}
		if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected content headers: %v", request.Header)
		}

		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read request body: %v", readErr)
			return
		}
		var topLevel map[string]json.RawMessage
		if unmarshalErr := json.Unmarshal(body, &topLevel); unmarshalErr != nil {
			t.Errorf("decode request body: %v", unmarshalErr)
			return
		}
		assertJSONKeys(t, topLevel, "messaging_product", "recipient_type", "to", "type", "template")

		var payload templateMessage
		if unmarshalErr := json.Unmarshal(body, &payload); unmarshalErr != nil {
			t.Errorf("decode typed request body: %v", unmarshalErr)
			return
		}
		if payload.MessagingProduct != "whatsapp" || payload.RecipientType != "individual" ||
			payload.To != "60123456789" || payload.Type != "template" {
			t.Errorf("unexpected fixed envelope: %#v", payload)
		}
		if payload.Template.Name != "aegissre_incident_report" || payload.Template.Language.Code != "en_US" {
			t.Errorf("unexpected approved template selection: %#v", payload.Template)
		}
		if len(payload.Template.Components) != 1 || payload.Template.Components[0].Type != "body" ||
			len(payload.Template.Components[0].Parameters) != 1 {
			t.Errorf("template does not contain exactly one body parameter: %#v", payload.Template.Components)
			return
		}
		parameter := payload.Template.Components[0].Parameters[0]
		if parameter.Type != "text" || parameter.Text != wantText || len(parameter.Text) > maxReportTextBytes {
			t.Errorf("unexpected canonical template parameter: %#v", parameter)
		}
		if strings.Contains(parameter.Text, report.Execution.GrantID) || strings.Contains(parameter.Text, report.Execution.ReceiptID) {
			t.Error("canonical notification exposed grant or receipt identifiers")
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"messages":[{"id":"wamid.HBg-test_1"}]}`)
	}))
	defer server.Close()

	notifier := newTestNotifier(t, server)
	delivery, err := notifier.Notify(context.Background(), report)
	if err != nil {
		t.Fatal(err)
	}
	if delivery.Channel != model.NotificationChannelWhatsApp || delivery.ProviderMessageID != "wamid.HBg-test_1" {
		t.Fatalf("unexpected delivery: %#v", delivery)
	}
}

func TestNewWhatsAppValidatesFixedRouting(t *testing.T) {
	valid := testWhatsAppConfig()
	notifier, err := NewWhatsApp(valid)
	if err != nil {
		t.Fatal(err)
	}
	wantEndpoint := productionGraphBaseURL + "/v26.0/123456789/messages"
	if notifier.endpoint != wantEndpoint {
		t.Fatalf("production endpoint = %q, want %q", notifier.endpoint, wantEndpoint)
	}
	if notifier.client == nil || notifier.client.CheckRedirect == nil {
		t.Fatal("default notifier client is not hardened against redirects")
	}

	tests := []struct {
		name   string
		change func(*Config)
	}{
		{name: "missing version", change: func(config *Config) { config.GraphVersion = "" }},
		{name: "invalid version", change: func(config *Config) { config.GraphVersion = "26.0" }},
		{name: "invalid phone ID", change: func(config *Config) { config.PhoneNumberID = "123-456" }},
		{name: "missing token", change: func(config *Config) { config.AccessToken = "" }},
		{name: "token whitespace", change: func(config *Config) { config.AccessToken = "secret\nvalue" }},
		{name: "invalid recipient", change: func(config *Config) { config.Recipient = "+60123456789" }},
		{name: "short recipient", change: func(config *Config) { config.Recipient = "12345" }},
		{name: "invalid template", change: func(config *Config) { config.Template = "Incident-Report" }},
		{name: "invalid language", change: func(config *Config) { config.Language = "en-us" }},
		{name: "negative retries", change: func(config *Config) { config.MaxRetries = -1 }},
		{name: "excessive retries", change: func(config *Config) { config.MaxRetries = maxRetriesAllowed + 1 }},
		{name: "remote test URL", change: func(config *Config) {
			config.BaseURL = "https://example.invalid"
			config.Client = &http.Client{}
		}},
		{name: "test URL without injected client", change: func(config *Config) {
			config.BaseURL = "http://127.0.0.1:8080"
		}},
		{name: "test URL with path", change: func(config *Config) {
			config.BaseURL = "http://127.0.0.1:8080/arbitrary"
			config.Client = &http.Client{}
		}},
		{name: "test URL with empty query", change: func(config *Config) {
			config.BaseURL = "http://127.0.0.1:8080?"
			config.Client = &http.Client{}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			_, err := NewWhatsApp(config)
			if err == nil {
				t.Fatal("invalid notifier configuration was accepted")
			}
			if strings.Contains(err.Error(), testAccessToken) {
				t.Fatal("configuration error exposed the access token")
			}
			if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeInvalidInput {
				t.Fatalf("configuration error code = %q, %v", code, err)
			}
		})
	}
}

func TestWhatsAppRejectsInvalidOrOversizedReportBeforeHTTP(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	notifier := newTestNotifier(t, server)

	tampered := testIncidentReport(t)
	tampered.Summary = model.ReportReasonPolicyDenied.Summary()
	if _, err := notifier.Notify(context.Background(), tampered); err == nil {
		t.Fatal("tampered incident report was accepted")
	}

	longValue := strings.Repeat("x", 512)
	oversized := model.IncidentReport{
		SchemaVersion:     model.SchemaVersionV1,
		ReportID:          longValue,
		RequestID:         longValue,
		IncidentID:        longValue,
		CorrelationID:     longValue,
		DiagnosisReportID: longValue,
		Target: model.ResourceTarget{
			APIVersion: longValue, Kind: longValue, Namespace: longValue, Name: longValue,
		},
		FinalState: model.IncidentEscalated,
		Reason:     model.ReportReasonDiagnosisInconclusive,
		Summary:    model.ReportReasonDiagnosisInconclusive.Summary(),
		CreatedAt:  time.Date(2026, 10, 2, 3, 4, 5, 0, time.UTC),
	}
	if err := oversized.Seal(); err != nil {
		t.Fatalf("seal oversized-but-valid report: %v", err)
	}
	if _, err := notifier.Notify(context.Background(), oversized); err == nil || !strings.Contains(err.Error(), "safe bound") {
		t.Fatalf("oversized canonical text error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid reports reached the provider %d times", calls.Load())
	}
}

func TestWhatsAppRetriesOnly429AndServerErrors(t *testing.T) {
	report := testIncidentReport(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			writer.Header().Set("Retry-After", "0")
			writer.WriteHeader(http.StatusTooManyRequests)
		case 2:
			writer.WriteHeader(http.StatusServiceUnavailable)
		default:
			_, _ = io.WriteString(writer, `{"messages":[{"id":"wamid.retry-success"}]}`)
		}
	}))
	defer server.Close()

	notifier := newTestNotifier(t, server)
	notifier.maxRetries = 2
	var delays []time.Duration
	notifier.sleep = func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}
	delivery, err := notifier.Notify(context.Background(), report)
	if err != nil {
		t.Fatal(err)
	}
	if delivery.ProviderMessageID != "wamid.retry-success" || calls.Load() != 3 {
		t.Fatalf("unexpected retry result: delivery=%#v calls=%d", delivery, calls.Load())
	}
	if len(delays) != 2 || delays[0] != 0 || delays[1] != 500*time.Millisecond {
		t.Fatalf("retry delays = %v", delays)
	}

	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			var statusCalls atomic.Int32
			statusServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				statusCalls.Add(1)
				writer.WriteHeader(status)
			}))
			defer statusServer.Close()
			statusNotifier := newTestNotifier(t, statusServer)
			statusNotifier.maxRetries = 3
			statusNotifier.sleep = func(context.Context, time.Duration) error {
				t.Fatal("non-retryable status attempted to sleep")
				return nil
			}
			_, err := statusNotifier.Notify(context.Background(), report)
			if err == nil || statusCalls.Load() != 1 {
				t.Fatalf("status %d error=%v calls=%d", status, err, statusCalls.Load())
			}
		})
	}
}

func TestWhatsAppDoesNotRetryOrExposeTransportErrors(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("transport echoed " + request.Header.Get("Authorization"))
	})}
	config := testWhatsAppConfig()
	config.BaseURL = "http://127.0.0.1:8080"
	config.Client = client
	config.MaxRetries = 5
	notifier, err := NewWhatsApp(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = notifier.Notify(context.Background(), testIncidentReport(t))
	if err == nil {
		t.Fatal("transport failure unexpectedly succeeded")
	}
	if calls.Load() != 1 {
		t.Fatalf("transport failure was retried %d times", calls.Load())
	}
	if strings.Contains(err.Error(), testAccessToken) || strings.Contains(err.Error(), "Bearer") {
		t.Fatalf("transport error exposed authorization: %v", err)
	}
}

func TestWhatsAppRejectsOversizedAndMalformedResponsesWithoutEchoingBody(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "oversized", body: strings.Repeat("x", maxResponseBytes+1)},
		{name: "invalid JSON", body: `{"messages":[`},
		{name: "missing message", body: `{"messages":[]}`},
		{name: "missing ID", body: `{"messages":[{}]}`},
		{name: "unsafe ID", body: `{"messages":[{"id":"bad\nid"}]}`},
		{name: "trailing JSON", body: `{"messages":[{"id":"wamid.first"}]} {"secret":"provider-body-secret"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			notifier := newTestNotifier(t, server)
			_, err := notifier.Notify(context.Background(), testIncidentReport(t))
			if err == nil {
				t.Fatal("invalid provider response was accepted")
			}
			if strings.Contains(err.Error(), test.body) || strings.Contains(err.Error(), "provider-body-secret") {
				t.Fatalf("provider body was exposed: %v", err)
			}
		})
	}
}

func TestWhatsAppUsesInjectedHardenedClientForRedirects(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)
		_, _ = io.WriteString(writer, `{"messages":[{"id":"redirected"}]}`)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	config := testWhatsAppConfig()
	config.BaseURL = redirect.URL
	config.Client = httpclient.External(time.Second)
	notifier, err := NewWhatsApp(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = notifier.Notify(context.Background(), testIncidentReport(t))
	if err == nil {
		t.Fatal("redirect unexpectedly crossed the provider trust boundary")
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("redirect target received %d requests", targetCalls.Load())
	}
	if strings.Contains(err.Error(), testAccessToken) {
		t.Fatalf("redirect error exposed access token: %v", err)
	}
}

func TestRetryDelayIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name    string
		header  string
		attempt int
		want    time.Duration
	}{
		{name: "zero seconds", header: "0", attempt: 4, want: 0},
		{name: "seconds", header: "3", want: 3 * time.Second},
		{name: "seconds cap", header: "9223372036854775807", want: maxRetryDelay},
		{name: "date cap", header: now.Add(time.Hour).Format(http.TimeFormat), want: maxRetryDelay},
		{name: "past date", header: now.Add(-time.Hour).Format(http.TimeFormat), want: 0},
		{name: "fallback", header: "invalid", attempt: 3, want: 2 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := retryDelay(test.header, test.attempt, now); got != test.want {
				t.Fatalf("retry delay = %v, want %v", got, test.want)
			}
		})
	}
}

func newTestNotifier(t *testing.T, server *httptest.Server) *WhatsApp {
	t.Helper()
	config := testWhatsAppConfig()
	config.BaseURL = server.URL
	config.Client = server.Client()
	notifier, err := NewWhatsApp(config)
	if err != nil {
		t.Fatal(err)
	}
	return notifier
}

func testWhatsAppConfig() Config {
	return Config{
		GraphVersion: "v26.0", PhoneNumberID: "123456789", AccessToken: testAccessToken,
		Recipient: "60123456789", Template: "aegissre_incident_report", Language: "en_US",
	}
}

func testIncidentReport(t *testing.T) model.IncidentReport {
	t.Helper()
	now := time.Date(2026, 10, 2, 3, 4, 5, 0, time.UTC)
	target := model.ResourceTarget{
		APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api",
	}
	report := model.IncidentReport{
		SchemaVersion: model.SchemaVersionV1,
		ReportID:      "report-1", RequestID: "request-1", IncidentID: "incident-1",
		CorrelationID: "correlation-1", DiagnosisReportID: "diagnosis-1", Target: target,
		FinalState: model.IncidentEscalated, Reason: model.ReportReasonDryRunCompleted,
		Summary: model.ReportReasonDryRunCompleted.Summary(), CreatedAt: now,
		Execution: &model.IncidentReportExecution{
			GrantID: "grant-secret-1", ReceiptID: "receipt-secret-1",
			Action:  model.ActionSpec{Kind: model.ActionRestartDeployment, Target: target},
			Outcome: model.ActionDryRun, DryRun: true, CompletedAt: now,
		},
	}
	if err := report.Seal(); err != nil {
		t.Fatal(err)
	}
	return report
}

func assertJSONKeys(t *testing.T, object map[string]json.RawMessage, want ...string) {
	t.Helper()
	if len(object) != len(want) {
		t.Errorf("JSON keys = %v, want %v", mapKeys(object), want)
		return
	}
	for _, key := range want {
		if _, ok := object[key]; !ok {
			t.Errorf("JSON omitted key %q; keys=%v", key, mapKeys(object))
		}
	}
}

func mapKeys(object map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	return keys
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
