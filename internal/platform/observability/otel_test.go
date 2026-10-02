package observability

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestHTTPPropagationAcrossInstrumentedClientAndServer(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := Setup(context.Background(), "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer shutdown(context.Background())

	traceID, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	spanID, _ := trace.SpanIDFromHex("0123456789abcdef")
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	})
	server := httptest.NewServer(HTTPHandler("test", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, trace.SpanContextFromContext(request.Context()).TraceID().String())
	})))
	defer server.Close()

	request, err := http.NewRequestWithContext(trace.ContextWithSpanContext(context.Background(), spanContext), http.MethodGet, server.URL+"/a2a", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := HTTPClient(server.Client())
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(body)) != traceID.String() {
		t.Fatalf("propagated trace ID = %q, want %q", body, traceID)
	}
}

func TestHTTPHandlerExcludesHealthChecks(t *testing.T) {
	t.Parallel()
	called := false
	handler := HTTPHandler("test", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if !called {
		t.Fatal("health handler was not called")
	}
}
