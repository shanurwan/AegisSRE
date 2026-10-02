// Package observability provides process-wide OpenTelemetry setup and narrow
// HTTP instrumentation. AegisSRE emits traces through an OTLP Collector; it
// does not send telemetry directly to a vendor endpoint.
package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type Shutdown func(context.Context) error

// StartOperation creates a root-or-child span for background control-plane
// work that has no inbound HTTP request, such as a scheduled Monitor scan.
// The returned completion function must be called exactly once.
func StartOperation(ctx context.Context, name string) (context.Context, func(error)) {
	ctx, span := otel.Tracer("github.com/shanurwan/AegisSRE").Start(ctx, name)
	return ctx, func(err error) {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "operation failed")
		}
		span.End()
	}
}

// Setup installs W3C Trace Context propagation unconditionally. When an OTLP
// endpoint is configured through the standard OTEL_EXPORTER_OTLP_* variables,
// it also starts a bounded batch exporter. An absent endpoint intentionally
// leaves a no-op provider for local and unit-test runs.
func Setup(ctx context.Context, role, version string) (Shutdown, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	if disabled, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED"))); disabled {
		return func(context.Context) error { return nil }, nil
	}
	if strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) == "" &&
		strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")) == "" {
		return func(context.Context) error { return nil }, nil
	}
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}
	res, err := resource.New(ctx, resource.WithAttributes(
		attribute.String("service.name", "aegissre-"+role),
		attribute.String("service.namespace", "aegissre"),
		attribute.String("service.version", version),
	))
	if err != nil {
		return nil, fmt.Errorf("create OpenTelemetry resource: %w", err)
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(traceSampleRatio()))),
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(2*time.Second),
			sdktrace.WithExportTimeout(5*time.Second),
			sdktrace.WithMaxQueueSize(2048),
			sdktrace.WithMaxExportBatchSize(512),
		),
	)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

func traceSampleRatio() float64 {
	raw := strings.TrimSpace(os.Getenv("AEGIS_TRACE_SAMPLE_RATIO"))
	if raw == "" {
		return 0.1
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value < 0 || value > 1 {
		return 0.1
	}
	return value
}

// HTTPHandler extracts W3C context and creates server spans for application
// traffic. Health, readiness, and Prometheus scrapes are intentionally
// excluded to avoid high-volume operational noise.
func HTTPHandler(role string, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return otelhttp.NewHandler(next, "aegissre."+role+".http",
		otelhttp.WithFilter(func(request *http.Request) bool {
			switch request.URL.Path {
			case "/healthz", "/readyz", "/metrics":
				return false
			default:
				return true
			}
		}),
	)
}

// HTTPClient returns a shallow client copy whose transport injects W3C trace
// context and records request spans. Redirect and timeout policy is retained.
func HTTPClient(client *http.Client) *http.Client {
	if client == nil {
		return nil
	}
	copy := *client
	transport := copy.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	copy.Transport = otelhttp.NewTransport(transport)
	return &copy
}

// ContextHandler adds trace correlation to JSON records without changing log
// messages or exporting a second copy of logs. The cluster's existing stdout
// collector remains the single log ingestion path.
type ContextHandler struct {
	next slog.Handler
}

func NewContextHandler(next slog.Handler) *ContextHandler { return &ContextHandler{next: next} }

func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h != nil && h.next != nil && h.next.Enabled(ctx, level)
}

func (h *ContextHandler) Handle(ctx context.Context, record slog.Record) error {
	if h == nil || h.next == nil {
		return errors.New("OpenTelemetry log handler is unavailable")
	}
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		record.AddAttrs(
			slog.String("trace_id", spanContext.TraceID().String()),
			slog.String("span_id", spanContext.SpanID().String()),
		)
	}
	return h.next.Handle(ctx, record)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{next: h.next.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{next: h.next.WithGroup(name)}
}
