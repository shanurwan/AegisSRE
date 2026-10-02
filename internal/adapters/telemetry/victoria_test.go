package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

func TestQueryMetricsUsesBoundedTemplate(t *testing.T) {
	t.Parallel()
	wantTime := time.Date(2026, 9, 30, 1, 2, 3, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/api/v1/query" {
			t.Errorf("path = %q", got)
		}
		if got := r.URL.Query().Get("query"); got != `max by (namespace, deployment) (kube_deployment_status_replicas_unavailable{namespace="outage-arena",deployment="demo-api"})` {
			t.Errorf("query = %q", got)
		}
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"result":[{"metric":{"namespace":"outage-arena","deployment":"demo-api"},"value":[1790730123,"1"]}]}}`)
	}))
	defer server.Close()

	client := &Victoria{MetricsURL: server.URL, Namespace: "outage-arena", Client: server.Client(), Now: func() time.Time { return wantTime }}
	got, err := client.QueryMetrics(context.Background(), toolapi.QueryMetricsInput{
		TemplateID: toolapi.MetricDeploymentUnavailable, Namespace: "outage-arena", Workload: "demo-api",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Samples) != 1 || got.Samples[0].Value != 1 {
		t.Fatalf("samples = %#v", got.Samples)
	}
}

func TestQueryLogSignalsUsesBoundedServerTemplate(t *testing.T) {
	t.Parallel()
	wantTime := time.Date(2026, 10, 1, 1, 2, 3, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/select/logsql/hits" {
			t.Errorf("path = %q", r.URL.Path)
		}
		values := r.URL.Query()
		query := values.Get("query")
		for _, required := range []string{
			`_stream:{kubernetes.pod_namespace="outage-arena"}`,
			`"kubernetes.pod_labels.aegissre.io/workload":="demo-api"`,
			`severity_text:i(error)`,
		} {
			if !strings.Contains(query, required) {
				t.Errorf("query %q does not contain %q", query, required)
			}
		}
		if values.Get("start") != wantTime.Add(-5*time.Minute).Format(time.RFC3339Nano) ||
			values.Get("end") != wantTime.Format(time.RFC3339Nano) ||
			values.Get("step") != "5m0s" || values.Get("fields_limit") != "50" || values.Get("timeout") != "3s" {
			t.Errorf("unbounded query parameters: %v", values)
		}
		fields := values["field"]
		if len(fields) != 2 || fields[0] != logNamespaceField || fields[1] != logWorkloadField {
			t.Errorf("group fields = %v", fields)
		}
		_, _ = fmt.Fprint(w, `{"hits":[{"fields":{"kubernetes.pod_namespace":"outage-arena","kubernetes.pod_labels.aegissre.io/workload":"demo-api"},"timestamps":["2026-10-01T01:00:00Z"],"values":[7],"total":7}]}`)
	}))
	defer server.Close()

	client := &Victoria{
		LogsURL: server.URL, Namespace: "outage-arena", Client: server.Client(),
		Now: func() time.Time { return wantTime },
	}
	got, err := client.QueryLogSignals(context.Background(), toolapi.QueryLogSignalsInput{
		TemplateID: toolapi.LogErrorBurst5m, Namespace: "outage-arena", Workload: "demo-api",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.TemplateID != toolapi.LogErrorBurst5m || !got.WindowStart.Equal(wantTime.Add(-5*time.Minute)) ||
		!got.WindowEnd.Equal(wantTime) || len(got.Samples) != 1 || got.Samples[0].Value != 7 ||
		got.Samples[0].Namespace != "outage-arena" || got.Samples[0].Workload != "demo-api" ||
		!got.Samples[0].Timestamp.Equal(wantTime) {
		t.Fatalf("unexpected log detection output: %#v", got)
	}
}

func TestQueryTraceSignalsUsesBoundedServerTemplate(t *testing.T) {
	t.Parallel()
	wantTime := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/select/logsql/stats_query" {
			t.Errorf("path = %q", r.URL.Path)
		}
		query := r.URL.Query().Get("query")
		for _, required := range []string{
			`_time:5m`,
			`"resource_attr:k8s.namespace.name":="outage-arena"`,
			`"resource_attr:k8s.deployment.name":="demo-api"`,
			`kind:=2`,
			`duration:>2s`,
			`count_uniq(trace_id) as traces`,
			`limit 51`,
		} {
			if !strings.Contains(query, required) {
				t.Errorf("query %q does not contain %q", query, required)
			}
		}
		if r.URL.Query().Get("time") != wantTime.Format(time.RFC3339Nano) || r.URL.Query().Get("timeout") != "3s" {
			t.Errorf("unbounded trace query parameters: %v", r.URL.Query())
		}
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"result":[{"metric":{"resource_attr:k8s.namespace.name":"outage-arena","resource_attr:k8s.deployment.name":"demo-api"},"value":[1790816400,"4"]}]}}`)
	}))
	defer server.Close()
	client := &Victoria{
		TracesURL: server.URL, Namespace: "outage-arena", Client: server.Client(),
		Now: func() time.Time { return wantTime },
	}
	got, err := client.QueryTraceSignals(context.Background(), toolapi.QueryTraceSignalsInput{
		TemplateID: toolapi.TraceSlowServerCount5m, Namespace: "outage-arena", Workload: "demo-api",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Samples) != 1 || got.Samples[0].Value != 4 || got.Samples[0].Workload != "demo-api" {
		t.Fatalf("unexpected trace detection output: %#v", got)
	}
}

func TestDetectionQueriesFailClosedOnUnmappedIdentity(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"hits":[{"fields":{"kubernetes.pod_namespace":"outage-arena"},"total":8}]}`)
	}))
	defer server.Close()
	client := &Victoria{LogsURL: server.URL, Namespace: "outage-arena", Client: server.Client()}
	_, err := client.QueryLogSignals(context.Background(), toolapi.QueryLogSignalsInput{
		TemplateID: toolapi.LogErrorBurst5m, Namespace: "outage-arena",
	})
	if err == nil || !strings.Contains(err.Error(), "without an exact namespace and workload identity") {
		t.Fatalf("unmapped detection identity was not rejected: %v", err)
	}
}

func TestTraceDetectionFailsClosedOnUnmappedIdentity(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"result":[{"metric":{"resource_attr:k8s.namespace.name":"outage-arena"},"value":[1790816400,"4"]}]}}`)
	}))
	defer server.Close()
	client := &Victoria{TracesURL: server.URL, Namespace: "outage-arena", Client: server.Client()}
	_, err := client.QueryTraceSignals(context.Background(), toolapi.QueryTraceSignalsInput{
		TemplateID: toolapi.TraceErrorCount5m, Namespace: "outage-arena",
	})
	if err == nil || !strings.Contains(err.Error(), "without an exact namespace and workload identity") {
		t.Fatalf("unmapped trace identity was not rejected: %v", err)
	}
}

func TestDetectionQueriesRejectFractionalCounts(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/select/logsql/hits":
			_, _ = fmt.Fprint(w, `{"hits":[{"fields":{"kubernetes.pod_namespace":"outage-arena","kubernetes.pod_labels.aegissre.io/workload":"demo-api"},"total":2.5}]}`)
		case "/select/logsql/stats_query":
			_, _ = fmt.Fprint(w, `{"status":"success","data":{"result":[{"metric":{"resource_attr:k8s.namespace.name":"outage-arena","resource_attr:k8s.deployment.name":"demo-api"},"value":[1790816400,"2.5"]}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &Victoria{
		LogsURL: server.URL, TracesURL: server.URL, Namespace: "outage-arena", Client: server.Client(),
	}
	if _, err := client.QueryLogSignals(context.Background(), toolapi.QueryLogSignalsInput{
		TemplateID: toolapi.LogErrorBurst5m, Namespace: "outage-arena",
	}); err == nil || !strings.Contains(err.Error(), "invalid detection count") {
		t.Fatalf("fractional log count was not rejected: %v", err)
	}
	if _, err := client.QueryTraceSignals(context.Background(), toolapi.QueryTraceSignalsInput{
		TemplateID: toolapi.TraceErrorCount5m, Namespace: "outage-arena",
	}); err == nil || !strings.Contains(err.Error(), "invalid detection count") {
		t.Fatalf("fractional trace count was not rejected: %v", err)
	}
}

func TestUnsupportedDetectionTemplatesDoNotReachBackend(t *testing.T) {
	t.Parallel()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client := &Victoria{
		LogsURL: server.URL, TracesURL: server.URL, Namespace: "outage-arena", Client: server.Client(),
	}
	if _, err := client.QueryLogSignals(context.Background(), toolapi.QueryLogSignalsInput{
		TemplateID: "caller_supplied_query", Namespace: "outage-arena",
	}); err == nil || !strings.Contains(err.Error(), "unsupported log detection template") {
		t.Fatalf("unsupported log template was not rejected: %v", err)
	}
	if _, err := client.QueryTraceSignals(context.Background(), toolapi.QueryTraceSignalsInput{
		TemplateID: "caller_supplied_query", Namespace: "outage-arena",
	}); err == nil || !strings.Contains(err.Error(), "unsupported trace detection template") {
		t.Fatalf("unsupported trace template was not rejected: %v", err)
	}
	if requests != 0 {
		t.Fatalf("unsupported templates reached telemetry backend %d times", requests)
	}
}

func TestDetectionQueryRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"hits":[]}`+strings.Repeat(" ", maxDetectionBodyBytes))
	}))
	defer server.Close()
	client := &Victoria{TracesURL: server.URL, Namespace: "outage-arena", Client: server.Client()}
	_, err := client.QueryTraceSignals(context.Background(), toolapi.QueryTraceSignalsInput{
		TemplateID: toolapi.TraceErrorCount5m, Namespace: "outage-arena",
	})
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("oversized detection response was not rejected: %v", err)
	}
}

func TestVictoriaRejectsCrossNamespaceBeforeRequest(t *testing.T) {
	t.Parallel()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client := &Victoria{MetricsURL: server.URL, LogsURL: server.URL, Namespace: "outage-arena", Client: server.Client()}
	if _, err := client.QueryMetrics(context.Background(), toolapi.QueryMetricsInput{
		TemplateID: toolapi.MetricDeploymentUnavailable, Namespace: "kube-system",
	}); err == nil {
		t.Fatal("cross-namespace metric query was allowed")
	}
	if _, err := client.SearchLogs(context.Background(), toolapi.SearchLogsInput{Namespace: "kube-system"}); err == nil {
		t.Fatal("cross-namespace log search was allowed")
	}
	if _, err := client.QueryLogSignals(context.Background(), toolapi.QueryLogSignalsInput{
		TemplateID: toolapi.LogErrorBurst5m, Namespace: "kube-system",
	}); err == nil {
		t.Fatal("cross-namespace log detection was allowed")
	}
	if _, err := client.QueryTraceSignals(context.Background(), toolapi.QueryTraceSignalsInput{
		TemplateID: toolapi.TraceErrorCount5m, Namespace: "kube-system",
	}); err == nil {
		t.Fatal("cross-namespace trace detection was allowed")
	}
	if _, err := client.QueryLogSignals(context.Background(), toolapi.QueryLogSignalsInput{
		TemplateID: toolapi.LogErrorBurst5m, Namespace: "outage-arena", Workload: `demo-api" OR *`,
	}); err == nil {
		t.Fatal("unsafe workload reached log detection")
	}
	if requests != 0 {
		t.Fatalf("cross-namespace input reached telemetry backend %d times", requests)
	}
}

func TestQueryMetricsDropsNonFiniteSamples(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"result":[`+
			`{"metric":{"namespace":"outage-arena","deployment":"nan"},"value":[1790730123,"NaN"]},`+
			`{"metric":{"namespace":"outage-arena","deployment":"inf"},"value":[1790730123,"+Inf"]},`+
			`{"metric":{"namespace":"outage-arena","deployment":"valid"},"value":[1790730123,"1"]}`+
			`]}}`)
	}))
	defer server.Close()

	client := &Victoria{MetricsURL: server.URL, Namespace: "outage-arena", Client: server.Client()}
	got, err := client.QueryMetrics(context.Background(), toolapi.QueryMetricsInput{
		TemplateID: toolapi.MetricDeploymentUnavailable, Namespace: "outage-arena",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Samples) != 1 || got.Samples[0].Labels["deployment"] != "valid" {
		t.Fatalf("non-finite samples were not dropped: %#v", got.Samples)
	}
}

func TestMetricQueryRejectsInjection(t *testing.T) {
	t.Parallel()
	_, err := metricQuery(toolapi.QueryMetricsInput{
		TemplateID: toolapi.MetricDeploymentUnavailable,
		Namespace:  `outage-arena"} or vector(1)`,
	})
	if err == nil {
		t.Fatal("expected unsafe namespace to be rejected")
	}
}
