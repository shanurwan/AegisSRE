package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
