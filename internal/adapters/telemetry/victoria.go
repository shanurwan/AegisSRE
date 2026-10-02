package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/platform/httpclient"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

var kubernetesName = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`)

type Victoria struct {
	MetricsURL string
	LogsURL    string
	TracesURL  string
	Namespace  string
	Client     *http.Client
	Now        func() time.Time
}

const (
	detectionLookback       = 5 * time.Minute
	detectionBackendTimeout = 3 * time.Second
	maxDetectionGroups      = 50
	maxDetectionBodyBytes   = 64 << 10
	maxDetectionCount       = 1<<53 - 1

	logNamespaceField   = "kubernetes.pod_namespace"
	logWorkloadField    = "kubernetes.pod_labels.aegissre.io/workload"
	traceNamespaceField = "resource_attr:k8s.namespace.name"
	traceWorkloadField  = "resource_attr:k8s.deployment.name"
)

func (v *Victoria) QueryMetrics(ctx context.Context, input toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error) {
	if err := v.authorizeNamespace(input.Namespace); err != nil {
		return toolapi.QueryMetricsOutput{}, err
	}
	query, err := metricQuery(input)
	if err != nil {
		return toolapi.QueryMetricsOutput{}, err
	}
	endpoint, err := url.Parse(strings.TrimRight(v.MetricsURL, "/") + "/api/v1/query")
	if err != nil {
		return toolapi.QueryMetricsOutput{}, fmt.Errorf("metrics endpoint: %w", err)
	}
	now := v.now()
	values := endpoint.Query()
	values.Set("query", query)
	values.Set("time", strconv.FormatInt(now.Unix(), 10))
	endpoint.RawQuery = values.Encode()

	var response prometheusResponse
	if err := v.getJSON(ctx, endpoint.String(), &response); err != nil {
		return toolapi.QueryMetricsOutput{}, err
	}
	if response.Status != "success" {
		return toolapi.QueryMetricsOutput{}, fmt.Errorf("VictoriaMetrics query failed: %s", response.Error)
	}
	out := toolapi.QueryMetricsOutput{TemplateID: input.TemplateID, Query: query, ObservedAt: now}
	for _, item := range response.Data.Result {
		if len(item.Value) != 2 {
			continue
		}
		seconds, ok := number(item.Value[0])
		if !ok {
			continue
		}
		raw, ok := item.Value[1].(string)
		if !ok {
			continue
		}
		value, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		out.Samples = append(out.Samples, toolapi.MetricSample{
			Labels: item.Metric, Timestamp: time.UnixMilli(int64(seconds * 1000)).UTC(), Value: value,
		})
	}
	return out, nil
}

func (v *Victoria) QueryLogSignals(ctx context.Context, input toolapi.QueryLogSignalsInput) (toolapi.QueryLogSignalsOutput, error) {
	if err := v.validateDetectionScope(input.Namespace, input.Workload); err != nil {
		return toolapi.QueryLogSignalsOutput{}, err
	}
	query, err := logDetectionQuery(input)
	if err != nil {
		return toolapi.QueryLogSignalsOutput{}, err
	}
	start, end, samples, err := v.queryDetectionHits(
		ctx, v.LogsURL, "VictoriaLogs", query, input.Namespace, input.Workload,
		logNamespaceField, logWorkloadField,
	)
	if err != nil {
		return toolapi.QueryLogSignalsOutput{}, err
	}
	return toolapi.QueryLogSignalsOutput{
		TemplateID: input.TemplateID, WindowStart: start, WindowEnd: end, Samples: samples,
	}, nil
}

func (v *Victoria) QueryTraceSignals(ctx context.Context, input toolapi.QueryTraceSignalsInput) (toolapi.QueryTraceSignalsOutput, error) {
	if err := v.validateDetectionScope(input.Namespace, input.Workload); err != nil {
		return toolapi.QueryTraceSignalsOutput{}, err
	}
	query, err := traceDetectionQuery(input)
	if err != nil {
		return toolapi.QueryTraceSignalsOutput{}, err
	}
	start, end, samples, err := v.queryDetectionStats(
		ctx, v.TracesURL, "VictoriaTraces", query, input.Namespace, input.Workload,
		traceNamespaceField, traceWorkloadField,
	)
	if err != nil {
		return toolapi.QueryTraceSignalsOutput{}, err
	}
	return toolapi.QueryTraceSignalsOutput{
		TemplateID: input.TemplateID, WindowStart: start, WindowEnd: end, Samples: samples,
	}, nil
}

func (v *Victoria) SearchLogs(ctx context.Context, input toolapi.SearchLogsInput) (toolapi.SearchLogsOutput, error) {
	if err := v.authorizeNamespace(input.Namespace); err != nil {
		return toolapi.SearchLogsOutput{}, err
	}
	if err := validateName("namespace", input.Namespace); err != nil {
		return toolapi.SearchLogsOutput{}, err
	}
	if input.Pod != "" {
		if err := validateName("pod", input.Pod); err != nil {
			return toolapi.SearchLogsOutput{}, err
		}
	}
	if len(input.Contains) > 128 || strings.ContainsAny(input.Contains, "\r\n\x00") {
		return toolapi.SearchLogsOutput{}, errors.New("log search text exceeds its safe bound")
	}
	lookback := input.LookbackMinutes
	if lookback == 0 {
		lookback = 15
	}
	if lookback < 1 || lookback > 60 {
		return toolapi.SearchLogsOutput{}, errors.New("log lookback must be between 1 and 60 minutes")
	}
	limit := input.Limit
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 200 {
		return toolapi.SearchLogsOutput{}, errors.New("log result limit must be between 1 and 200")
	}

	filters := []string{"kubernetes.pod_namespace=" + strconv.Quote(input.Namespace)}
	if input.Pod != "" {
		filters = append(filters, "kubernetes.pod_name="+strconv.Quote(input.Pod))
	}
	query := "_stream:{" + strings.Join(filters, ",") + "}"
	if input.Contains != "" {
		query += " AND _msg:" + strconv.Quote(input.Contains)
	}
	now := v.now()
	endpoint, err := url.Parse(strings.TrimRight(v.LogsURL, "/") + "/select/logsql/query")
	if err != nil {
		return toolapi.SearchLogsOutput{}, fmt.Errorf("logs endpoint: %w", err)
	}
	values := endpoint.Query()
	values.Set("query", query)
	values.Set("start", now.Add(-time.Duration(lookback)*time.Minute).Format(time.RFC3339Nano))
	values.Set("end", now.Format(time.RFC3339Nano))
	values.Set("limit", strconv.Itoa(limit))
	endpoint.RawQuery = values.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return toolapi.SearchLogsOutput{}, err
	}
	resp, err := v.client().Do(req)
	if err != nil {
		return toolapi.SearchLogsOutput{}, fmt.Errorf("VictoriaLogs request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return toolapi.SearchLogsOutput{}, fmt.Errorf("VictoriaLogs returned %s", resp.Status)
	}

	result := toolapi.SearchLogsOutput{}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 2<<20))
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	for scanner.Scan() {
		if len(result.Lines) >= limit {
			result.Truncated = true
			break
		}
		var row map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			continue
		}
		line := toolapi.LogLine{Labels: make(map[string]string)}
		if raw, ok := row["_time"].(string); ok {
			line.Timestamp, _ = time.Parse(time.RFC3339Nano, raw)
		}
		line.Message, _ = row["_msg"].(string)
		for key, value := range row {
			if key == "_time" || key == "_msg" {
				continue
			}
			if text, ok := value.(string); ok && len(text) <= 256 {
				line.Labels[key] = text
			}
		}
		result.Lines = append(result.Lines, line)
	}
	if err := scanner.Err(); err != nil {
		return toolapi.SearchLogsOutput{}, fmt.Errorf("read VictoriaLogs response: %w", err)
	}
	return result, nil
}

func (v *Victoria) authorizeNamespace(namespace string) error {
	if strings.TrimSpace(v.Namespace) == "" {
		return errors.New("telemetry namespace policy is not configured")
	}
	if namespace != v.Namespace {
		return model.NewError(model.CodeOutOfScope, "telemetry namespace is outside the configured scope")
	}
	return nil
}

func (v *Victoria) validateDetectionScope(namespace, workload string) error {
	if err := v.authorizeNamespace(namespace); err != nil {
		return err
	}
	if err := validateName("namespace", namespace); err != nil {
		return err
	}
	if workload != "" {
		if err := validateName("workload", workload); err != nil {
			return err
		}
	}
	return nil
}

func logDetectionQuery(input toolapi.QueryLogSignalsInput) (string, error) {
	identity := `_stream:{` + logNamespaceField + `=` + strconv.Quote(input.Namespace) + `}`
	identity += ` AND "` + logWorkloadField + `":*`
	if input.Workload != "" {
		identity += ` AND "` + logWorkloadField + `":=` + strconv.Quote(input.Workload)
	}
	switch input.TemplateID {
	case toolapi.LogErrorBurst5m:
		return identity + ` AND (severity_text:i(error) OR severity_text:i(fatal) OR level:i(error) OR level:i(fatal))`, nil
	case toolapi.LogDependencyTimeoutBurst5m:
		return identity + ` AND (event_name:="dependency_timeout" OR event:="dependency_timeout")`, nil
	default:
		return "", fmt.Errorf("unsupported log detection template %q", input.TemplateID)
	}
}

func traceDetectionQuery(input toolapi.QueryTraceSignalsInput) (string, error) {
	identity := `_time:5m AND "` + traceNamespaceField + `":=` + strconv.Quote(input.Namespace)
	identity += ` AND "` + traceWorkloadField + `":*`
	if input.Workload != "" {
		identity += ` AND "` + traceWorkloadField + `":=` + strconv.Quote(input.Workload)
	}
	switch input.TemplateID {
	case toolapi.TraceErrorCount5m:
		return traceStatsQuery(identity + ` AND status_code:=2`), nil
	case toolapi.TraceSlowServerCount5m:
		return traceStatsQuery(identity + ` AND kind:=2 AND duration:>2s`), nil
	default:
		return "", fmt.Errorf("unsupported trace detection template %q", input.TemplateID)
	}
}

func traceStatsQuery(filter string) string {
	return filter + ` | stats by ("` + traceNamespaceField + `", "` + traceWorkloadField + `") count_uniq(trace_id) as traces | limit 51`
}

func (v *Victoria) queryDetectionHits(
	ctx context.Context,
	baseURL, backendName, query, namespace, workload, namespaceField, workloadField string,
) (time.Time, time.Time, []toolapi.DetectionSample, error) {
	if strings.TrimSpace(baseURL) == "" {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("%s endpoint is not configured", backendName)
	}
	end := v.now()
	start := end.Add(-detectionLookback)
	endpoint, err := url.Parse(strings.TrimRight(baseURL, "/") + "/select/logsql/hits")
	if err != nil {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("%s endpoint: %w", backendName, err)
	}
	values := endpoint.Query()
	values.Set("query", query)
	values.Set("start", start.Format(time.RFC3339Nano))
	values.Set("end", end.Format(time.RFC3339Nano))
	values.Set("step", detectionLookback.String())
	values.Add("field", namespaceField)
	values.Add("field", workloadField)
	values.Set("fields_limit", strconv.Itoa(maxDetectionGroups))
	values.Set("timeout", detectionBackendTimeout.String())
	endpoint.RawQuery = values.Encode()

	requestCtx, cancel := context.WithTimeout(ctx, detectionBackendTimeout)
	defer cancel()
	var response detectionHitsResponse
	if err := v.getBoundedJSON(requestCtx, endpoint.String(), backendName, maxDetectionBodyBytes, &response); err != nil {
		return time.Time{}, time.Time{}, nil, err
	}
	if len(response.Hits) > maxDetectionGroups {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("%s returned too many detection groups", backendName)
	}
	samples := make([]toolapi.DetectionSample, 0, len(response.Hits))
	seen := make(map[string]struct{}, len(response.Hits))
	for _, hit := range response.Hits {
		returnedNamespace := hit.Fields[namespaceField]
		returnedWorkload := hit.Fields[workloadField]
		if returnedNamespace == "" || returnedWorkload == "" {
			return time.Time{}, time.Time{}, nil, fmt.Errorf("%s returned a detection group without an exact namespace and workload identity", backendName)
		}
		if returnedNamespace != namespace {
			return time.Time{}, time.Time{}, nil, model.NewError(model.CodeOutOfScope, backendName+" returned a detection group outside the configured namespace")
		}
		if err := validateName("workload", returnedWorkload); err != nil {
			return time.Time{}, time.Time{}, nil, fmt.Errorf("%s detection identity: %w", backendName, err)
		}
		if workload != "" && returnedWorkload != workload {
			return time.Time{}, time.Time{}, nil, model.NewError(model.CodeOutOfScope, backendName+" returned a different workload")
		}
		value, ok := number(hit.Total)
		if !ok || value < 0 || value > maxDetectionCount || math.Trunc(value) != value || math.IsNaN(value) || math.IsInf(value, 0) {
			return time.Time{}, time.Time{}, nil, fmt.Errorf("%s returned an invalid detection count", backendName)
		}
		key := returnedNamespace + "\x00" + returnedWorkload
		if _, duplicate := seen[key]; duplicate {
			return time.Time{}, time.Time{}, nil, fmt.Errorf("%s returned a duplicate detection identity", backendName)
		}
		seen[key] = struct{}{}
		samples = append(samples, toolapi.DetectionSample{
			Namespace: returnedNamespace, Workload: returnedWorkload, Timestamp: end, Value: value,
		})
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Namespace != samples[j].Namespace {
			return samples[i].Namespace < samples[j].Namespace
		}
		return samples[i].Workload < samples[j].Workload
	})
	return start, end, samples, nil
}

func (v *Victoria) queryDetectionStats(
	ctx context.Context,
	baseURL, backendName, query, namespace, workload, namespaceField, workloadField string,
) (time.Time, time.Time, []toolapi.DetectionSample, error) {
	if strings.TrimSpace(baseURL) == "" {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("%s endpoint is not configured", backendName)
	}
	end := v.now()
	start := end.Add(-detectionLookback)
	endpoint, err := url.Parse(strings.TrimRight(baseURL, "/") + "/select/logsql/stats_query")
	if err != nil {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("%s endpoint: %w", backendName, err)
	}
	values := endpoint.Query()
	values.Set("query", query)
	values.Set("time", end.Format(time.RFC3339Nano))
	values.Set("timeout", detectionBackendTimeout.String())
	endpoint.RawQuery = values.Encode()

	requestCtx, cancel := context.WithTimeout(ctx, detectionBackendTimeout)
	defer cancel()
	var response prometheusResponse
	if err := v.getBoundedJSON(requestCtx, endpoint.String(), backendName, maxDetectionBodyBytes, &response); err != nil {
		return time.Time{}, time.Time{}, nil, err
	}
	if response.Status != "success" {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("%s stats query failed: %s", backendName, response.Error)
	}
	if len(response.Data.Result) > maxDetectionGroups {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("%s returned too many detection groups", backendName)
	}
	samples := make([]toolapi.DetectionSample, 0, len(response.Data.Result))
	seen := make(map[string]struct{}, len(response.Data.Result))
	for _, item := range response.Data.Result {
		returnedNamespace := item.Metric[namespaceField]
		returnedWorkload := item.Metric[workloadField]
		if returnedNamespace == "" || returnedWorkload == "" {
			return time.Time{}, time.Time{}, nil, fmt.Errorf("%s returned a detection group without an exact namespace and workload identity", backendName)
		}
		if returnedNamespace != namespace {
			return time.Time{}, time.Time{}, nil, model.NewError(model.CodeOutOfScope, backendName+" returned a detection group outside the configured namespace")
		}
		if err := validateName("workload", returnedWorkload); err != nil {
			return time.Time{}, time.Time{}, nil, fmt.Errorf("%s detection identity: %w", backendName, err)
		}
		if workload != "" && returnedWorkload != workload {
			return time.Time{}, time.Time{}, nil, model.NewError(model.CodeOutOfScope, backendName+" returned a different workload")
		}
		if len(item.Value) != 2 {
			return time.Time{}, time.Time{}, nil, fmt.Errorf("%s returned a malformed detection count", backendName)
		}
		raw, ok := item.Value[1].(string)
		if !ok {
			return time.Time{}, time.Time{}, nil, fmt.Errorf("%s returned a malformed detection count", backendName)
		}
		value, err := strconv.ParseFloat(raw, 64)
		if err != nil || value < 0 || value > maxDetectionCount || math.Trunc(value) != value || math.IsNaN(value) || math.IsInf(value, 0) {
			return time.Time{}, time.Time{}, nil, fmt.Errorf("%s returned an invalid detection count", backendName)
		}
		key := returnedNamespace + "\x00" + returnedWorkload
		if _, duplicate := seen[key]; duplicate {
			return time.Time{}, time.Time{}, nil, fmt.Errorf("%s returned a duplicate detection identity", backendName)
		}
		seen[key] = struct{}{}
		samples = append(samples, toolapi.DetectionSample{
			Namespace: returnedNamespace, Workload: returnedWorkload, Timestamp: end, Value: value,
		})
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Namespace != samples[j].Namespace {
			return samples[i].Namespace < samples[j].Namespace
		}
		return samples[i].Workload < samples[j].Workload
	})
	return start, end, samples, nil
}

func (v *Victoria) getBoundedJSON(ctx context.Context, endpoint, backendName string, maxBytes int64, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := v.client().Do(req)
	if err != nil {
		return fmt.Errorf("%s request: %w", backendName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s returned %s", backendName, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return fmt.Errorf("read %s response: %w", backendName, err)
	}
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("%s response exceeds %d bytes", backendName, maxBytes)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode %s response: %w", backendName, err)
	}
	return nil
}

func metricQuery(input toolapi.QueryMetricsInput) (string, error) {
	if err := validateName("namespace", input.Namespace); err != nil {
		return "", err
	}
	if input.Workload != "" {
		if err := validateName("workload", input.Workload); err != nil {
			return "", err
		}
	}
	matcher := `namespace="` + input.Namespace + `"`
	deploymentMatcher := matcher
	if input.Workload != "" {
		deploymentMatcher += `,deployment="` + input.Workload + `"`
	}
	switch input.TemplateID {
	case toolapi.MetricDeploymentUnavailable:
		return "max by (namespace, deployment) (kube_deployment_status_replicas_unavailable{" + deploymentMatcher + "})", nil
	case toolapi.MetricDeploymentAvailable:
		return "max by (namespace, deployment) (kube_deployment_status_replicas_available{" + deploymentMatcher + "})", nil
	case toolapi.MetricPodCrashLoop:
		return "max by (namespace, pod) (kube_pod_container_status_waiting_reason{" + matcher + `,reason="CrashLoopBackOff"})`, nil
	case toolapi.MetricContainerRestarts:
		return "sum by (namespace, pod) (increase(kube_pod_container_status_restarts_total{" + matcher + "}[5m]))", nil
	case toolapi.MetricPodNotReady:
		return "max by (namespace, pod) (kube_pod_status_ready{" + matcher + `,condition="false"})`, nil
	default:
		return "", fmt.Errorf("unsupported metric template %q", input.TemplateID)
	}
}

func validateName(field, value string) error {
	if len(value) > 253 || !kubernetesName.MatchString(value) {
		return fmt.Errorf("invalid Kubernetes %s", field)
	}
	return nil
}

func (v *Victoria) getJSON(ctx context.Context, endpoint string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := v.client().Do(req)
	if err != nil {
		return fmt.Errorf("VictoriaMetrics request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("VictoriaMetrics returned %s", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(target); err != nil {
		return fmt.Errorf("decode VictoriaMetrics response: %w", err)
	}
	return nil
}

func (v *Victoria) client() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return httpclient.Direct(10 * time.Second)
}

func (v *Victoria) now() time.Time {
	if v.Now != nil {
		return v.Now().UTC()
	}
	return time.Now().UTC()
}

func number(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case json.Number:
		result, err := v.Float64()
		return result, err == nil
	default:
		return 0, false
	}
}

type prometheusResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Data   struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
			Value  []any             `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

type detectionHitsResponse struct {
	Hits []struct {
		Fields map[string]string `json:"fields"`
		Total  any               `json:"total"`
	} `json:"hits"`
}
