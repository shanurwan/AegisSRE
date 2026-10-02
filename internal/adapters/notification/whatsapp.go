// Package notification contains outbound notification adapters. These
// adapters receive only sealed, sanitized incident reports and have no
// infrastructure authority.
package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/platform/httpclient"
)

const (
	productionGraphBaseURL = "https://graph.facebook.com"
	defaultRequestTimeout  = 10 * time.Second
	maxRetriesAllowed      = 5
	maxRetryDelay          = 5 * time.Second
	baseRetryDelay         = 250 * time.Millisecond
	maxResponseBytes       = 64 << 10
	maxReportTextBytes     = 2048
)

var (
	graphVersionPattern = regexp.MustCompile(`^v[1-9][0-9]*\.[0-9]+$`)
	digitsPattern       = regexp.MustCompile(`^[0-9]+$`)
	templatePattern     = regexp.MustCompile(`^[a-z0-9_]+$`)
	languagePattern     = regexp.MustCompile(`^[a-z]{2,3}(?:_[A-Z]{2})?$`)
)

// Config contains the fixed routing and credential material for one WhatsApp
// Cloud API notifier. BaseURL exists only so tests can use a loopback server;
// production always targets https://graph.facebook.com.
type Config struct {
	GraphVersion  string
	PhoneNumberID string
	AccessToken   string
	Recipient     string
	Template      string
	Language      string
	MaxRetries    int
	Client        *http.Client
	BaseURL       string
}

// WhatsApp delivers approved template messages through Meta's Cloud API.
type WhatsApp struct {
	endpoint    string
	accessToken string
	recipient   string
	template    string
	language    string
	maxRetries  int
	client      *http.Client
	sleep       func(context.Context, time.Duration) error
}

var _ ports.Notifier = (*WhatsApp)(nil)

// NewWhatsApp validates a fixed notification route. Arbitrary remote base
// URLs are rejected; a custom base is accepted only for an injected loopback
// test client.
func NewWhatsApp(config Config) (*WhatsApp, error) {
	graphVersion := strings.TrimSpace(config.GraphVersion)
	if !graphVersionPattern.MatchString(graphVersion) || len(graphVersion) > 16 {
		return nil, invalidConfig("Graph API version is invalid")
	}
	phoneNumberID := strings.TrimSpace(config.PhoneNumberID)
	if !validDigits(phoneNumberID, 1, 32) {
		return nil, invalidConfig("phone number ID is invalid")
	}
	accessToken := config.AccessToken
	if strings.TrimSpace(accessToken) != accessToken || len(accessToken) < 1 || len(accessToken) > 8192 ||
		strings.IndexFunc(accessToken, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, invalidConfig("access token is invalid")
	}
	recipient := strings.TrimSpace(config.Recipient)
	if !validDigits(recipient, 6, 32) {
		return nil, invalidConfig("recipient is invalid")
	}
	template := strings.TrimSpace(config.Template)
	if len(template) < 1 || len(template) > 512 || !templatePattern.MatchString(template) {
		return nil, invalidConfig("template name is invalid")
	}
	language := strings.TrimSpace(config.Language)
	if len(language) > 16 || !languagePattern.MatchString(language) {
		return nil, invalidConfig("template language is invalid")
	}
	if config.MaxRetries < 0 || config.MaxRetries > maxRetriesAllowed {
		return nil, invalidConfig("maximum retries must be between zero and five")
	}

	baseURL, err := notificationBaseURL(config.BaseURL, config.Client)
	if err != nil {
		return nil, err
	}
	client := config.Client
	if client == nil {
		client = httpclient.External(defaultRequestTimeout)
	}

	return &WhatsApp{
		endpoint:    baseURL + "/" + graphVersion + "/" + phoneNumberID + "/messages",
		accessToken: accessToken, recipient: recipient, template: template,
		language: language, maxRetries: config.MaxRetries, client: client,
		sleep: sleepContext,
	}, nil
}

// Notify sends exactly one approved template containing one bounded canonical
// text parameter. It never sends arbitrary diagnosis, evidence, or grant data.
func (w *WhatsApp) Notify(ctx context.Context, report model.IncidentReport) (model.NotificationDelivery, error) {
	if w == nil || w.client == nil || w.sleep == nil {
		return model.NotificationDelivery{}, model.NewError(model.CodeExecutionFailed, "WhatsApp notifier is unavailable")
	}
	if err := report.VerifyDigest(); err != nil {
		return model.NotificationDelivery{}, fmt.Errorf("validate WhatsApp incident report: %w", err)
	}
	reportText, err := canonicalReportText(report)
	if err != nil {
		return model.NotificationDelivery{}, err
	}
	payload, err := json.Marshal(templateMessage{
		MessagingProduct: "whatsapp", RecipientType: "individual", To: w.recipient, Type: "template",
		Template: messageTemplate{
			Name: w.template, Language: templateLanguage{Code: w.language},
			Components: []templateComponent{{
				Type: "body", Parameters: []templateParameter{{Type: "text", Text: reportText}},
			}},
		},
	})
	if err != nil {
		return model.NotificationDelivery{}, model.NewError(model.CodeExecutionFailed, "encode WhatsApp template request")
	}

	for attempt := 0; ; attempt++ {
		responseBody, status, retryAfter, err := w.send(ctx, payload)
		if err != nil {
			return model.NotificationDelivery{}, err
		}
		if status >= http.StatusOK && status < http.StatusMultipleChoices {
			return parseDelivery(responseBody)
		}
		if !retryableStatus(status) || attempt >= w.maxRetries {
			return model.NotificationDelivery{}, model.NewError(
				model.CodeExecutionFailed, fmt.Sprintf("WhatsApp Cloud API returned HTTP %d", status),
			)
		}
		if err := w.sleep(ctx, retryDelay(retryAfter, attempt, time.Now().UTC())); err != nil {
			return model.NotificationDelivery{}, err
		}
	}
}

func (w *WhatsApp) send(ctx context.Context, payload []byte) ([]byte, int, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, "", model.NewError(model.CodeExecutionFailed, "create WhatsApp request")
	}
	request.Header.Set("Authorization", "Bearer "+w.accessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := w.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, "", ctx.Err()
		}
		// Do not wrap arbitrary transport errors: a custom transport could echo
		// request headers and disclose the bearer credential.
		return nil, 0, "", model.NewError(model.CodeExecutionFailed, "WhatsApp request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, 0, "", model.NewError(model.CodeExecutionFailed, "read WhatsApp response")
	}
	if len(body) > maxResponseBytes {
		return nil, 0, "", model.NewError(model.CodeExecutionFailed, "WhatsApp response exceeds the byte limit")
	}
	return body, response.StatusCode, response.Header.Get("Retry-After"), nil
}

type templateMessage struct {
	MessagingProduct string          `json:"messaging_product"`
	RecipientType    string          `json:"recipient_type"`
	To               string          `json:"to"`
	Type             string          `json:"type"`
	Template         messageTemplate `json:"template"`
}

type messageTemplate struct {
	Name       string              `json:"name"`
	Language   templateLanguage    `json:"language"`
	Components []templateComponent `json:"components"`
}

type templateLanguage struct {
	Code string `json:"code"`
}

type templateComponent struct {
	Type       string              `json:"type"`
	Parameters []templateParameter `json:"parameters"`
}

type templateParameter struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func canonicalReportText(report model.IncidentReport) (string, error) {
	parts := []string{
		"AegisSRE terminal incident report",
		"report=" + report.ReportID,
		"incident=" + report.IncidentID,
		"target=" + report.Target.APIVersion + "/" + report.Target.Kind + "/" + report.Target.Namespace + "/" + report.Target.Name,
		"state=" + string(report.FinalState),
		"reason=" + string(report.Reason),
		"summary=" + report.Summary,
		"created_at=" + report.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if report.Execution != nil {
		parts = append(parts,
			"action="+string(report.Execution.Action.Kind),
			"outcome="+string(report.Execution.Outcome),
			"dry_run="+strconv.FormatBool(report.Execution.DryRun),
		)
	}
	text := strings.Join(parts, " | ")
	if !utf8.ValidString(text) || len(text) > maxReportTextBytes {
		return "", model.NewError(model.CodeInvalidInput, "canonical incident report text exceeds the safe bound")
	}
	return text, nil
}

type messagesResponse struct {
	Messages []struct {
		ID string `json:"id"`
	} `json:"messages"`
}

func parseDelivery(body []byte) (model.NotificationDelivery, error) {
	var response messagesResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&response); err != nil {
		return model.NotificationDelivery{}, model.NewError(model.CodeExecutionFailed, "decode WhatsApp response")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return model.NotificationDelivery{}, model.NewError(model.CodeExecutionFailed, "WhatsApp response contains trailing JSON")
	}
	if len(response.Messages) == 0 {
		return model.NotificationDelivery{}, model.NewError(model.CodeExecutionFailed, "WhatsApp response omitted a message ID")
	}
	delivery := model.NotificationDelivery{
		Channel: model.NotificationChannelWhatsApp, ProviderMessageID: response.Messages[0].ID,
	}
	if err := delivery.Validate(); err != nil {
		return model.NotificationDelivery{}, model.NewError(model.CodeExecutionFailed, "WhatsApp response contained an invalid message ID")
	}
	return delivery, nil
}

func notificationBaseURL(raw string, client *http.Client) (string, error) {
	if raw == "" {
		return productionGraphBaseURL, nil
	}
	if client == nil {
		return "", invalidConfig("a test base URL requires an injected HTTP client")
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || (parsed.RawPath != "" && parsed.RawPath != "/") {
		return "", invalidConfig("test base URL is invalid")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return "", invalidConfig("custom base URL must be loopback-only")
	}
	return strings.TrimRight(raw, "/"), nil
}

func validDigits(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && digitsPattern.MatchString(value)
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError && status <= 599
}

func retryDelay(header string, attempt int, now time.Time) time.Duration {
	delay := baseRetryDelay
	for value := 0; value < attempt && delay < maxRetryDelay; value++ {
		delay *= 2
	}
	if seconds, err := strconv.ParseInt(strings.TrimSpace(header), 10, 64); err == nil && seconds >= 0 {
		if seconds >= int64(maxRetryDelay/time.Second) {
			return maxRetryDelay
		}
		delay = time.Duration(seconds) * time.Second
	} else if when, err := http.ParseTime(strings.TrimSpace(header)); err == nil {
		delay = when.Sub(now)
		if delay < 0 {
			delay = 0
		}
	}
	if delay > maxRetryDelay {
		return maxRetryDelay
	}
	return delay
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func invalidConfig(message string) error {
	return model.NewError(model.CodeInvalidInput, "WhatsApp notifier "+message)
}
