package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// durableExecutionLeaseSafetyMargin covers the bounded post-cancellation
// reconciliation/receipt-persistence window used by Operator and action MCP.
// Their Aegis-owned request and persistence work must fit inside one lease;
// external acceptance after cancellation remains an uncertain outcome.
const durableExecutionLeaseSafetyMargin = 10 * time.Second

type Config struct {
	Role                     string
	ListenAddr               string
	AdminListenAddr          string
	PublicURL                string
	AllowedNamespace         string
	ObserveMCPURL            string
	OperateMCPURL            string
	InvestigatorURL          string
	OperatorURL              string
	VictoriaMetricsURL       string
	VictoriaLogsURL          string
	VictoriaTracesURL        string
	Backend                  string
	FixturePath              string
	Kubeconfig               string
	ScanInterval             time.Duration
	VerificationCount        int
	IncidentCooldown         time.Duration
	RequestTimeout           time.Duration
	EvidenceBudget           int
	MaxLogBytes              int
	DryRun                   bool
	AllowMutations           bool
	AllowLogTraceActions     bool
	DelegationTTL            time.Duration
	MaxScaleReplicas         int
	MaxScaleIncrease         int
	DelegationPrivateKey     string
	DelegationPrivateKeyFile string
	DelegationPublicKey      string
	DelegationKeyID          string
	DelegationPublicKeysFile string
	WorkloadPolicyPath       string
	MTLSEnabled              bool
	TLSCertificateFile       string
	TLSPrivateKeyFile        string
	TLSCAFile                string
	TLSIdentity              string
	TrustDomain              string
	SystemNamespace          string
	DatabaseURL              string
	DatabaseURLFile          string
	DatabaseMaxConnections   int
	StateLease               time.Duration
	OutboxPollInterval       time.Duration
	OutboxMaxAttempts        int
	InstanceID               string
	LLMBaseURL               string
	LLMAPIKey                string
	LLMModel                 string
	WhatsAppEnabled          bool
	WhatsAppGraphVersion     string
	WhatsAppPhoneID          string
	WhatsAppAccessToken      string
	WhatsAppRecipient        string
	WhatsAppTemplate         string
	WhatsAppLanguage         string
	LogLevel                 string
	Discovery                string
	NANDAIndexURL            string
	NANDAInvestigatorID      string
	NANDAInvestigatorKey     string
	NANDAOperatorID          string
	NANDAOperatorKey         string
	NANDAAllowHTTP           bool
	NANDACacheTTL            time.Duration
	AgentFactsID             string
	AgentFactsPrivateKey     string
	AgentFactsPrivateKeyFile string
}

func Load(role string) (Config, error) {
	for _, name := range []string{
		"AEGIS_LISTEN_ADDR",
		"AEGIS_PUBLIC_URL",
		"AEGIS_ALLOWED_NAMESPACE",
		"AEGIS_OBSERVE_MCP_URL",
		"AEGIS_OPERATE_MCP_URL",
		"AEGIS_INVESTIGATOR_URL",
		"AEGIS_OPERATOR_URL",
		"AEGIS_VICTORIA_METRICS_URL",
		"AEGIS_VICTORIA_LOGS_URL",
		"AEGIS_VICTORIA_TRACES_URL",
		"AEGIS_BACKEND",
		"AEGIS_DELEGATION_KEY_ID",
		"AEGIS_LOG_LEVEL",
		"AEGIS_DISCOVERY",
		"AEGIS_NANDA_INDEX_URL",
	} {
		if value, exists := os.LookupEnv(name); exists && strings.TrimSpace(value) == "" {
			return Config{}, fmt.Errorf("%s is set but empty", name)
		}
	}
	cfg := Config{
		Role:                     role,
		ListenAddr:               env("AEGIS_LISTEN_ADDR", ":8080"),
		AdminListenAddr:          env("AEGIS_ADMIN_LISTEN_ADDR", ":9090"),
		PublicURL:                strings.TrimRight(env("AEGIS_PUBLIC_URL", "http://127.0.0.1:8080"), "/"),
		AllowedNamespace:         env("AEGIS_ALLOWED_NAMESPACE", "outage-arena"),
		ObserveMCPURL:            env("AEGIS_OBSERVE_MCP_URL", "http://127.0.0.1:8090/mcp"),
		OperateMCPURL:            env("AEGIS_OPERATE_MCP_URL", "http://127.0.0.1:8091/mcp"),
		InvestigatorURL:          strings.TrimRight(env("AEGIS_INVESTIGATOR_URL", "http://127.0.0.1:8081"), "/"),
		OperatorURL:              strings.TrimRight(env("AEGIS_OPERATOR_URL", "http://127.0.0.1:8082"), "/"),
		VictoriaMetricsURL:       strings.TrimRight(env("AEGIS_VICTORIA_METRICS_URL", "http://vmsingle.observability.svc.cluster.local:8428"), "/"),
		VictoriaLogsURL:          strings.TrimRight(env("AEGIS_VICTORIA_LOGS_URL", "http://vlogs.observability.svc.cluster.local:9428"), "/"),
		VictoriaTracesURL:        strings.TrimRight(env("AEGIS_VICTORIA_TRACES_URL", "http://vtraces.observability.svc.cluster.local:10428"), "/"),
		Backend:                  env("AEGIS_BACKEND", "kubernetes"),
		FixturePath:              os.Getenv("AEGIS_FIXTURE_PATH"),
		Kubeconfig:               os.Getenv("KUBECONFIG"),
		DelegationPrivateKey:     os.Getenv("AEGIS_DELEGATION_PRIVATE_KEY"),
		DelegationPrivateKeyFile: strings.TrimSpace(os.Getenv("AEGIS_DELEGATION_PRIVATE_KEY_FILE")),
		DelegationPublicKey:      os.Getenv("AEGIS_DELEGATION_PUBLIC_KEY"),
		DelegationKeyID:          env("AEGIS_DELEGATION_KEY_ID", "aegissre-monitor-v1"),
		DelegationPublicKeysFile: firstNonEmpty(
			strings.TrimSpace(os.Getenv("AEGIS_DELEGATION_PUBLIC_KEYRING_FILE")),
			strings.TrimSpace(os.Getenv("AEGIS_DELEGATION_PUBLIC_KEYS_FILE")),
		),
		WorkloadPolicyPath:   strings.TrimSpace(os.Getenv("AEGIS_WORKLOAD_POLICY_FILE")),
		TLSCertificateFile:   strings.TrimSpace(os.Getenv("AEGIS_TLS_CERT_FILE")),
		TLSPrivateKeyFile:    strings.TrimSpace(os.Getenv("AEGIS_TLS_KEY_FILE")),
		TLSCAFile:            strings.TrimSpace(os.Getenv("AEGIS_TLS_CA_FILE")),
		TLSIdentity:          strings.TrimSpace(os.Getenv("AEGIS_TLS_IDENTITY")),
		TrustDomain:          env("AEGIS_TRUST_DOMAIN", "aegissre.internal"),
		SystemNamespace:      env("AEGIS_SYSTEM_NAMESPACE", "aegissre-system"),
		DatabaseURL:          strings.TrimSpace(os.Getenv("AEGIS_DATABASE_URL")),
		DatabaseURLFile:      strings.TrimSpace(os.Getenv("AEGIS_DATABASE_URL_FILE")),
		InstanceID:           strings.TrimSpace(os.Getenv("AEGIS_INSTANCE_ID")),
		LLMBaseURL:           strings.TrimRight(os.Getenv("AEGIS_LLM_BASE_URL"), "/"),
		LLMAPIKey:            os.Getenv("AEGIS_LLM_API_KEY"),
		LLMModel:             strings.TrimSpace(os.Getenv("AEGIS_LLM_MODEL")),
		WhatsAppGraphVersion: strings.TrimSpace(os.Getenv("AEGIS_WHATSAPP_GRAPH_VERSION")),
		WhatsAppPhoneID:      strings.TrimSpace(os.Getenv("AEGIS_WHATSAPP_PHONE_NUMBER_ID")),
		WhatsAppAccessToken:  strings.TrimSpace(os.Getenv("AEGIS_WHATSAPP_ACCESS_TOKEN")),
		WhatsAppRecipient:    strings.TrimSpace(os.Getenv("AEGIS_WHATSAPP_RECIPIENT")),
		WhatsAppTemplate:     env("AEGIS_WHATSAPP_TEMPLATE", "aegissre_incident_update"),
		WhatsAppLanguage:     env("AEGIS_WHATSAPP_LANGUAGE", "en_US"),
		LogLevel:             env("AEGIS_LOG_LEVEL", "info"),
	}
	cfg.Discovery = env("AEGIS_DISCOVERY", "static")
	cfg.NANDAIndexURL = strings.TrimRight(env("AEGIS_NANDA_INDEX_URL", "https://api.nandaindex.org"), "/")
	cfg.NANDAInvestigatorID = strings.TrimSpace(os.Getenv("AEGIS_NANDA_INVESTIGATOR_ID"))
	cfg.NANDAInvestigatorKey = strings.TrimSpace(os.Getenv("AEGIS_NANDA_INVESTIGATOR_KEY"))
	cfg.NANDAOperatorID = strings.TrimSpace(os.Getenv("AEGIS_NANDA_OPERATOR_ID"))
	cfg.NANDAOperatorKey = strings.TrimSpace(os.Getenv("AEGIS_NANDA_OPERATOR_KEY"))
	cfg.AgentFactsID = strings.TrimSpace(os.Getenv("AEGIS_AGENTFACTS_ID"))
	cfg.AgentFactsPrivateKey = os.Getenv("AEGIS_AGENTFACTS_PRIVATE_KEY")
	cfg.AgentFactsPrivateKeyFile = strings.TrimSpace(os.Getenv("AEGIS_AGENTFACTS_PRIVATE_KEY_FILE"))
	var err error
	if cfg.ScanInterval, err = duration("AEGIS_SCAN_INTERVAL", 30*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.VerificationCount, err = integer("AEGIS_VERIFICATION_COUNT", 2); err != nil {
		return Config{}, err
	}
	if cfg.IncidentCooldown, err = duration("AEGIS_INCIDENT_COOLDOWN", 15*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.RequestTimeout, err = duration("AEGIS_REQUEST_TIMEOUT", 10*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.EvidenceBudget, err = integer("AEGIS_EVIDENCE_BUDGET", 6); err != nil {
		return Config{}, err
	}
	if cfg.MaxLogBytes, err = integer("AEGIS_MAX_LOG_BYTES", 32768); err != nil {
		return Config{}, err
	}
	if cfg.DryRun, err = boolean("AEGIS_DRY_RUN", true); err != nil {
		return Config{}, err
	}
	if cfg.AllowMutations, err = boolean("AEGIS_ALLOW_MUTATIONS", false); err != nil {
		return Config{}, err
	}
	if cfg.AllowLogTraceActions, err = boolean("AEGIS_ALLOW_LOG_TRACE_ACTIONS", false); err != nil {
		return Config{}, err
	}
	if cfg.MTLSEnabled, err = boolean("AEGIS_MTLS_ENABLED", false); err != nil {
		return Config{}, err
	}
	if cfg.DelegationTTL, err = duration("AEGIS_DELEGATION_TTL", 2*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.MaxScaleReplicas, err = integer("AEGIS_MAX_SCALE_REPLICAS", 20); err != nil {
		return Config{}, err
	}
	if cfg.MaxScaleIncrease, err = integer("AEGIS_MAX_SCALE_INCREASE", 5); err != nil {
		return Config{}, err
	}
	if cfg.WhatsAppEnabled, err = boolean("AEGIS_WHATSAPP_ENABLED", false); err != nil {
		return Config{}, err
	}
	if cfg.DatabaseMaxConnections, err = integer("AEGIS_DATABASE_MAX_CONNECTIONS", 8); err != nil {
		return Config{}, err
	}
	if cfg.StateLease, err = duration("AEGIS_STATE_LEASE", time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.OutboxPollInterval, err = duration("AEGIS_OUTBOX_POLL_INTERVAL", 2*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.OutboxMaxAttempts, err = integer("AEGIS_OUTBOX_MAX_ATTEMPTS", 8); err != nil {
		return Config{}, err
	}
	if cfg.NANDAAllowHTTP, err = boolean("AEGIS_NANDA_ALLOW_HTTP", false); err != nil {
		return Config{}, err
	}
	if cfg.NANDACacheTTL, err = duration("AEGIS_NANDA_CACHE_TTL", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if err := c.validateDiscovery(); err != nil {
		return err
	}
	if c.ListenAddr == "" || c.AdminListenAddr == "" || c.PublicURL == "" || c.AllowedNamespace == "" {
		return errors.New("listen address, public URL, and allowed namespace are required")
	}
	if c.MTLSEnabled && c.ListenAddr == c.AdminListenAddr {
		return errors.New("AEGIS_ADMIN_LISTEN_ADDR must differ from AEGIS_LISTEN_ADDR when mTLS is enabled")
	}
	if c.ScanInterval <= 0 || c.ScanInterval > 24*time.Hour || c.VerificationCount < 1 || c.VerificationCount > 10 {
		return errors.New("scan interval must be positive and verification count must be 1..10")
	}
	if c.IncidentCooldown <= 0 || c.IncidentCooldown > 7*24*time.Hour {
		return errors.New("incident cooldown must be positive and no more than seven days")
	}
	if c.RequestTimeout < time.Second || c.RequestTimeout > 2*time.Minute {
		return errors.New("request timeout must be between one second and two minutes")
	}
	if c.EvidenceBudget < 1 || c.EvidenceBudget > 20 || c.MaxLogBytes < 1024 || c.MaxLogBytes > 131072 {
		return errors.New("evidence budget or maximum log size is outside its safe bound")
	}
	if c.DelegationTTL <= 0 || c.DelegationTTL > 5*time.Minute {
		return errors.New("delegation TTL must be positive and no more than five minutes")
	}
	if c.MaxScaleReplicas < 1 || c.MaxScaleReplicas > 1000 || c.MaxScaleIncrease < 1 || c.MaxScaleIncrease > c.MaxScaleReplicas {
		return errors.New("replica policy bounds are invalid")
	}
	if strings.TrimSpace(c.DelegationKeyID) == "" {
		return errors.New("delegation key ID is required")
	}
	if c.DelegationPrivateKey != "" && c.DelegationPrivateKeyFile != "" {
		return errors.New("configure only one of AEGIS_DELEGATION_PRIVATE_KEY or AEGIS_DELEGATION_PRIVATE_KEY_FILE")
	}
	if c.DelegationPublicKey != "" && c.DelegationPublicKeysFile != "" {
		return errors.New("configure only one of AEGIS_DELEGATION_PUBLIC_KEY or AEGIS_DELEGATION_PUBLIC_KEYRING_FILE")
	}
	if c.DatabaseURL != "" && c.DatabaseURLFile != "" {
		return errors.New("configure only one of AEGIS_DATABASE_URL or AEGIS_DATABASE_URL_FILE")
	}
	if c.InstanceID != "" && (strings.TrimSpace(c.InstanceID) != c.InstanceID || len(c.InstanceID) > 512) {
		return errors.New("AEGIS_INSTANCE_ID must be non-blank and no more than 512 bytes")
	}
	if c.DatabaseMaxConnections < 1 || c.DatabaseMaxConnections > 50 {
		return errors.New("AEGIS_DATABASE_MAX_CONNECTIONS must be between one and fifty")
	}
	if c.StateLease < 5*time.Second || c.StateLease > 5*time.Minute {
		return errors.New("AEGIS_STATE_LEASE must be between five seconds and five minutes")
	}
	if c.Role == "monitor" && (c.DatabaseURL != "" || c.DatabaseURLFile != "") && c.StateLease <= c.ScanInterval {
		return errors.New("AEGIS_STATE_LEASE must exceed AEGIS_SCAN_INTERVAL for durable Monitor leadership")
	}
	if (c.Role == "operator" || c.Role == "mcp-action") &&
		(c.DatabaseURL != "" || c.DatabaseURLFile != "") &&
		c.StateLease <= c.RequestTimeout+durableExecutionLeaseSafetyMargin {
		return errors.New("AEGIS_STATE_LEASE must exceed AEGIS_REQUEST_TIMEOUT by more than ten seconds for durable execution fencing")
	}
	if c.OutboxPollInterval < 100*time.Millisecond || c.OutboxPollInterval > time.Minute {
		return errors.New("AEGIS_OUTBOX_POLL_INTERVAL must be between 100ms and one minute")
	}
	if c.OutboxMaxAttempts < 1 || c.OutboxMaxAttempts > 100 {
		return errors.New("AEGIS_OUTBOX_MAX_ATTEMPTS must be between one and one hundred")
	}
	if !validDNSName(c.TrustDomain, true) || !validDNSName(c.SystemNamespace, false) {
		return errors.New("AEGIS_TRUST_DOMAIN or AEGIS_SYSTEM_NAMESPACE is invalid")
	}
	if c.MTLSEnabled {
		for name, value := range map[string]string{
			"AEGIS_TLS_CERT_FILE": c.TLSCertificateFile,
			"AEGIS_TLS_KEY_FILE":  c.TLSPrivateKeyFile,
			"AEGIS_TLS_CA_FILE":   c.TLSCAFile,
			"AEGIS_TLS_IDENTITY":  c.TLSIdentity,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s is required when AEGIS_MTLS_ENABLED=true", name)
			}
		}
		expected, err := workloadIdentity(c.TrustDomain, c.SystemNamespace, c.Role)
		if err != nil {
			return err
		}
		if c.TLSIdentity != expected {
			return errors.New("AEGIS_TLS_IDENTITY does not match the configured AegisSRE role")
		}
		for name, value := range map[string]string{
			"AEGIS_PUBLIC_URL":       c.PublicURL,
			"AEGIS_OBSERVE_MCP_URL":  c.ObserveMCPURL,
			"AEGIS_OPERATE_MCP_URL":  c.OperateMCPURL,
			"AEGIS_INVESTIGATOR_URL": c.InvestigatorURL,
			"AEGIS_OPERATOR_URL":     c.OperatorURL,
		} {
			parsed, _ := url.Parse(value)
			if parsed == nil || parsed.Scheme != "https" {
				return fmt.Errorf("%s must use https when AEGIS_MTLS_ENABLED=true", name)
			}
		}
	}
	if (!c.DryRun || c.AllowMutations) && c.Role != "test" && !c.MTLSEnabled {
		return errors.New("AEGIS_MTLS_ENABLED=true is required for live action-plane configuration")
	}
	if (c.MTLSEnabled || !c.DryRun || c.AllowMutations) &&
		(c.Role == "monitor" || c.Role == "operator" || c.Role == "mcp-action") &&
		c.DatabaseURL == "" && c.DatabaseURLFile == "" {
		return errors.New("durable PostgreSQL state is required for an authenticated production Monitor, Operator, or action MCP")
	}
	if (c.MTLSEnabled || !c.DryRun || c.AllowMutations) &&
		(c.Role == "monitor" || c.Role == "operator" || c.Role == "mcp-read" || c.Role == "mcp-action") &&
		strings.TrimSpace(c.WorkloadPolicyPath) == "" {
		return errors.New("AEGIS_WORKLOAD_POLICY_FILE is required for authenticated production control-plane configuration")
	}
	if c.MTLSEnabled {
		switch c.Role {
		case "monitor":
			if c.DelegationPrivateKeyFile == "" {
				return errors.New("AEGIS_DELEGATION_PRIVATE_KEY_FILE is required for an authenticated production Monitor")
			}
		case "operator", "mcp-action":
			if c.DelegationPublicKeysFile == "" {
				return errors.New("AEGIS_DELEGATION_PUBLIC_KEYRING_FILE is required for an authenticated production verifier")
			}
		}
	}
	if c.LLMBaseURL != "" && (c.LLMModel == "" || strings.TrimSpace(c.LLMAPIKey) == "") {
		return errors.New("AEGIS_LLM_MODEL and AEGIS_LLM_API_KEY are required when AEGIS_LLM_BASE_URL is set")
	}
	if c.WhatsAppEnabled && c.Role == "operator" {
		if c.DatabaseURL == "" && c.DatabaseURLFile == "" {
			return errors.New("AEGIS_WHATSAPP_ENABLED requires a durable PostgreSQL outbox")
		}
		for name, value := range map[string]string{
			"AEGIS_WHATSAPP_PHONE_NUMBER_ID": c.WhatsAppPhoneID,
			"AEGIS_WHATSAPP_ACCESS_TOKEN":    c.WhatsAppAccessToken,
			"AEGIS_WHATSAPP_RECIPIENT":       c.WhatsAppRecipient,
			"AEGIS_WHATSAPP_GRAPH_VERSION":   c.WhatsAppGraphVersion,
			"AEGIS_WHATSAPP_TEMPLATE":        c.WhatsAppTemplate,
			"AEGIS_WHATSAPP_LANGUAGE":        c.WhatsAppLanguage,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s is required when AEGIS_WHATSAPP_ENABLED=true for Operator", name)
			}
		}
		if !validGraphVersion(c.WhatsAppGraphVersion) {
			return errors.New("AEGIS_WHATSAPP_GRAPH_VERSION must be a pinned version such as v23.0")
		}
		if !digitsOnly(c.WhatsAppPhoneID) || len(c.WhatsAppPhoneID) > 32 ||
			!digitsOnly(c.WhatsAppRecipient) || len(c.WhatsAppRecipient) < 6 || len(c.WhatsAppRecipient) > 32 {
			return errors.New("WhatsApp phone-number ID and recipient must contain digits only")
		}
		if len(c.WhatsAppTemplate) > 512 || !validTemplateName(c.WhatsAppTemplate) {
			return errors.New("AEGIS_WHATSAPP_TEMPLATE must contain lowercase letters, digits, and underscores only")
		}
		if !validLanguage(c.WhatsAppLanguage) {
			return errors.New("AEGIS_WHATSAPP_LANGUAGE must use a supported locale form such as en_US")
		}
	}
	for name, value := range map[string]string{
		"AEGIS_PUBLIC_URL":           c.PublicURL,
		"AEGIS_OBSERVE_MCP_URL":      c.ObserveMCPURL,
		"AEGIS_OPERATE_MCP_URL":      c.OperateMCPURL,
		"AEGIS_INVESTIGATOR_URL":     c.InvestigatorURL,
		"AEGIS_OPERATOR_URL":         c.OperatorURL,
		"AEGIS_VICTORIA_METRICS_URL": c.VictoriaMetricsURL,
		"AEGIS_VICTORIA_LOGS_URL":    c.VictoriaLogsURL,
		"AEGIS_VICTORIA_TRACES_URL":  c.VictoriaTracesURL,
	} {
		if err := validateHTTPURL(name, value); err != nil {
			return err
		}
	}
	if c.LLMBaseURL != "" {
		if err := validateHTTPURL("AEGIS_LLM_BASE_URL", c.LLMBaseURL); err != nil {
			return err
		}
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unsupported AEGIS_LOG_LEVEL %q", c.LogLevel)
	}
	if c.Backend != "kubernetes" && c.Backend != "fixture" {
		return fmt.Errorf("unsupported AEGIS_BACKEND %q", c.Backend)
	}
	if c.Backend == "fixture" && c.FixturePath == "" {
		return errors.New("AEGIS_FIXTURE_PATH is required for the fixture backend")
	}
	if c.Role == "mcp-action" && c.Backend == "fixture" && (!c.DryRun || c.AllowMutations) {
		return errors.New("the fixture action backend is restricted to dry-run development; live action requires Kubernetes")
	}
	return nil
}

func validGraphVersion(value string) bool {
	if len(value) < 4 || value[0] != 'v' {
		return false
	}
	parts := strings.Split(value[1:], ".")
	if len(parts) != 2 || !digitsOnly(parts[0]) || !digitsOnly(parts[1]) {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	return err == nil && major > 0
}

func digitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validTemplateName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func validLanguage(value string) bool {
	parts := strings.Split(value, "_")
	if len(parts) < 1 || len(parts) > 2 || len(parts[0]) < 2 || len(parts[0]) > 3 {
		return false
	}
	for _, character := range parts[0] {
		if character < 'a' || character > 'z' {
			return false
		}
	}
	if len(parts) == 1 {
		return true
	}
	if len(parts[1]) != 2 {
		return false
	}
	for _, character := range parts[1] {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

func validateHTTPURL(name, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("%s must be an http(s) URL without user information", name)
	}
	return nil
}

func workloadIdentity(trustDomain, namespace, role string) (string, error) {
	serviceAccount := ""
	switch role {
	case "monitor":
		serviceAccount = "aegis-monitor"
	case "investigator":
		serviceAccount = "aegis-investigator"
	case "operator":
		serviceAccount = "aegis-operator"
	case "mcp-read":
		serviceAccount = "aegis-mcp-read"
	case "mcp-action":
		serviceAccount = "aegis-mcp-action"
	default:
		return "", fmt.Errorf("mTLS is unsupported for role %q", role)
	}
	return "spiffe://" + trustDomain + "/ns/" + namespace + "/sa/" + serviceAccount, nil
}

func validDNSName(value string, allowDots bool) bool {
	if value == "" || len(value) > 253 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '-' || allowDots && character == '.' {
			continue
		}
		return false
	}
	return !strings.Contains(value, "..")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func duration(name string, fallback time.Duration) (time.Duration, error) {
	raw, exists := os.LookupEnv(name)
	if !exists {
		return fallback, nil
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("%s is set but empty", name)
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid duration: %w", name, err)
	}
	return value, nil
}

func integer(name string, fallback int) (int, error) {
	raw, exists := os.LookupEnv(name)
	if !exists {
		return fallback, nil
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("%s is set but empty", name)
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid integer: %w", name, err)
	}
	return value, nil
}

func boolean(name string, fallback bool) (bool, error) {
	raw, exists := os.LookupEnv(name)
	if !exists {
		return fallback, nil
	}
	raw = strings.TrimSpace(raw)
	switch {
	case strings.EqualFold(raw, "true"):
		return true, nil
	case strings.EqualFold(raw, "false"):
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", name)
	}
}

func (c Config) validateDiscovery() error {
	switch c.Discovery {
	case "static":
	case "nanda":
		if c.Role != "monitor" {
			break
		}
		index, err := url.Parse(c.NANDAIndexURL)
		if err != nil || index.Host == "" || (index.Scheme != "https" && (index.Scheme != "http" || !c.NANDAAllowHTTP)) {
			return errors.New("AEGIS_NANDA_INDEX_URL must be an https URL (http only with AEGIS_NANDA_ALLOW_HTTP=true)")
		}
		for name, value := range map[string]string{
			"AEGIS_NANDA_INVESTIGATOR_ID": c.NANDAInvestigatorID, "AEGIS_NANDA_OPERATOR_ID": c.NANDAOperatorID,
		} {
			if !strings.HasPrefix(value, "urn:air:") {
				return fmt.Errorf("%s must be a urn:air: identifier when AEGIS_DISCOVERY=nanda", name)
			}
		}
		for name, value := range map[string]string{
			"AEGIS_NANDA_INVESTIGATOR_KEY": c.NANDAInvestigatorKey, "AEGIS_NANDA_OPERATOR_KEY": c.NANDAOperatorKey,
		} {
			if !strings.HasPrefix(value, "did:key:") {
				return fmt.Errorf("%s must pin the peer's did:key when AEGIS_DISCOVERY=nanda", name)
			}
		}
	default:
		return errors.New("AEGIS_DISCOVERY must be static or nanda")
	}
	if c.NANDACacheTTL < 10*time.Second || c.NANDACacheTTL > time.Hour {
		return errors.New("AEGIS_NANDA_CACHE_TTL must be between ten seconds and one hour")
	}
	if c.MTLSEnabled && c.NANDAAllowHTTP {
		return errors.New("AEGIS_NANDA_ALLOW_HTTP is for local fixtures and cannot be combined with mTLS")
	}
	if c.AgentFactsPrivateKey != "" && c.AgentFactsPrivateKeyFile != "" {
		return errors.New("configure only one of AEGIS_AGENTFACTS_PRIVATE_KEY or AEGIS_AGENTFACTS_PRIVATE_KEY_FILE")
	}
	hasKey := c.AgentFactsPrivateKey != "" || c.AgentFactsPrivateKeyFile != ""
	if hasKey != (c.AgentFactsID != "") {
		return errors.New("AEGIS_AGENTFACTS_ID and an AgentFacts private key must be configured together")
	}
	if c.AgentFactsID != "" && !strings.HasPrefix(c.AgentFactsID, "urn:air:") {
		return errors.New("AEGIS_AGENTFACTS_ID must be a urn:air: identifier")
	}
	return nil
}
