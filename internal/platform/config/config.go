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

type Config struct {
	Role                 string
	ListenAddr           string
	PublicURL            string
	AllowedNamespace     string
	ObserveMCPURL        string
	OperateMCPURL        string
	InvestigatorURL      string
	OperatorURL          string
	VictoriaMetricsURL   string
	VictoriaLogsURL      string
	Backend              string
	FixturePath          string
	Kubeconfig           string
	ScanInterval         time.Duration
	VerificationCount    int
	IncidentCooldown     time.Duration
	RequestTimeout       time.Duration
	EvidenceBudget       int
	MaxLogBytes          int
	DryRun               bool
	AllowMutations       bool
	DelegationTTL        time.Duration
	MaxScaleReplicas     int
	MaxScaleIncrease     int
	DelegationPrivateKey string
	DelegationPublicKey  string
	DelegationKeyID      string
	LLMBaseURL           string
	LLMAPIKey            string
	LLMModel             string
	LogLevel             string
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
		"AEGIS_BACKEND",
		"AEGIS_DELEGATION_KEY_ID",
		"AEGIS_LOG_LEVEL",
	} {
		if value, exists := os.LookupEnv(name); exists && strings.TrimSpace(value) == "" {
			return Config{}, fmt.Errorf("%s is set but empty", name)
		}
	}
	cfg := Config{
		Role:                 role,
		ListenAddr:           env("AEGIS_LISTEN_ADDR", ":8080"),
		PublicURL:            strings.TrimRight(env("AEGIS_PUBLIC_URL", "http://127.0.0.1:8080"), "/"),
		AllowedNamespace:     env("AEGIS_ALLOWED_NAMESPACE", "outage-arena"),
		ObserveMCPURL:        env("AEGIS_OBSERVE_MCP_URL", "http://127.0.0.1:8090/mcp"),
		OperateMCPURL:        env("AEGIS_OPERATE_MCP_URL", "http://127.0.0.1:8091/mcp"),
		InvestigatorURL:      strings.TrimRight(env("AEGIS_INVESTIGATOR_URL", "http://127.0.0.1:8081"), "/"),
		OperatorURL:          strings.TrimRight(env("AEGIS_OPERATOR_URL", "http://127.0.0.1:8082"), "/"),
		VictoriaMetricsURL:   strings.TrimRight(env("AEGIS_VICTORIA_METRICS_URL", "http://vmsingle.observability.svc.cluster.local:8428"), "/"),
		VictoriaLogsURL:      strings.TrimRight(env("AEGIS_VICTORIA_LOGS_URL", "http://vlogs.observability.svc.cluster.local:9428"), "/"),
		Backend:              env("AEGIS_BACKEND", "kubernetes"),
		FixturePath:          os.Getenv("AEGIS_FIXTURE_PATH"),
		Kubeconfig:           os.Getenv("KUBECONFIG"),
		DelegationPrivateKey: os.Getenv("AEGIS_DELEGATION_PRIVATE_KEY"),
		DelegationPublicKey:  os.Getenv("AEGIS_DELEGATION_PUBLIC_KEY"),
		DelegationKeyID:      env("AEGIS_DELEGATION_KEY_ID", "aegissre-monitor-v1"),
		LLMBaseURL:           strings.TrimRight(os.Getenv("AEGIS_LLM_BASE_URL"), "/"),
		LLMAPIKey:            os.Getenv("AEGIS_LLM_API_KEY"),
		LLMModel:             strings.TrimSpace(os.Getenv("AEGIS_LLM_MODEL")),
		LogLevel:             env("AEGIS_LOG_LEVEL", "info"),
	}
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
	if cfg.DelegationTTL, err = duration("AEGIS_DELEGATION_TTL", 2*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.MaxScaleReplicas, err = integer("AEGIS_MAX_SCALE_REPLICAS", 20); err != nil {
		return Config{}, err
	}
	if cfg.MaxScaleIncrease, err = integer("AEGIS_MAX_SCALE_INCREASE", 5); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.ListenAddr == "" || c.PublicURL == "" || c.AllowedNamespace == "" {
		return errors.New("listen address, public URL, and allowed namespace are required")
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
	if c.LLMBaseURL != "" && (c.LLMModel == "" || strings.TrimSpace(c.LLMAPIKey) == "") {
		return errors.New("AEGIS_LLM_MODEL and AEGIS_LLM_API_KEY are required when AEGIS_LLM_BASE_URL is set")
	}
	for name, value := range map[string]string{
		"AEGIS_PUBLIC_URL":           c.PublicURL,
		"AEGIS_OBSERVE_MCP_URL":      c.ObserveMCPURL,
		"AEGIS_OPERATE_MCP_URL":      c.OperateMCPURL,
		"AEGIS_INVESTIGATOR_URL":     c.InvestigatorURL,
		"AEGIS_OPERATOR_URL":         c.OperatorURL,
		"AEGIS_VICTORIA_METRICS_URL": c.VictoriaMetricsURL,
		"AEGIS_VICTORIA_LOGS_URL":    c.VictoriaLogsURL,
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
	return nil
}

func validateHTTPURL(name, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("%s must be an http(s) URL without user information", name)
	}
	return nil
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
