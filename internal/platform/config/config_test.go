package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadRejectsMalformedSafetySettings(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "AEGIS_MAX_SCALE_REPLICAS", value: "2x"},
		{name: "AEGIS_INCIDENT_COOLDOWN", value: "tomorrow"},
		{name: "AEGIS_ALLOW_MUTATIONS", value: "tru"},
		{name: "AEGIS_ALLOW_LOG_TRACE_ACTIONS", value: "tru"},
		{name: "AEGIS_DRY_RUN", value: ""},
		{name: "AEGIS_ALLOWED_NAMESPACE", value: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.name, test.value)
			_, err := Load("test")
			if err == nil || !strings.Contains(err.Error(), test.name) {
				t.Fatalf("Load() error = %v, want strict %s parse error", err, test.name)
			}
		})
	}
}

func TestLoadUsesSafeDefaultsWhenSettingsAreUnset(t *testing.T) {
	cfg, err := Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DryRun || cfg.AllowMutations || cfg.AllowLogTraceActions || cfg.MaxScaleReplicas != 20 || cfg.MaxScaleIncrease != 5 {
		t.Fatalf("unexpected safety defaults: %#v", cfg)
	}
	if cfg.WhatsAppEnabled {
		t.Fatal("WhatsApp must be disabled unless explicitly configured")
	}
}

func TestLoadRequiresExplicitLogTraceActionOptIn(t *testing.T) {
	t.Setenv("AEGIS_ALLOW_LOG_TRACE_ACTIONS", "true")
	cfg, err := Load("monitor")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowLogTraceActions {
		t.Fatal("explicit log/trace action opt-in was not loaded")
	}
}

func TestOperatorWhatsAppConfigurationIsAllOrNothing(t *testing.T) {
	t.Setenv("AEGIS_WHATSAPP_ENABLED", "true")
	if _, err := Load("operator"); err == nil || !strings.Contains(err.Error(), "AEGIS_WHATSAPP") {
		t.Fatalf("Load(operator) error = %v, want missing WhatsApp configuration", err)
	}

	t.Setenv("AEGIS_WHATSAPP_GRAPH_VERSION", "v99.0")
	t.Setenv("AEGIS_WHATSAPP_PHONE_NUMBER_ID", "123456789")
	t.Setenv("AEGIS_WHATSAPP_ACCESS_TOKEN", "test-token")
	t.Setenv("AEGIS_WHATSAPP_RECIPIENT", "60123456789")
	t.Setenv("AEGIS_WHATSAPP_TEMPLATE", "aegissre_incident_update")
	t.Setenv("AEGIS_WHATSAPP_LANGUAGE", "en_US")
	t.Setenv("AEGIS_DATABASE_URL", "postgres://aegis:secret@postgres/aegis?sslmode=require")
	cfg, err := Load("operator")
	if err != nil {
		t.Fatalf("Load(operator) error = %v", err)
	}
	if !cfg.WhatsAppEnabled || cfg.WhatsAppGraphVersion != "v99.0" {
		t.Fatalf("unexpected WhatsApp config: %#v", cfg)
	}
}

func TestOperatorWhatsAppLeaseMustCoverProviderTimeout(t *testing.T) {
	cfg, err := Load("test")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Role = "operator"
	cfg.WhatsAppEnabled = true
	cfg.DatabaseURL = "postgres://aegis:secret@postgres/aegis?sslmode=require"
	cfg.WhatsAppGraphVersion = "v99.0"
	cfg.WhatsAppPhoneID = "123456789"
	cfg.WhatsAppAccessToken = "test-token"
	cfg.WhatsAppRecipient = "60123456789"
	cfg.WhatsAppTemplate = "aegissre_incident_update"
	cfg.WhatsAppLanguage = "en_US"
	cfg.RequestTimeout = 59 * time.Second
	cfg.StateLease = time.Minute
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "AEGIS_STATE_LEASE") {
		t.Fatalf("Validate() error = %v, want unsafe outbox lease rejection", err)
	}
	cfg.RequestTimeout = 10 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() safe outbox lease error = %v", err)
	}
}

func TestDurableExecutionLeaseMustOutliveRequestAndRecoveryWindow(t *testing.T) {
	for _, role := range []string{"operator", "mcp-action"} {
		role := role
		t.Run(role, func(t *testing.T) {
			cfg, err := Load("test")
			if err != nil {
				t.Fatal(err)
			}
			cfg.Role = role
			cfg.DatabaseURL = "postgres://aegis:secret@postgres/aegis?sslmode=require"
			cfg.RequestTimeout = 10 * time.Second

			// Equality is unsafe: a former owner may still be in its bounded
			// post-cancellation durable-write window at takeover time.
			cfg.StateLease = cfg.RequestTimeout + durableExecutionLeaseSafetyMargin
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "durable execution fencing") {
				t.Fatalf("Validate() error = %v, want unsafe durable lease rejection", err)
			}

			cfg.StateLease += time.Second
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() safe durable lease error = %v", err)
			}
		})
	}
}

func TestLiveOperatorRequiresBoundMTLSAndDurableState(t *testing.T) {
	t.Setenv("AEGIS_DRY_RUN", "false")
	t.Setenv("AEGIS_WORKLOAD_POLICY_FILE", "/etc/aegissre/policy.json")
	if _, err := Load("operator"); err == nil || !strings.Contains(err.Error(), "AEGIS_MTLS_ENABLED") {
		t.Fatalf("Load(operator) without mTLS error = %v", err)
	}

	t.Setenv("AEGIS_MTLS_ENABLED", "true")
	t.Setenv("AEGIS_LISTEN_ADDR", ":8443")
	t.Setenv("AEGIS_ADMIN_LISTEN_ADDR", ":9090")
	t.Setenv("AEGIS_PUBLIC_URL", "https://aegis-operator:8443")
	t.Setenv("AEGIS_OBSERVE_MCP_URL", "https://aegis-mcp-read:8443/mcp")
	t.Setenv("AEGIS_OPERATE_MCP_URL", "https://aegis-mcp-action:8443/mcp")
	t.Setenv("AEGIS_INVESTIGATOR_URL", "https://aegis-investigator:8443")
	t.Setenv("AEGIS_OPERATOR_URL", "https://aegis-operator:8443")
	t.Setenv("AEGIS_TLS_CERT_FILE", "/var/run/secrets/aegissre/tls/tls.crt")
	t.Setenv("AEGIS_TLS_KEY_FILE", "/var/run/secrets/aegissre/tls/tls.key")
	t.Setenv("AEGIS_TLS_CA_FILE", "/var/run/secrets/aegissre/trust/ca.crt")
	t.Setenv("AEGIS_TLS_IDENTITY", "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-operator")
	if _, err := Load("operator"); err == nil || !strings.Contains(err.Error(), "durable PostgreSQL") {
		t.Fatalf("Load(operator) without database error = %v", err)
	}
	t.Setenv("AEGIS_DATABASE_URL_FILE", "/var/run/secrets/aegissre/database/url")
	t.Setenv("AEGIS_DELEGATION_PUBLIC_KEYRING_FILE", "/var/run/secrets/aegissre/signing/trusted-public-keys.json")
	if _, err := Load("operator"); err != nil {
		t.Fatalf("Load(operator) production configuration error = %v", err)
	}
	t.Setenv("AEGIS_TLS_IDENTITY", "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-monitor")
	if _, err := Load("operator"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Load(operator) wrong local identity error = %v", err)
	}
}

func TestAuthenticatedReadMCPRequiresExactWorkloadPolicy(t *testing.T) {
	cfg, err := Load("test")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Role = "mcp-read"
	cfg.MTLSEnabled = true
	cfg.ListenAddr, cfg.AdminListenAddr = ":8443", ":9090"
	cfg.PublicURL = "https://aegis-mcp-read:8443"
	cfg.ObserveMCPURL = "https://aegis-mcp-read:8443/mcp"
	cfg.OperateMCPURL = "https://aegis-mcp-action:8443/mcp"
	cfg.InvestigatorURL = "https://aegis-investigator:8443"
	cfg.OperatorURL = "https://aegis-operator:8443"
	cfg.TLSCertificateFile = "/tls/tls.crt"
	cfg.TLSPrivateKeyFile = "/tls/tls.key"
	cfg.TLSCAFile = "/tls/ca.crt"
	cfg.TLSIdentity = "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-mcp-read"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "AEGIS_WORKLOAD_POLICY_FILE") {
		t.Fatalf("Validate() error = %v, want exact read policy requirement", err)
	}
	cfg.WorkloadPolicyPath = "/etc/aegissre/policy.json"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() authenticated read MCP error = %v", err)
	}
}

func TestLiveFixtureActionBackendIsRejected(t *testing.T) {
	cfg, err := Load("test")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Role = "mcp-action"
	cfg.Backend = "fixture"
	cfg.FixturePath = "fixture.json"
	cfg.DryRun = false
	cfg.AllowMutations = true
	cfg.MTLSEnabled = true
	cfg.ListenAddr, cfg.AdminListenAddr = ":8443", ":9090"
	cfg.PublicURL = "https://aegis-mcp-action:8443"
	cfg.ObserveMCPURL = "https://aegis-mcp-read:8443/mcp"
	cfg.OperateMCPURL = "https://aegis-mcp-action:8443/mcp"
	cfg.InvestigatorURL = "https://aegis-investigator:8443"
	cfg.OperatorURL = "https://aegis-operator:8443"
	cfg.TLSCertificateFile = "/tls/tls.crt"
	cfg.TLSPrivateKeyFile = "/tls/tls.key"
	cfg.TLSCAFile = "/tls/ca.crt"
	cfg.TLSIdentity = "spiffe://aegissre.internal/ns/aegissre-system/sa/aegis-mcp-action"
	cfg.WorkloadPolicyPath = "/etc/aegissre/policy.json"
	cfg.DatabaseURL = "postgres://aegis:secret@postgres/aegis?sslmode=verify-full"
	cfg.DelegationPublicKeysFile = "/signing/trusted-public-keys.json"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "fixture action backend") {
		t.Fatalf("Validate() error = %v, want live fixture rejection", err)
	}
}

func TestInstanceIDIsBounded(t *testing.T) {
	cfg, err := Load("test")
	if err != nil {
		t.Fatal(err)
	}
	cfg.InstanceID = strings.Repeat("x", 513)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "AEGIS_INSTANCE_ID") {
		t.Fatalf("Validate() error = %v, want bounded instance ID rejection", err)
	}
}

func TestDiscoveryDefaultsToStaticAddresses(t *testing.T) {
	cfg, err := Load("monitor")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Discovery != "static" || cfg.AgentFactsID != "" {
		t.Fatalf("discovery = %q, AgentFacts = %q; NANDA must be opt-in", cfg.Discovery, cfg.AgentFactsID)
	}
}

func TestNANDADiscoveryRequiresPinnedPeerIdentities(t *testing.T) {
	setNANDA := func(t *testing.T) {
		t.Setenv("AEGIS_DISCOVERY", "nanda")
		t.Setenv("AEGIS_NANDA_INVESTIGATOR_ID", "urn:air:aegis.example.org:agent:investigator")
		t.Setenv("AEGIS_NANDA_OPERATOR_ID", "urn:air:aegis.example.org:agent:operator")
		t.Setenv("AEGIS_NANDA_INVESTIGATOR_KEY", "did:key:zaaaaaaaaaaaaaaaa")
		t.Setenv("AEGIS_NANDA_OPERATOR_KEY", "did:key:zbbbbbbbbbbbbbbbb")
	}
	t.Run("complete", func(t *testing.T) {
		setNANDA(t)
		if _, err := Load("monitor"); err != nil {
			t.Fatal(err)
		}
	})
	tests := map[string]func(*testing.T){
		"AEGIS_DISCOVERY":              func(t *testing.T) { t.Setenv("AEGIS_DISCOVERY", "dns") },
		"AEGIS_NANDA_OPERATOR_ID":      func(t *testing.T) { t.Setenv("AEGIS_NANDA_OPERATOR_ID", "https://operator.example") },
		"AEGIS_NANDA_INVESTIGATOR_KEY": func(t *testing.T) { t.Setenv("AEGIS_NANDA_INVESTIGATOR_KEY", "") },
		"AEGIS_NANDA_INDEX_URL":        func(t *testing.T) { t.Setenv("AEGIS_NANDA_INDEX_URL", "http://index.example") },
		"AEGIS_NANDA_CACHE_TTL":        func(t *testing.T) { t.Setenv("AEGIS_NANDA_CACHE_TTL", "1s") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			setNANDA(t)
			mutate(t)
			if _, err := Load("monitor"); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("Load(monitor) error = %v, want a %s error", err, name)
			}
		})
	}
}

func TestAgentFactsIdentityAndKeyAreConfiguredTogether(t *testing.T) {
	t.Setenv("AEGIS_AGENTFACTS_ID", "urn:air:aegis.example.org:agent:investigator")
	if _, err := Load("investigator"); err == nil || !strings.Contains(err.Error(), "AEGIS_AGENTFACTS_ID") {
		t.Fatalf("Load(investigator) error = %v, want an AgentFacts key error", err)
	}
	t.Setenv("AEGIS_AGENTFACTS_PRIVATE_KEY", "c2VlZA")
	if _, err := Load("investigator"); err != nil {
		t.Fatal(err)
	}
}

func TestLLMWireAPIAndThinkingAreValidated(t *testing.T) {
	t.Setenv("AEGIS_LLM_THINKING", "false")
	if _, err := Load("investigator"); err == nil || !strings.Contains(err.Error(), "AEGIS_LLM_THINKING") {
		t.Fatalf("thinking without chat_completions: %v", err)
	}
	t.Setenv("AEGIS_LLM_API", "chat_completions")
	if _, err := Load("investigator"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEGIS_LLM_API", "completions")
	if _, err := Load("investigator"); err == nil || !strings.Contains(err.Error(), "AEGIS_LLM_API") {
		t.Fatalf("unknown API accepted: %v", err)
	}
}
