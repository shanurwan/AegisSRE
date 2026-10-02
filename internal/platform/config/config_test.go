package config

import (
	"strings"
	"testing"
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
	cfg, err := Load("operator")
	if err != nil {
		t.Fatalf("Load(operator) error = %v", err)
	}
	if !cfg.WhatsAppEnabled || cfg.WhatsAppGraphVersion != "v99.0" {
		t.Fatalf("unexpected WhatsApp config: %#v", cfg)
	}
}
