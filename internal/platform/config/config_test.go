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
	if !cfg.DryRun || cfg.AllowMutations || cfg.MaxScaleReplicas != 20 || cfg.MaxScaleIncrease != 5 {
		t.Fatalf("unexpected safety defaults: %#v", cfg)
	}
}
