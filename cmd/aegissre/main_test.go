package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shanurwan/AegisSRE/internal/app/monitor"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/platform/config"
)

func TestMonitorTerminalLogsCarryOnlySafeRunCorrelation(t *testing.T) {
	t.Parallel()
	target := model.ResourceTarget{
		APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "aegissre-e2e-canary",
	}
	const secretSignature = "do-not-log-grant-signature"
	outcome := monitor.IncidentOutcome{
		Incident: model.Incident{ID: "incident-live-1", State: model.IncidentResolved},
		Grant: &model.DelegationGrant{
			GrantID: "grant-live-1", Action: model.ActionSpec{Kind: model.ActionRestartDeployment, Target: target},
			Signature: model.GrantSignature{Algorithm: model.SignatureAlgorithmEd25519, KeyID: "key-1", Value: secretSignature},
		},
		Status: "resolved",
		Detail: "follow-up observation meets availability criteria",
		Report: &model.IncidentReportResult{
			Report: model.IncidentReport{
				ReportID: "report-live-1", IncidentID: "incident-live-1", Target: target,
				Execution: &model.IncidentReportExecution{GrantID: "grant-live-1"},
			},
			Notification: model.NotificationReceipt{
				Channel: model.NotificationChannelWhatsApp, Status: model.NotificationQueued,
			},
		},
	}

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logMonitorOutcome(context.Background(), logger, outcome)
	if strings.Contains(output.String(), secretSignature) || strings.Contains(output.String(), `"signature"`) {
		t.Fatalf("terminal logs exposed delegation signature material: %s", output.String())
	}

	decoder := json.NewDecoder(&output)
	for index, message := range []string{"incident outcome", "incident report outcome"} {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			t.Fatalf("decode log event %d: %v", index, err)
		}
		for key, want := range map[string]string{
			"msg": message, "incident_id": "incident-live-1", "grant_id": "grant-live-1",
			"target_api_version": "apps/v1", "target_kind": "Deployment",
			"target_namespace": "outage-arena", "target_name": "aegissre-e2e-canary",
		} {
			if got := event[key]; got != want {
				t.Fatalf("event %d field %s = %#v, want %q", index, key, got, want)
			}
		}
	}
}

func TestValidatePostgresTransportRequiresVerifiedTLSInProduction(t *testing.T) {
	t.Parallel()
	production := config.Config{Role: "operator", MTLSEnabled: true}
	for _, connectionString := range []string{
		"postgres://aegis:secret@postgres.internal/aegis?sslmode=disable",
		"postgres://aegis:secret@postgres.internal/aegis?sslmode=require",
		"postgres://aegis:secret@postgres.internal/aegis?sslmode=prefer",
	} {
		poolConfig, err := pgxpool.ParseConfig(connectionString)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePostgresTransport(production, poolConfig); err == nil || !strings.Contains(err.Error(), "PostgreSQL") {
			t.Fatalf("validatePostgresTransport(%q) error = %v, want verified-TLS rejection", connectionString, err)
		}
	}

	verified, err := pgxpool.ParseConfig("postgres://aegis:secret@postgres.internal/aegis?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePostgresTransport(production, verified); err != nil {
		t.Fatalf("verify-full connection rejected: %v", err)
	}

	development := production
	development.MTLSEnabled = false
	disabled, err := pgxpool.ParseConfig("postgres://aegis:secret@127.0.0.1/aegis?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePostgresTransport(development, disabled); err != nil {
		t.Fatalf("local non-production connection rejected: %v", err)
	}
}

func TestMigrationAlwaysRequiresVerifiedPostgresTLS(t *testing.T) {
	t.Parallel()
	unsafe, err := pgxpool.ParseConfig("postgres://aegis:secret@postgres.internal/aegis?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePostgresTransport(config.Config{Role: "migrate"}, unsafe); err == nil {
		t.Fatal("migration accepted an unencrypted PostgreSQL connection")
	}
	verified, err := pgxpool.ParseConfig("postgres://aegis:secret@postgres.internal/aegis?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePostgresTransport(config.Config{Role: "migrate"}, verified); err != nil {
		t.Fatalf("migration rejected verify-full PostgreSQL: %v", err)
	}
}

func TestRuntimeInstanceIDPrefersConfiguredPodIdentity(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Role: "operator", InstanceID: "pod-uid-123"}
	if got := runtimeInstanceID(cfg); got != cfg.InstanceID {
		t.Fatalf("runtimeInstanceID() = %q, want %q", got, cfg.InstanceID)
	}
}
