package security

import (
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

func TestSignAndVerifyIncidentReportRequest(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)
	publicKey, privateKey := signingKeys(t)
	request, err := SignReportRequest(privateKey, "monitor-report-key", testReportRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReportRequest(publicKey, "monitor-report-key", model.AgentOperator, request, now.Add(time.Second)); err != nil {
		t.Fatalf("valid incident report request rejected: %v", err)
	}

	for name, mutate := range map[string]func(*model.IncidentReportRequest){
		"request id":  func(value *model.IncidentReportRequest) { value.RequestID = "report-request-tampered" },
		"correlation": func(value *model.IncidentReportRequest) { value.CorrelationID = "correlation-tampered" },
		"target":      func(value *model.IncidentReportRequest) { value.Target.Name = "other-api" },
		"expiry":      func(value *model.IncidentReportRequest) { value.ExpiresAt = value.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			err := VerifyReportRequest(publicKey, "monitor-report-key", model.AgentOperator, changed, now.Add(time.Second))
			if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeInvalidSignature {
				t.Fatalf("tampered request error = %v, want %s", err, model.CodeInvalidSignature)
			}
		})
	}
}

func TestIncidentReportRequestRejectsSpoofingAndCrossDomainSignature(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 2, 0, 0, 0, time.UTC)
	publicKey, privateKey := signingKeys(t)
	request := testReportRequest(now)

	if err := VerifyReportRequest(publicKey, "monitor-key", model.AgentOperator, request, now); err == nil {
		t.Fatal("unsigned report request was accepted")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeDelegationRequired {
		t.Fatalf("unsigned request error = %v", err)
	}

	grant, err := SignGrant(privateKey, "monitor-key", testGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = model.ReportRequestSignature{
		Algorithm: grant.Signature.Algorithm,
		KeyID:     grant.Signature.KeyID,
		Value:     grant.Signature.Value,
	}
	if err := VerifyReportRequest(publicKey, "monitor-key", model.AgentOperator, request, now); err == nil {
		t.Fatal("delegation-grant signature was replayed as report authorization")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeInvalidSignature {
		t.Fatalf("cross-domain signature error = %v", err)
	}

	_, attackerPrivate := signingKeys(t)
	spoofed, err := SignReportRequest(attackerPrivate, "monitor-key", testReportRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReportRequest(publicKey, "monitor-key", model.AgentOperator, spoofed, now); err == nil {
		t.Fatal("attacker-signed report request was accepted")
	}
}

func TestIncidentReportRequestValidityIntervalAndAudience(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	publicKey, privateKey := signingKeys(t)
	request, err := SignReportRequest(privateKey, "monitor-key", testReportRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReportRequest(publicKey, "monitor-key", model.AgentOperator, request, now.Add(-time.Nanosecond)); err == nil {
		t.Fatal("report request was accepted before requested_at")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeGrantNotYetValid {
		t.Fatalf("not-yet-valid error = %v", err)
	}
	if err := VerifyReportRequest(publicKey, "monitor-key", model.AgentOperator, request, request.ExpiresAt); err == nil {
		t.Fatal("report request was accepted at exclusive expiry")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeGrantExpired {
		t.Fatalf("expiry error = %v", err)
	}
	if err := VerifyReportRequest(publicKey, "monitor-key", model.AgentMCPAction, request, now); err == nil {
		t.Fatal("report request was accepted for the action MCP audience")
	}
}

func TestCanonicalIncidentReportRequestNormalizesTimesWithoutMutation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	left := testReportRequest(now)
	right := testReportRequest(now)
	right.ReportCreatedAt = right.ReportCreatedAt.In(time.FixedZone("MYT", 8*60*60))
	right.RequestedAt = right.RequestedAt.In(time.FixedZone("MYT", 8*60*60))
	right.ExpiresAt = right.ExpiresAt.In(time.FixedZone("MYT", 8*60*60))
	originalLocation := right.RequestedAt.Location()
	originalReportLocation := right.ReportCreatedAt.Location()
	leftBytes, err := CanonicalReportRequestBytes(left)
	if err != nil {
		t.Fatal(err)
	}
	rightBytes, err := CanonicalReportRequestBytes(right)
	if err != nil {
		t.Fatal(err)
	}
	if string(leftBytes) != string(rightBytes) {
		t.Fatal("canonical report request changed across equivalent time zones")
	}
	if right.RequestedAt.Location() != originalLocation || right.ReportCreatedAt.Location() != originalReportLocation {
		t.Fatal("canonicalization mutated caller request")
	}
}

func testReportRequest(now time.Time) model.IncidentReportRequest {
	return model.IncidentReportRequest{
		SchemaVersion:     model.IncidentReportRequestSchemaVersionV2,
		RequestID:         "report-request-1",
		Issuer:            model.AgentMonitor,
		Audience:          model.AgentOperator,
		IncidentID:        "incident-1",
		CorrelationID:     "correlation-1",
		DiagnosisReportID: "diagnosis-1",
		Target: model.ResourceTarget{
			APIVersion: "apps/v1", Kind: "Deployment",
			Namespace: "outage-arena", Name: "demo-api",
		},
		FinalState:      model.IncidentResolved,
		Reason:          model.ReportReasonRecoveryVerified,
		ReportCreatedAt: now,
		RequestedAt:     now,
		ExpiresAt:       now.Add(2 * time.Minute),
	}
}
