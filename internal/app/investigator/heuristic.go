package investigator

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

// HeuristicReasoner is the deterministic, keyless default. It deliberately
// prefers escalation over an action when evidence suggests a persistent fault.
type HeuristicReasoner struct {
	Clock ports.Clock
	IDs   ports.IDGenerator
}

func (h HeuristicReasoner) Diagnose(_ context.Context, request model.InvestigationRequest, evidence []model.EvidenceItem) (model.DiagnosisReport, error) {
	report := model.DiagnosisReport{
		SchemaVersion: model.SchemaVersionV1,
		ID:            "diag-" + h.IDs.NewID(), IncidentID: request.Incident.ID,
		Status: model.DiagnosisInconclusive, Confidence: 0.4,
		CreatedAt: h.Clock.Now(),
	}
	for _, item := range evidence {
		report.EvidenceIDs = append(report.EvidenceIDs, item.ID)
	}
	var snapshot toolapi.GetWorkloadSnapshotOutput
	found := false
	for _, item := range evidence {
		if item.Tool == toolapi.ToolGetWorkloadSnapshot {
			if err := json.Unmarshal(item.Payload, &snapshot); err == nil {
				found = true
			}
			break
		}
	}
	if !found {
		return report, nil
	}

	reasons := collectReasons(snapshot.Snapshot)
	support := append([]string(nil), report.EvidenceIDs...)
	switch {
	case reasons["ImagePullBackOff"] || reasons["ErrImagePull"]:
		report.Status, report.RootCause, report.Confidence = model.DiagnosisConfirmed, "deployment cannot pull its configured container image", 0.96
	case reasons["OOMKilled"]:
		report.Status, report.RootCause, report.Confidence = model.DiagnosisConfirmed, "container termination indicates memory exhaustion", 0.93
	case reasons["CrashLoopBackOff"]:
		report.Status, report.RootCause, report.Confidence = model.DiagnosisConfirmed, "application containers are repeatedly crashing", 0.9
	case reasons["FailedScheduling"] || reasons["Unschedulable"]:
		report.Status, report.RootCause, report.Confidence = model.DiagnosisConfirmed, "pods cannot be scheduled with current cluster constraints", 0.9
	case snapshot.Snapshot.UnavailableReplicas > 0 && len(snapshot.Snapshot.Pods) > 0:
		report.Status, report.RootCause, report.Confidence = model.DiagnosisConfirmed, "deployment rollout is stalled with non-ready replicas", 0.84
		report.Proposals = []model.ActionProposal{{
			ID:         "proposal-" + h.IDs.NewID(),
			Action:     model.ActionSpec{Kind: model.ActionRestartDeployment, Target: snapshot.Snapshot.Target},
			Rationale:  "restart the deployment rollout to replace transiently unhealthy replicas",
			Confidence: 0.84, EvidenceIDs: support,
			SuccessCriteria: []string{"observed generation catches up", "available replicas reach desired replicas"},
		}}
	default:
		report.RootCause = "available evidence does not identify a safe automated remediation"
	}
	report.Hypotheses = []model.Hypothesis{{
		Summary: report.RootCause, Confidence: report.Confidence, SupportingEvidenceIDs: support,
	}}
	return report, nil
}

func collectReasons(snapshot toolapi.WorkloadSnapshot) map[string]bool {
	result := make(map[string]bool)
	for _, pod := range snapshot.Pods {
		for _, container := range pod.Containers {
			for _, value := range []string{container.Reason, container.LastReason} {
				if value != "" {
					result[value] = true
				}
			}
		}
	}
	for _, event := range snapshot.Events {
		result[event.Reason] = true
		if strings.Contains(strings.ToLower(event.Message), "unschedulable") {
			result["Unschedulable"] = true
		}
	}
	return result
}
