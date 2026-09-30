package investigator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type Service struct {
	Tools       ports.ToolCaller
	Reasoner    ports.Reasoner
	Clock       ports.Clock
	IDs         ports.IDGenerator
	Audit       ports.Auditor
	MaxLogBytes int
}

func (s *Service) Handle(ctx context.Context, envelope model.Envelope) (model.Envelope, error) {
	if s.Tools == nil || s.Reasoner == nil || s.Clock == nil || s.IDs == nil {
		return model.Envelope{}, errors.New("investigator dependencies are incomplete")
	}
	if err := envelope.Validate(); err != nil {
		return model.Envelope{}, err
	}
	if envelope.Sender != model.AgentMonitor || envelope.Recipient != model.AgentInvestigator || envelope.Kind != model.MessageInvestigationRequest {
		return model.Envelope{}, model.NewError(model.CodeOutOfScope, "Investigator accepts only Monitor investigation requests")
	}
	var request model.InvestigationRequest
	if err := envelope.DecodePayload(&request); err != nil {
		return model.Envelope{}, err
	}
	if err := request.Validate(); err != nil {
		return model.Envelope{}, err
	}
	if request.Incident.ID != envelope.IncidentID {
		return model.Envelope{}, model.NewError(model.CodeInvalidInput, "incident IDs differ between A2A envelope and request")
	}

	timeout := request.Budget.Timeout
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 30 * time.Second
	}
	workCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	report, err := s.Investigate(workCtx, request)
	if err != nil {
		return model.Envelope{}, err
	}
	response, err := model.NewEnvelope(
		s.IDs.NewID(), request.Incident.ID, envelope.CorrelationID, envelope.MessageID,
		model.AgentInvestigator, model.AgentMonitor, model.MessageDiagnosisReport,
		s.Clock.Now(), report,
	)
	if err != nil {
		return model.Envelope{}, err
	}
	return response, nil
}

func (s *Service) Investigate(ctx context.Context, request model.InvestigationRequest) (model.DiagnosisReport, error) {
	if err := request.Validate(); err != nil {
		return model.DiagnosisReport{}, err
	}
	if len(request.Scope.Targets) != 1 {
		return model.DiagnosisReport{}, model.NewError(model.CodeOutOfScope, "v1 investigations require exactly one workload target")
	}
	target := request.Scope.Targets[0]
	if !contains(request.Scope.Namespaces, target.Namespace) {
		return model.DiagnosisReport{}, model.NewError(model.CodeOutOfScope, "target is outside the investigation namespace scope")
	}
	callBudget := request.Budget.MaxToolCalls
	evidenceBudget := request.Budget.MaxEvidence
	calls := 0
	evidence := make([]model.EvidenceItem, 0, evidenceBudget)

	var snapshot toolapi.GetWorkloadSnapshotOutput
	if err := s.Tools.Call(ctx, toolapi.ToolGetWorkloadSnapshot, toolapi.GetWorkloadSnapshotInput{
		Namespace: target.Namespace, Kind: target.Kind, Name: target.Name,
	}, &snapshot); err != nil {
		return model.DiagnosisReport{}, fmt.Errorf("collect workload snapshot: %w", err)
	}
	calls++
	item, err := s.evidence(request.Incident.ID, model.EvidenceKubernetes, toolapi.ToolGetWorkloadSnapshot,
		"deployment, selected pods, and warning events", snapshot)
	if err != nil {
		return model.DiagnosisReport{}, err
	}
	evidence = append(evidence, item)

	for _, pod := range snapshot.Snapshot.Pods {
		if calls >= callBudget || len(evidence) >= evidenceBudget {
			break
		}
		if pod.Ready {
			continue
		}
		container := ""
		if len(pod.Containers) > 0 {
			container = pod.Containers[0].Name
		}
		var logs toolapi.GetPodLogsOutput
		err := s.Tools.Call(ctx, toolapi.ToolGetPodLogs, toolapi.GetPodLogsInput{
			Namespace: target.Namespace, Pod: pod.Name, Container: container,
			TailLines: 100, MaxBytes: s.maxLogBytes(),
		}, &logs)
		calls++
		if err != nil {
			continue
		}
		logEvidence, err := s.evidence(request.Incident.ID, model.EvidenceLogs, toolapi.ToolGetPodLogs,
			"bounded log tail from unhealthy pod "+pod.Name, logs)
		if err != nil {
			return model.DiagnosisReport{}, err
		}
		evidence = append(evidence, logEvidence)
	}

	report, err := s.Reasoner.Diagnose(ctx, request, evidence)
	if err != nil {
		return model.DiagnosisReport{}, fmt.Errorf("reason over evidence: %w", err)
	}
	report.SchemaVersion = model.SchemaVersionV1
	report.IncidentID = request.Incident.ID
	if report.ID == "" {
		report.ID = "diag-" + s.IDs.NewID()
	}
	if report.CreatedAt.IsZero() {
		report.CreatedAt = s.Clock.Now().UTC()
	}
	if err := report.Seal(); err != nil {
		return model.DiagnosisReport{}, err
	}
	if s.Audit != nil {
		_ = s.Audit.Record(ctx, model.AuditEvent{
			ID: s.IDs.NewID(), IncidentID: request.Incident.ID, Actor: model.AgentInvestigator,
			Operation: "diagnose", Decision: string(report.Status), SideEffect: false,
			OccurredAt: s.Clock.Now(),
		})
	}
	return report, nil
}

func (s *Service) maxLogBytes() int {
	if s.MaxLogBytes < 1024 || s.MaxLogBytes > 131072 {
		return 32768
	}
	return s.MaxLogBytes
}

func (s *Service) evidence(incidentID string, source model.EvidenceSource, tool, summary string, payload any) (model.EvidenceItem, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return model.EvidenceItem{}, fmt.Errorf("encode evidence: %w", err)
	}
	item := model.EvidenceItem{
		ID: "ev-" + s.IDs.NewID(), IncidentID: incidentID, Source: source,
		Tool: tool, Summary: summary, ObservedAt: s.Clock.Now().UTC(), Payload: raw,
	}
	if err := item.Seal(); err != nil {
		return model.EvidenceItem{}, err
	}
	return item, nil
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
