package operator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type Service struct {
	Tools          ports.ToolCaller
	Verifier       ports.GrantVerifier
	ReportVerifier ports.ReportRequestVerifier
	Policy         ports.GrantAuthorizer
	Replay         ports.ReplayGuard
	Clock          ports.Clock
	IDs            ports.IDGenerator
	Audit          ports.Auditor
	Notifier       ports.Notifier

	mu       sync.Mutex
	receipts map[string]*receiptRecord
	reports  map[string]*reportRecord
}

type receiptRecord struct {
	grantFingerprint string
	done             chan struct{}
	receipt          model.ActionReceipt
	err              error
	reported         bool
}

type reportRecord struct {
	requestDigest string
	done          chan struct{}
	result        model.IncidentReportResult
	err           error
}

const maxOperatorCacheEntries = 4096

func (s *Service) Handle(ctx context.Context, envelope model.Envelope) (model.Envelope, error) {
	if s.Clock == nil || s.IDs == nil {
		return model.Envelope{}, errors.New("operator dependencies are incomplete")
	}
	if err := envelope.Validate(); err != nil {
		return model.Envelope{}, err
	}
	if envelope.Sender != model.AgentMonitor || envelope.Recipient != model.AgentOperator {
		return model.Envelope{}, model.NewError(model.CodeDelegationRequired, "Operator accepts only trusted Monitor workflow requests")
	}
	switch envelope.Kind {
	case model.MessageRemediationRequest:
		return s.handleRemediation(ctx, envelope)
	case model.MessageIncidentReportRequest:
		return s.handleIncidentReport(ctx, envelope)
	default:
		return model.Envelope{}, model.NewError(model.CodeOutOfScope, "Operator does not accept this workflow message kind")
	}
}

func (s *Service) handleRemediation(ctx context.Context, envelope model.Envelope) (model.Envelope, error) {
	if s.Tools == nil || s.Verifier == nil || s.Policy == nil || s.Replay == nil {
		return model.Envelope{}, errors.New("operator remediation dependencies are incomplete")
	}
	var grant model.DelegationGrant
	if err := envelope.DecodePayload(&grant); err != nil {
		return model.Envelope{}, err
	}
	if grant.IncidentID != envelope.IncidentID {
		return model.Envelope{}, model.NewError(model.CodeInvalidInput, "incident IDs differ between A2A envelope and grant")
	}
	receipt, err := s.Execute(ctx, grant)
	if err != nil {
		return model.Envelope{}, err
	}
	return model.NewEnvelope(
		s.IDs.NewID(), grant.IncidentID, envelope.CorrelationID, envelope.MessageID,
		model.AgentOperator, model.AgentMonitor, model.MessageActionReceipt,
		s.Clock.Now(), receipt,
	)
}

func (s *Service) handleIncidentReport(ctx context.Context, envelope model.Envelope) (model.Envelope, error) {
	var request model.IncidentReportRequest
	if err := envelope.DecodePayload(&request); err != nil {
		return model.Envelope{}, err
	}
	if err := request.Validate(); err != nil {
		return model.Envelope{}, err
	}
	if request.IncidentID != envelope.IncidentID || request.CorrelationID != envelope.CorrelationID {
		return model.Envelope{}, model.NewError(model.CodeInvalidInput, "incident report request does not match its A2A incident and correlation chain")
	}
	result, err := s.Report(ctx, request)
	if err != nil {
		return model.Envelope{}, err
	}
	return model.NewEnvelope(
		s.IDs.NewID(), request.IncidentID, envelope.CorrelationID, envelope.MessageID,
		model.AgentOperator, model.AgentMonitor, model.MessageIncidentReport,
		s.Clock.Now(), result,
	)
}

// Report creates and delivers a sanitized terminal incident report. It is
// deliberately separate from Execute: a report request can never reach the
// action MCP plane or grant Kubernetes authority.
func (s *Service) Report(ctx context.Context, request model.IncidentReportRequest) (model.IncidentReportResult, error) {
	if s.Clock == nil || s.ReportVerifier == nil {
		return model.IncidentReportResult{}, errors.New("operator report dependencies are incomplete")
	}
	if err := s.ReportVerifier.VerifyReportRequest(request, s.Clock.Now().UTC()); err != nil {
		return model.IncidentReportResult{}, err
	}
	requestDigest, err := request.ComputeDigest()
	if err != nil {
		return model.IncidentReportResult{}, err
	}
	record, owner, err := s.beginReport(request.RequestID, requestDigest)
	if err != nil {
		return model.IncidentReportResult{}, err
	}
	if !owner {
		select {
		case <-ctx.Done():
			return model.IncidentReportResult{}, ctx.Err()
		case <-record.done:
			return cloneReportResult(record.result), record.err
		}
	}

	result, reportErr := s.createReport(ctx, request)
	s.finishReport(record, result, reportErr)
	return cloneReportResult(result), reportErr
}

func (s *Service) createReport(ctx context.Context, request model.IncidentReportRequest) (model.IncidentReportResult, error) {
	var execution *model.IncidentReportExecution
	if request.GrantID != "" {
		receipt, ok := s.cachedReceipt(request.GrantID)
		if !ok {
			return model.IncidentReportResult{}, model.NewError(model.CodeInvalidInput, "incident report references an unknown Operator receipt")
		}
		if receipt.ReceiptID != request.ReceiptID || receipt.IncidentID != request.IncidentID || !receipt.Action.Target.Equal(request.Target) {
			return model.IncidentReportResult{}, model.NewError(model.CodeInvalidInput, "incident report request does not match the cached action receipt")
		}
		if err := validateReceiptForReport(receipt, request); err != nil {
			return model.IncidentReportResult{}, err
		}
		execution = &model.IncidentReportExecution{
			GrantID: receipt.GrantID, ReceiptID: receipt.ReceiptID, Action: receipt.Action,
			Outcome: receipt.Outcome, DryRun: receipt.DryRun, CompletedAt: receipt.CompletedAt,
		}
	}
	reportID, err := request.DeterministicReportID()
	if err != nil {
		return model.IncidentReportResult{}, fmt.Errorf("derive deterministic incident report ID: %w", err)
	}
	report := model.IncidentReport{
		SchemaVersion: model.SchemaVersionV1,
		ReportID:      reportID, RequestID: request.RequestID,
		IncidentID: request.IncidentID, CorrelationID: request.CorrelationID,
		DiagnosisReportID: request.DiagnosisReportID, Target: request.Target,
		FinalState: request.FinalState, Reason: request.Reason, Summary: request.Reason.Summary(),
		Execution: execution, CreatedAt: request.RequestedAt.UTC(),
	}
	if err := report.Seal(); err != nil {
		return model.IncidentReportResult{}, err
	}
	notification := s.notify(ctx, report)
	result := model.IncidentReportResult{Report: report, Notification: notification}
	if err := result.Validate(); err != nil {
		return model.IncidentReportResult{}, err
	}
	if s.Audit != nil {
		_ = s.Audit.Record(ctx, model.AuditEvent{
			ID: report.ReportID, IncidentID: report.IncidentID, Actor: model.AgentOperator,
			Operation: "deliver_incident_report", Decision: string(notification.Status),
			SideEffect: notification.Status == model.NotificationDelivered, OccurredAt: s.Clock.Now(),
		})
	}
	return result, nil
}

func validateReceiptForReport(receipt model.ActionReceipt, request model.IncidentReportRequest) error {
	switch request.Reason {
	case model.ReportReasonRecoveryVerified, model.ReportReasonVerificationTimedOut:
		if receipt.Outcome != model.ActionSucceeded || receipt.DryRun {
			return model.NewError(model.CodeInvalidInput, "verification report requires a successful live action receipt")
		}
	case model.ReportReasonDryRunCompleted:
		if receipt.Outcome != model.ActionDryRun || !receipt.DryRun {
			return model.NewError(model.CodeInvalidInput, "dry-run report requires a dry-run action receipt")
		}
	case model.ReportReasonActionRejected:
		if receipt.Outcome != model.ActionRejected {
			return model.NewError(model.CodeInvalidInput, "action rejection report requires a rejected action receipt")
		}
	case model.ReportReasonActionFailed:
		if receipt.Outcome != model.ActionFailed && receipt.Outcome != model.ActionRolledBack {
			return model.NewError(model.CodeInvalidInput, "action failure report requires a failed or rolled-back receipt")
		}
	case model.ReportReasonAuthorityExceeded:
		if receipt.Outcome != model.ActionEscalated {
			return model.NewError(model.CodeInvalidInput, "authority report requires an escalated action receipt")
		}
	case model.ReportReasonDiagnosisInconclusive, model.ReportReasonPolicyDenied, model.ReportReasonActionOutcomeUnverified:
		return model.NewError(model.CodeInvalidInput, "report reason cannot reference an action receipt")
	}
	return nil
}

func (s *Service) notify(ctx context.Context, report model.IncidentReport) model.NotificationReceipt {
	receipt := model.NotificationReceipt{
		ReportID: report.ReportID, IdempotencyKey: report.RequestID,
		Channel: model.NotificationChannelWhatsApp, AttemptedAt: s.Clock.Now().UTC(),
	}
	if s.Notifier == nil {
		receipt.Status = model.NotificationFailed
		receipt.ErrorCode = model.CodeExecutionFailed
		receipt.ErrorMessage = "notification service is unavailable"
		return receipt
	}
	delivery, err := s.Notifier.Notify(ctx, report)
	if err != nil {
		receipt.Status = model.NotificationFailed
		receipt.ErrorCode = model.CodeExecutionFailed
		receipt.ErrorMessage = "notification delivery failed"
		return receipt
	}
	if err := delivery.Validate(); err != nil || delivery.Channel != model.NotificationChannelWhatsApp {
		receipt.Status = model.NotificationFailed
		receipt.ErrorCode = model.CodeExecutionFailed
		receipt.ErrorMessage = "notification service returned an invalid delivery result"
		return receipt
	}
	receipt.Status = model.NotificationDelivered
	receipt.Channel = delivery.Channel
	receipt.ProviderMessageID = delivery.ProviderMessageID
	return receipt
}

func (s *Service) beginReport(requestID, digest string) (*reportRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reports == nil {
		s.reports = make(map[string]*reportRecord)
	}
	if record, ok := s.reports[requestID]; ok {
		if record.requestDigest != digest {
			return nil, false, model.NewError(model.CodeInvalidInput, "incident report request ID was reused with different contents")
		}
		return record, false, nil
	}
	if len(s.reports) >= maxOperatorCacheEntries && !evictOldestCompletedReport(s.reports) {
		return nil, false, model.NewError(model.CodeToolBudgetExceeded, "Operator report cache is at its bounded in-flight limit")
	}
	record := &reportRecord{requestDigest: digest, done: make(chan struct{})}
	s.reports[requestID] = record
	return record, true, nil
}

func (s *Service) finishReport(record *reportRecord, result model.IncidentReportResult, err error) {
	s.mu.Lock()
	if err == nil && result.Report.Execution != nil {
		grantID := result.Report.Execution.GrantID
		if cached, ok := s.receipts[grantID]; ok && cached.err == nil &&
			cached.receipt.ReceiptID == result.Report.Execution.ReceiptID {
			select {
			case <-cached.done:
				cached.reported = true
			default:
			}
		}
	}
	record.result = cloneReportResult(result)
	record.err = err
	close(record.done)
	s.mu.Unlock()
}

func cloneReportResult(result model.IncidentReportResult) model.IncidentReportResult {
	if result.Report.Execution != nil {
		execution := *result.Report.Execution
		if execution.Action.Parameters.Replicas != nil {
			replicas := *execution.Action.Parameters.Replicas
			execution.Action.Parameters.Replicas = &replicas
		}
		result.Report.Execution = &execution
	}
	return result
}

func evictOldestCompletedReport(records map[string]*reportRecord) bool {
	oldestID := ""
	var oldest time.Time
	for requestID, record := range records {
		select {
		case <-record.done:
			completedAt := record.result.Notification.AttemptedAt
			if oldestID == "" || completedAt.Before(oldest) {
				oldestID, oldest = requestID, completedAt
			}
		default:
		}
	}
	if oldestID == "" {
		return false
	}
	delete(records, oldestID)
	return true
}

func (s *Service) Execute(ctx context.Context, grant model.DelegationGrant) (model.ActionReceipt, error) {
	now := s.Clock.Now().UTC()
	if err := s.Verifier.Verify(grant, now); err != nil {
		s.auditDenial(ctx, grant, err)
		return model.ActionReceipt{}, err
	}
	decision := s.Policy.Authorize(grant, now)
	if !decision.Allowed {
		err := model.NewError(decision.Code, decision.Reason)
		s.auditDenial(ctx, grant, err)
		return model.ActionReceipt{}, err
	}
	record, owner, err := s.beginReceipt(grant)
	if err != nil {
		s.auditDenial(ctx, grant, err)
		return model.ActionReceipt{}, err
	}
	if !owner {
		select {
		case <-ctx.Done():
			return model.ActionReceipt{}, ctx.Err()
		case <-record.done:
			if record.err != nil {
				return model.ActionReceipt{}, record.err
			}
			return cloneActionReceipt(record.receipt), nil
		}
	}

	receipt, executeErr := s.executeReserved(ctx, grant, now)
	s.finishReceipt(grant.GrantID, record, receipt, executeErr)
	return cloneActionReceipt(receipt), executeErr
}

func (s *Service) executeReserved(ctx context.Context, grant model.DelegationGrant, now time.Time) (model.ActionReceipt, error) {
	if err := s.Replay.ConsumeGrant(grant, now); err != nil {
		if code, ok := model.ErrorCodeOf(err); ok && code == model.CodeReplayedGrant {
			return s.recoverReplay(ctx, grant, now, err)
		}
		s.auditDenial(ctx, grant, err)
		return model.ActionReceipt{}, err
	}

	var output toolapi.ExecuteRemediationOutput
	if err := s.Tools.Call(ctx, toolapi.ToolExecuteRemediation, toolapi.ExecuteRemediationInput{
		Grant: grant, DryRun: grant.DryRun,
	}, &output); err != nil {
		s.auditDenial(ctx, grant, err)
		return model.ActionReceipt{}, fmt.Errorf("execute constrained remediation tool: %w", err)
	}
	if err := output.Receipt.Validate(); err != nil {
		return model.ActionReceipt{}, fmt.Errorf("validate action MCP receipt: %w", err)
	}
	if output.Receipt.GrantID != grant.GrantID || output.Receipt.IncidentID != grant.IncidentID || !output.Receipt.Action.Equal(grant.Action) {
		return model.ActionReceipt{}, model.NewError(model.CodeExecutionFailed, "action MCP receipt does not match the delegated grant")
	}
	if output.Receipt.DryRun != grant.DryRun ||
		(grant.DryRun && output.Receipt.Outcome != model.ActionDryRun) ||
		(!grant.DryRun && output.Receipt.Outcome == model.ActionDryRun) {
		return model.ActionReceipt{}, model.NewError(model.CodeExecutionFailed, "action MCP receipt dry-run semantics do not match the delegated grant")
	}
	if s.Audit != nil {
		_ = s.Audit.Record(ctx, model.AuditEvent{
			ID: s.IDs.NewID(), IncidentID: grant.IncidentID, Actor: model.AgentOperator,
			Operation: string(grant.Action.Kind), Decision: string(output.Receipt.Outcome),
			SideEffect: output.Receipt.Outcome == model.ActionSucceeded,
			OccurredAt: s.Clock.Now(),
		})
	}
	return output.Receipt, nil
}

func (s *Service) recoverReplay(ctx context.Context, grant model.DelegationGrant, now time.Time, replayErr error) (model.ActionReceipt, error) {
	if grant.DryRun {
		s.auditDenial(ctx, grant, replayErr)
		return model.ActionReceipt{}, replayErr
	}
	var status toolapi.GetRemediationStatusOutput
	if err := s.Tools.Call(ctx, toolapi.ToolGetRemediationStatus, toolapi.GetRemediationStatusInput{Grant: grant}, &status); err != nil {
		s.auditDenial(ctx, grant, err)
		return model.ActionReceipt{}, fmt.Errorf("check replayed remediation status: %w", err)
	}
	if !status.Snapshot.Target.Equal(grant.Action.Target) {
		err := model.NewError(model.CodeExecutionFailed, "remediation status target does not match the delegated grant")
		s.auditDenial(ctx, grant, err)
		return model.ActionReceipt{}, err
	}
	if !status.Satisfied {
		s.auditDenial(ctx, grant, replayErr)
		return model.ActionReceipt{}, replayErr
	}
	after := model.ResourceSnapshot{
		ResourceVersion:   status.Snapshot.ResourceVersion,
		DesiredReplicas:   status.Snapshot.DesiredReplicas,
		ReadyReplicas:     status.Snapshot.ReadyReplicas,
		AvailableReplicas: status.Snapshot.AvailableReplicas,
	}
	receipt := s.recoveredReceipt(grant, model.ActionSucceeded, &after, now)
	if err := receipt.Validate(); err != nil {
		return model.ActionReceipt{}, err
	}
	if s.Audit != nil {
		_ = s.Audit.Record(ctx, model.AuditEvent{
			ID: receipt.AuditRef, IncidentID: grant.IncidentID, Actor: model.AgentOperator,
			Operation: "recover_replayed_" + string(grant.Action.Kind), Decision: string(receipt.Outcome),
			SideEffect: false, OccurredAt: s.Clock.Now(),
		})
	}
	return receipt, nil
}

func (s *Service) recoveredReceipt(grant model.DelegationGrant, outcome model.ActionOutcome, after *model.ResourceSnapshot, now time.Time) model.ActionReceipt {
	return model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1, ReceiptID: "receipt-" + s.IDs.NewID(),
		GrantID: grant.GrantID, IncidentID: grant.IncidentID, Action: grant.Action,
		Outcome: outcome, DryRun: grant.DryRun, StartedAt: now, CompletedAt: s.Clock.Now().UTC(),
		After: after, AuditRef: "audit-" + s.IDs.NewID(),
	}
}

func (s *Service) cachedReceipt(grantID string) (model.ActionReceipt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.receipts[grantID]
	if !ok || record.err != nil {
		return model.ActionReceipt{}, false
	}
	select {
	case <-record.done:
		return cloneActionReceipt(record.receipt), true
	default:
		return model.ActionReceipt{}, false
	}
}

func (s *Service) beginReceipt(grant model.DelegationGrant) (*receiptRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.receipts == nil {
		s.receipts = make(map[string]*receiptRecord)
	}
	fingerprint := grant.Signature.Algorithm + "\x00" + grant.Signature.KeyID + "\x00" + grant.Signature.Value
	if record, exists := s.receipts[grant.GrantID]; exists {
		if record.grantFingerprint != fingerprint {
			return nil, false, model.NewError(model.CodeInvalidInput, "grant ID was reused with different signed contents")
		}
		return record, false, nil
	}
	if len(s.receipts) >= maxOperatorCacheEntries && !evictOldestReportedReceipt(s.receipts) {
		return nil, false, model.NewError(model.CodeToolBudgetExceeded, "Operator receipt cache is at its bounded unreported or in-flight limit")
	}
	record := &receiptRecord{grantFingerprint: fingerprint, done: make(chan struct{})}
	s.receipts[grant.GrantID] = record
	return record, true, nil
}

func (s *Service) finishReceipt(grantID string, record *receiptRecord, receipt model.ActionReceipt, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if current, ok := s.receipts[grantID]; ok && current == record {
			delete(s.receipts, grantID)
		}
		record.err = err
		close(record.done)
		return
	}
	record.receipt = cloneActionReceipt(receipt)
	close(record.done)
}

func evictOldestReportedReceipt(records map[string]*receiptRecord) bool {
	oldestGrantID := ""
	var oldest time.Time
	for grantID, record := range records {
		if record == nil || !record.reported || record.err != nil {
			continue
		}
		select {
		case <-record.done:
		default:
			continue
		}
		completedAt := record.receipt.CompletedAt
		if oldestGrantID == "" || completedAt.Before(oldest) || completedAt.Equal(oldest) && grantID < oldestGrantID {
			oldestGrantID, oldest = grantID, completedAt
		}
	}
	if oldestGrantID == "" {
		return false
	}
	delete(records, oldestGrantID)
	return true
}

func cloneActionReceipt(receipt model.ActionReceipt) model.ActionReceipt {
	if receipt.Action.Parameters.Replicas != nil {
		replicas := *receipt.Action.Parameters.Replicas
		receipt.Action.Parameters.Replicas = &replicas
	}
	if receipt.Before != nil {
		before := *receipt.Before
		receipt.Before = &before
	}
	if receipt.After != nil {
		after := *receipt.After
		receipt.After = &after
	}
	return receipt
}

func (s *Service) auditDenial(ctx context.Context, grant model.DelegationGrant, err error) {
	if s.Audit == nil || s.IDs == nil || s.Clock == nil {
		return
	}
	code, _ := model.ErrorCodeOf(err)
	_ = s.Audit.Record(ctx, model.AuditEvent{
		ID: s.IDs.NewID(), IncidentID: grant.IncidentID, Actor: model.AgentOperator,
		Operation: string(grant.Action.Kind), Decision: string(code), Reason: err.Error(),
		SideEffect: false, OccurredAt: s.Clock.Now(),
	})
}
