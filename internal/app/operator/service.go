package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	ExecutionStore ports.ActionExecutionStore
	ReportOutbox   ports.ReportOutboxStore
	InstanceID     string
	ExecutionLease time.Duration
	RequestTimeout time.Duration

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

const (
	maxOperatorCacheEntries        = 4096
	defaultExecutionRequestTimeout = 10 * time.Second
	durableExecutionRecoveryWindow = 10 * time.Second
)

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
	if s.Tools == nil || s.Verifier == nil || s.Policy == nil ||
		(s.ExecutionStore == nil && s.Replay == nil) {
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
	if s.ReportOutbox != nil {
		return s.reportDurable(ctx, request)
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

	result, reportErr := s.createMemoryReport(ctx, request)
	s.finishReport(record, result, reportErr)
	return cloneReportResult(result), reportErr
}

func (s *Service) reportDurable(ctx context.Context, request model.IncidentReportRequest) (model.IncidentReportResult, error) {
	stored, found, err := s.ReportOutbox.GetReport(ctx, request.RequestID)
	if err != nil {
		return model.IncidentReportResult{}, fmt.Errorf("load durable incident report: %w", err)
	}
	if found {
		if !sameReportRequest(stored.Request, request) {
			// A lost response may outlive the original signature window. Monitor
			// renews only the freshness envelope while retaining the stable logical
			// RequestID. A changed semantic request is never treated as recovery.
			if err := s.ReportVerifier.VerifyReportRequest(request, s.Clock.Now().UTC()); err != nil {
				return model.IncidentReportResult{}, err
			}
			if !sameReportRequestSemantics(stored.Request, request) ||
				!request.RequestedAt.After(stored.Request.RequestedAt) {
				return model.IncidentReportResult{}, model.NewError(
					model.CodeInvalidInput,
					"incident report request ID was reused with different semantic contents",
				)
			}
		}
		result := durableReportResult(stored)
		if err := result.Validate(); err != nil {
			return model.IncidentReportResult{}, fmt.Errorf("validate durable incident report result: %w", err)
		}
		return result, nil
	}

	// Freshness is mandatory only for first acceptance. An exact request that
	// was accepted while fresh is returned above after restart or expiry without
	// creating a second outbox item.
	if err := s.ReportVerifier.VerifyReportRequest(request, s.Clock.Now().UTC()); err != nil {
		return model.IncidentReportResult{}, err
	}
	report, err := s.buildReport(ctx, request, true)
	if err != nil {
		return model.IncidentReportResult{}, err
	}
	var intent *ports.ReportNotificationIntent
	if s.Notifier != nil {
		intent = &ports.ReportNotificationIntent{
			Channel: model.NotificationChannelWhatsApp, AvailableAt: s.Clock.Now().UTC(),
		}
	}
	stored, err = s.ReportOutbox.AcceptReport(ctx, request, report, intent)
	if err != nil {
		return model.IncidentReportResult{}, fmt.Errorf("persist incident report and optional notification outbox: %w", err)
	}
	result := durableReportResult(stored)
	if err := result.Validate(); err != nil {
		return model.IncidentReportResult{}, err
	}
	if s.Audit != nil {
		operation := "store_incident_report"
		if stored.HasNotificationIntent {
			operation = "queue_incident_report"
		}
		_ = s.Audit.Record(ctx, model.AuditEvent{
			ID: report.ReportID, IncidentID: report.IncidentID, Actor: model.AgentOperator,
			Operation: operation, Decision: string(result.Notification.Status),
			SideEffect: false, OccurredAt: s.Clock.Now(),
		})
	}
	return result, nil
}

func (s *Service) createMemoryReport(ctx context.Context, request model.IncidentReportRequest) (model.IncidentReportResult, error) {
	report, err := s.buildReport(ctx, request, false)
	if err != nil {
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

func (s *Service) buildReport(
	ctx context.Context,
	request model.IncidentReportRequest,
	durable bool,
) (model.IncidentReport, error) {
	var execution *model.IncidentReportExecution
	if request.ReceiptID != "" {
		var (
			receipt model.ActionReceipt
			ok      bool
		)
		if durable {
			if s.ExecutionStore == nil {
				return model.IncidentReport{}, errors.New("durable Operator execution store is required for an execution-backed report")
			}
			record, found, err := s.ExecutionStore.GetExecutionByID(ctx, ports.ExecutionScopeOperator, request.GrantID)
			if err != nil {
				return model.IncidentReport{}, fmt.Errorf("load durable Operator receipt: %w", err)
			}
			if found && record.Status == ports.ExecutionCompleted && record.Receipt != nil {
				receipt, ok = cloneActionReceipt(*record.Receipt), true
			}
		} else {
			receipt, ok = s.cachedReceipt(request.GrantID)
		}
		if !ok {
			return model.IncidentReport{}, model.NewError(model.CodeInvalidInput, "incident report references an unknown Operator receipt")
		}
		if receipt.ReceiptID != request.ReceiptID || receipt.IncidentID != request.IncidentID || !receipt.Action.Target.Equal(request.Target) {
			return model.IncidentReport{}, model.NewError(model.CodeInvalidInput, "incident report request does not match the Operator receipt")
		}
		if err := validateReceiptForReport(receipt, request); err != nil {
			return model.IncidentReport{}, err
		}
		execution = &model.IncidentReportExecution{
			GrantID: receipt.GrantID, ReceiptID: receipt.ReceiptID, Action: receipt.Action,
			Outcome: receipt.Outcome, DryRun: receipt.DryRun, CompletedAt: receipt.CompletedAt,
		}
	}
	reportID, err := request.DeterministicReportID()
	if err != nil {
		return model.IncidentReport{}, fmt.Errorf("derive deterministic incident report ID: %w", err)
	}
	report := model.IncidentReport{
		SchemaVersion: model.SchemaVersionV1,
		ReportID:      reportID, RequestID: request.RequestID,
		IncidentID: request.IncidentID, CorrelationID: request.CorrelationID,
		DiagnosisReportID: request.DiagnosisReportID, Target: request.Target,
		FinalState: request.FinalState, Reason: request.Reason, Summary: request.Reason.Summary(),
		Execution: execution, CreatedAt: request.ReportCreatedAt.UTC(),
	}
	if err := report.Seal(); err != nil {
		return model.IncidentReport{}, err
	}
	return report, nil
}

func sameReportRequest(left, right model.IncidentReportRequest) bool {
	leftDigest, leftErr := left.ComputeDigest()
	rightDigest, rightErr := right.ComputeDigest()
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest && left.Signature == right.Signature
}

func sameReportRequestSemantics(left, right model.IncidentReportRequest) bool {
	return left.SchemaVersion == right.SchemaVersion && left.RequestID == right.RequestID &&
		left.Issuer == right.Issuer && left.Audience == right.Audience &&
		left.IncidentID == right.IncidentID && left.CorrelationID == right.CorrelationID &&
		left.DiagnosisReportID == right.DiagnosisReportID && left.GrantID == right.GrantID &&
		left.ReceiptID == right.ReceiptID && left.Target.Equal(right.Target) &&
		left.FinalState == right.FinalState && left.Reason == right.Reason &&
		left.ReportCreatedAt.Equal(right.ReportCreatedAt)
}

func durableReportResult(stored ports.StoredReport) model.IncidentReportResult {
	attemptedAt := stored.CreatedAt.UTC()
	if attemptedAt.IsZero() {
		attemptedAt = stored.Request.RequestedAt.UTC()
	}
	result := model.IncidentReportResult{
		Report: stored.Report,
		Notification: model.NotificationReceipt{
			ReportID: stored.Report.ReportID, IdempotencyKey: stored.Request.RequestID,
			Channel: model.NotificationChannelWhatsApp, AttemptedAt: attemptedAt,
		},
	}
	if stored.HasNotificationIntent {
		result.Notification.Status = model.NotificationQueued
		return result
	}
	result.Notification.Status = model.NotificationFailed
	result.Notification.ErrorCode = model.CodeExecutionFailed
	result.Notification.ErrorMessage = "notification service is unavailable"
	return result
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
	if s.Clock == nil || s.Tools == nil || s.Verifier == nil || s.Policy == nil {
		return model.ActionReceipt{}, errors.New("operator execution dependencies are incomplete")
	}
	if s.ExecutionStore != nil {
		return s.executeDurable(ctx, grant)
	}
	return s.executeMemory(ctx, grant)
}

func (s *Service) executeMemory(ctx context.Context, grant model.DelegationGrant) (model.ActionReceipt, error) {
	if s.Replay == nil {
		return model.ActionReceipt{}, errors.New("operator replay guard is required without a durable execution store")
	}
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

func (s *Service) executeDurable(ctx context.Context, grant model.DelegationGrant) (model.ActionReceipt, error) {
	instanceID := s.InstanceID
	if instanceID == "" {
		return model.ActionReceipt{}, errors.New("operator instance ID is required with a durable execution store")
	}
	lease := s.executionLease()

	// Completed exact matches are result lookups, not new authorization. They
	// remain recoverable after grant expiry so a response lost during restart
	// cannot cause a second mutation.
	existing, found, err := s.ExecutionStore.GetExecution(ctx, ports.ExecutionScopeOperator, grant)
	if err != nil {
		return model.ActionReceipt{}, durableStorePendingError("load durable Operator execution", err)
	}
	if found {
		switch existing.Status {
		case ports.ExecutionCompleted:
			if existing.Receipt == nil {
				return model.ActionReceipt{}, model.NewError(model.CodeExecutionFailed, "completed durable execution omitted its receipt")
			}
			if err := validateActionReceipt(*existing.Receipt, grant); err != nil {
				return model.ActionReceipt{}, err
			}
			return cloneActionReceipt(*existing.Receipt), nil
		case ports.ExecutionUncertain:
			return model.ActionReceipt{}, model.NewError(model.CodeExecutionFailed, "previous delegated execution has an uncertain outcome")
		case ports.ExecutionReserved:
			if err := s.validateDurableExecutionWindow(lease); err != nil {
				return model.ActionReceipt{}, err
			}
			// Acquire only an expired lease, then reconcile the independently
			// durable action-MCP result before freshness or current policy can
			// reject a receipt that was already committed downstream.
			reservation, reserveErr := s.ExecutionStore.ReserveExecution(
				ctx, ports.ExecutionScopeOperator, grant, instanceID, lease,
			)
			if reserveErr != nil {
				return model.ActionReceipt{}, durableStorePendingError("recover durable Operator execution lease", reserveErr)
			}
			return s.handleDurableReservation(ctx, grant, reservation, true)
		default:
			return model.ActionReceipt{}, model.NewError(model.CodeExecutionFailed, "durable execution store returned an invalid state")
		}
	}

	// First acceptance must be inside the signed validity interval and current
	// policy. Recovery is handled above because an exact downstream receipt is
	// evidence of an already accepted action, not authority for a new action.
	if err := s.validateDurableExecutionWindow(lease); err != nil {
		return model.ActionReceipt{}, err
	}
	now := s.Clock.Now().UTC()
	if err := s.authorizeCurrentGrant(grant, now); err != nil {
		s.auditDenial(ctx, grant, err)
		return model.ActionReceipt{}, err
	}

	reservation, err := s.ExecutionStore.ReserveExecution(
		ctx, ports.ExecutionScopeOperator, grant, instanceID, lease,
	)
	if err != nil {
		if _, coded := model.ErrorCodeOf(err); coded {
			s.auditDenial(ctx, grant, err)
		}
		return model.ActionReceipt{}, durableStorePendingError("reserve durable Operator execution", err)
	}
	return s.handleDurableReservation(ctx, grant, reservation, reservation.RecoveredLease)
}

func (s *Service) handleDurableReservation(
	ctx context.Context,
	grant model.DelegationGrant,
	reservation ports.ExecutionRecord,
	recovering bool,
) (model.ActionReceipt, error) {
	switch reservation.Status {
	case ports.ExecutionCompleted:
		if reservation.Receipt == nil {
			return model.ActionReceipt{}, model.NewError(model.CodeExecutionFailed, "completed durable execution omitted its receipt")
		}
		if err := validateActionReceipt(*reservation.Receipt, grant); err != nil {
			return model.ActionReceipt{}, err
		}
		return cloneActionReceipt(*reservation.Receipt), nil
	case ports.ExecutionUncertain:
		return model.ActionReceipt{}, model.NewError(model.CodeExecutionFailed, "delegated execution has an uncertain outcome")
	case ports.ExecutionReserved:
		if !reservation.Owner || reservation.LeaseToken == "" {
			return model.ActionReceipt{}, model.NewError(model.CodeReplayedGrant, "delegated execution is already in progress")
		}
	default:
		return model.ActionReceipt{}, model.NewError(model.CodeExecutionFailed, "durable execution store returned an invalid state")
	}

	requestTimeout := s.executionRequestTimeout()
	fencedCtx := context.WithValue(
		ctx, durableExecutionDeadlineKey{}, time.Now().Add(requestTimeout+durableExecutionRecoveryWindow),
	)
	operationCtx, cancel := context.WithTimeout(fencedCtx, requestTimeout)
	defer cancel()
	if recovering {
		return s.recoverDurableReservation(operationCtx, grant, reservation)
	}
	return s.executeDurableReservation(operationCtx, grant, reservation, s.Clock.Now().UTC())
}

func (s *Service) recoverDurableReservation(
	ctx context.Context,
	grant model.DelegationGrant,
	reservation ports.ExecutionRecord,
) (model.ActionReceipt, error) {
	var result toolapi.GetRemediationResultOutput
	if err := s.Tools.Call(ctx, toolapi.ToolGetRemediationResult, toolapi.GetRemediationResultInput{Grant: grant}, &result); err != nil {
		// The lookup itself is read-only. Preserve the lease for another bounded
		// lookup attempt rather than guessing whether an action ran.
		return model.ActionReceipt{}, durableActionOutcomePendingError(
			fmt.Errorf("look up durable action MCP result: %w", err),
		)
	}
	if !result.State.Valid() || (result.State == toolapi.RemediationCompleted) != (result.Receipt != nil) {
		return model.ActionReceipt{}, s.markDurableUncertain(
			ctx, grant, reservation.LeaseToken,
			model.NewError(model.CodeExecutionFailed, "action MCP returned an invalid durable result"),
		)
	}

	switch result.State {
	case toolapi.RemediationCompleted:
		if err := validateActionReceipt(*result.Receipt, grant); err != nil {
			return model.ActionReceipt{}, s.markDurableUncertain(ctx, grant, reservation.LeaseToken, err)
		}
		return s.completeDurableReceipt(ctx, grant, reservation.LeaseToken, *result.Receipt)
	case toolapi.RemediationUncertain:
		return model.ActionReceipt{}, s.markDurableUncertain(
			ctx, grant, reservation.LeaseToken,
			model.NewError(model.CodeExecutionFailed, "action MCP execution has an uncertain outcome"),
		)
	case toolapi.RemediationReserved:
		// Re-enter the exact action endpoint so action MCP can atomically reject a
		// live lease or take over an expired lease and reconcile Kubernetes. Its
		// recovery path requires fresh authorization before any retry-safe
		// mutation, while an already-applied grant marker can be completed after
		// expiry. Any RPC/replay error below leaves this Operator lease retryable.
		return s.executeDurableReservation(ctx, grant, reservation, s.Clock.Now().UTC())
	case toolapi.RemediationNotFound:
		now := s.Clock.Now().UTC()
		if err := s.authorizeCurrentGrant(grant, now); err != nil {
			// A read-only miss is not proof that the previous action-MCP request
			// was never accepted. Its HTTP context may have been canceled while
			// Kubernetes still commits the request. Do not persist a terminal
			// no-mutation receipt that could race that late side effect.
			return model.ActionReceipt{}, s.markDurableUncertain(ctx, grant, reservation.LeaseToken, err)
		}
		return s.executeDurableReservation(ctx, grant, reservation, now)
	default:
		panic("validated remediation result state became unreachable")
	}
}

func (s *Service) authorizeCurrentGrant(grant model.DelegationGrant, now time.Time) error {
	if err := s.Verifier.Verify(grant, now); err != nil {
		return err
	}
	decision := s.Policy.Authorize(grant, now)
	if !decision.Allowed {
		return model.NewError(decision.Code, decision.Reason)
	}
	return nil
}

func (s *Service) executeDurableReservation(
	ctx context.Context,
	grant model.DelegationGrant,
	reservation ports.ExecutionRecord,
	now time.Time,
) (model.ActionReceipt, error) {

	if !grant.DryRun {
		if s.Audit == nil {
			// No action call has started, so the outcome is known rather than
			// uncertain. Keep the reservation until lease expiry and allow a
			// freshly authorized takeover to retry the audit intent.
			return model.ActionReceipt{}, durableActionOutcomePendingError(
				errors.New("durable audit sink is required before a live delegated action"),
			)
		}
		if err := s.Audit.Record(ctx, model.AuditEvent{
			ID: durableAuditID("operator-intent", grant.GrantID+":"+reservation.LeaseToken), IncidentID: grant.IncidentID,
			Actor: model.AgentOperator, Operation: string(grant.Action.Kind), Decision: "execution_reserved",
			SideEffect: false, OccurredAt: now,
		}); err != nil {
			return model.ActionReceipt{}, durableActionOutcomePendingError(
				fmt.Errorf("persist live action audit intent: %w", err),
			)
		}
	}

	var output toolapi.ExecuteRemediationOutput
	if err := s.Tools.Call(ctx, toolapi.ToolExecuteRemediation, toolapi.ExecuteRemediationInput{
		Grant: grant, DryRun: grant.DryRun,
	}, &output); err != nil {
		if actionToolErrorIsReportable(err) {
			return s.reconcileReportableToolError(ctx, grant, reservation, err)
		}
		// A transport/tool error is not durable evidence of the downstream
		// outcome. Retain the reservation so a later owner can query action MCP's
		// ledger and recover a completed, reserved, or uncertain truth.
		return model.ActionReceipt{}, durableActionOutcomePendingError(
			fmt.Errorf("execute constrained remediation tool: %w", err),
		)
	}
	if err := validateActionReceipt(output.Receipt, grant); err != nil {
		return model.ActionReceipt{}, s.markDurableUncertain(ctx, grant, reservation.LeaseToken, err)
	}
	return s.completeDurableReceipt(ctx, grant, reservation.LeaseToken, output.Receipt)
}

func (s *Service) reconcileReportableToolError(
	ctx context.Context,
	grant model.DelegationGrant,
	reservation ports.ExecutionRecord,
	toolErr error,
) (model.ActionReceipt, error) {
	var result toolapi.GetRemediationResultOutput
	if err := s.Tools.Call(
		ctx, toolapi.ToolGetRemediationResult, toolapi.GetRemediationResultInput{Grant: grant}, &result,
	); err != nil {
		return model.ActionReceipt{}, durableActionOutcomePendingError()
	}
	if !result.State.Valid() || (result.State == toolapi.RemediationCompleted) != (result.Receipt != nil) {
		return model.ActionReceipt{}, s.markDurableUncertain(
			ctx, grant, reservation.LeaseToken,
			model.NewError(model.CodeExecutionFailed, "action MCP returned an invalid durable result after a terminal error"),
		)
	}

	switch result.State {
	case toolapi.RemediationCompleted:
		if err := validateActionReceipt(*result.Receipt, grant); err != nil {
			return model.ActionReceipt{}, s.markDurableUncertain(ctx, grant, reservation.LeaseToken, err)
		}
		return s.completeDurableReceipt(ctx, grant, reservation.LeaseToken, *result.Receipt)
	case toolapi.RemediationUncertain:
		return model.ActionReceipt{}, s.markDurableUncertain(ctx, grant, reservation.LeaseToken, toolErr)
	case toolapi.RemediationReserved:
		return model.ActionReceipt{}, durableActionOutcomePendingError()
	case toolapi.RemediationNotFound:
		code, _ := model.ErrorCodeOf(toolErr)
		switch code {
		case model.CodePolicyDenied, model.CodeOutOfScope, model.CodeDelegationRequired:
			if reservation.RecoveredLease {
				// A prior owner may still have a request accepted late. A current
				// denial cannot prove that no side effect occurred.
				return model.ActionReceipt{}, s.markDurableUncertain(ctx, grant, reservation.LeaseToken, toolErr)
			}
			return s.completeDurableRejection(ctx, grant, reservation, s.Clock.Now().UTC(), toolErr)
		default:
			return model.ActionReceipt{}, durableActionOutcomePendingError()
		}
	default:
		panic("validated remediation result state became unreachable")
	}
}

func actionToolErrorIsReportable(err error) bool {
	code, ok := model.ErrorCodeOf(err)
	if !ok {
		return false
	}
	switch code {
	case model.CodePolicyDenied, model.CodeOutOfScope, model.CodeDelegationRequired, model.CodeExecutionFailed:
		return true
	default:
		return false
	}
}

func durableActionOutcomePendingError(causes ...error) error {
	// An uncoded error would be normalized by the A2A transport to
	// EXECUTION_FAILED and could make Monitor report prematurely. This explicit
	// code remains retryable until the Operator ledger reaches a terminal state.
	const message = "durable action outcome reconciliation is pending"
	if len(causes) != 0 && causes[0] != nil {
		return model.WrapError(model.CodeExecutionPending, message, causes[0])
	}
	return model.NewError(model.CodeExecutionPending, message)
}

func durableStorePendingError(operation string, err error) error {
	if _, coded := model.ErrorCodeOf(err); coded {
		return err
	}
	return durableActionOutcomePendingError(fmt.Errorf("%s: %w", operation, err))
}

func (s *Service) completeDurableReceipt(
	ctx context.Context,
	grant model.DelegationGrant,
	leaseToken string,
	receipt model.ActionReceipt,
) (model.ActionReceipt, error) {
	writeCtx, cancel := durableExecutionContext(ctx)
	defer cancel()
	persisted, err := s.ExecutionStore.CompleteExecution(
		writeCtx, ports.ExecutionScopeOperator, grant.GrantID, leaseToken, receipt,
	)
	if err != nil {
		// The transaction may have committed even when its acknowledgement was
		// lost. Never overwrite recoverable downstream truth with "uncertain";
		// the next owner re-reads both durable ledgers.
		return model.ActionReceipt{}, durableActionOutcomePendingError(
			fmt.Errorf("persist durable Operator receipt: %w", err),
		)
	}
	if persisted.Status != ports.ExecutionCompleted || persisted.Receipt == nil {
		return model.ActionReceipt{}, model.NewError(model.CodeExecutionFailed, "durable execution completion omitted its receipt")
	}
	if err := validateActionReceipt(*persisted.Receipt, grant); err != nil {
		return model.ActionReceipt{}, err
	}
	if s.Audit != nil {
		_ = s.Audit.Record(ctx, model.AuditEvent{
			ID: durableAuditID("operator-result", grant.GrantID), IncidentID: grant.IncidentID,
			Actor: model.AgentOperator, Operation: string(grant.Action.Kind),
			Decision:   string(persisted.Receipt.Outcome),
			SideEffect: persisted.Receipt.Outcome == model.ActionSucceeded,
			OccurredAt: persisted.Receipt.CompletedAt,
		})
	}
	return cloneActionReceipt(*persisted.Receipt), nil
}

func (s *Service) completeDurableRejection(
	ctx context.Context,
	grant model.DelegationGrant,
	reservation ports.ExecutionRecord,
	now time.Time,
	cause error,
) (model.ActionReceipt, error) {
	code, ok := model.ErrorCodeOf(cause)
	if !ok {
		code = model.CodeExecutionFailed
	}
	startedAt := reservation.StartedAt.UTC()
	if startedAt.IsZero() || now.Before(startedAt) {
		startedAt = now
	}
	receipt := model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1,
		ReceiptID:     durableAuditID("operator-rejected-receipt", grant.GrantID),
		GrantID:       grant.GrantID,
		IncidentID:    grant.IncidentID,
		Action:        grant.Action,
		Outcome:       model.ActionRejected,
		StartedAt:     startedAt,
		CompletedAt:   now,
		ErrorCode:     code,
		ErrorMessage:  "action MCP rejected the delegated action before accepting execution",
		AuditRef:      durableAuditID("operator-rejected", grant.GrantID),
	}
	if err := validateActionReceipt(receipt, grant); err != nil {
		return model.ActionReceipt{}, fmt.Errorf("build durable Operator rejection: %w", err)
	}
	if s.Audit == nil {
		return model.ActionReceipt{}, durableActionOutcomePendingError()
	}
	writeCtx, cancel := durableExecutionContext(ctx)
	defer cancel()
	if err := s.Audit.Record(writeCtx, model.AuditEvent{
		ID: receipt.AuditRef, IncidentID: grant.IncidentID, Actor: model.AgentOperator,
		Operation: string(grant.Action.Kind), Decision: string(model.ActionRejected),
		SideEffect: false, OccurredAt: now,
	}); err != nil {
		return model.ActionReceipt{}, model.WrapError(
			model.CodeExecutionPending,
			"durable rejection audit persistence is pending",
			err,
		)
	}
	persisted, err := s.completeDurableReceipt(ctx, grant, reservation.LeaseToken, receipt)
	if err != nil {
		return model.ActionReceipt{}, err
	}
	return persisted, nil
}

func (s *Service) markDurableUncertain(
	ctx context.Context,
	grant model.DelegationGrant,
	leaseToken string,
	cause error,
) error {
	result := model.WrapError(
		model.CodeExecutionFailed,
		"delegated execution outcome is uncertain and requires reconciliation",
		cause,
	)
	writeCtx, cancel := durableExecutionContext(ctx)
	defer cancel()
	markErr := s.ExecutionStore.MarkExecutionUncertain(
		writeCtx, ports.ExecutionScopeOperator, grant.GrantID, leaseToken, model.CodeExecutionFailed,
	)
	if markErr != nil {
		return errors.Join(result, fmt.Errorf("persist uncertain Operator execution: %w", markErr))
	}
	return result
}

func (s *Service) executionLease() time.Duration {
	if s.ExecutionLease < time.Second || s.ExecutionLease > 5*time.Minute {
		return 30 * time.Second
	}
	return s.ExecutionLease
}

func (s *Service) executionRequestTimeout() time.Duration {
	if s.RequestTimeout <= 0 || s.RequestTimeout > 2*time.Minute {
		return defaultExecutionRequestTimeout
	}
	return s.RequestTimeout
}

func (s *Service) validateDurableExecutionWindow(lease time.Duration) error {
	if lease <= s.executionRequestTimeout()+durableExecutionRecoveryWindow {
		return model.NewError(
			model.CodeInvalidInput,
			"Operator execution lease must outlive its request and durable recovery windows",
		)
	}
	return nil
}

type durableExecutionDeadlineKey struct{}

func durableExecutionContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Value(durableExecutionDeadlineKey{}).(time.Time); ok {
		return context.WithDeadline(base, deadline)
	}
	return context.WithTimeout(base, durableExecutionRecoveryWindow)
}

func durableAuditID(domain, value string) string {
	digest := sha256.Sum256([]byte(domain + "\x00" + value))
	return "audit-" + domain + "-" + hex.EncodeToString(digest[:])
}

func validateActionReceipt(receipt model.ActionReceipt, grant model.DelegationGrant) error {
	if err := receipt.Validate(); err != nil {
		return fmt.Errorf("validate action MCP receipt: %w", err)
	}
	if receipt.GrantID != grant.GrantID || receipt.IncidentID != grant.IncidentID || !receipt.Action.Equal(grant.Action) {
		return model.NewError(model.CodeExecutionFailed, "action MCP receipt does not match the delegated grant")
	}
	if receipt.Outcome != model.ActionRejected && (receipt.DryRun != grant.DryRun ||
		(grant.DryRun && receipt.Outcome != model.ActionDryRun) ||
		(!grant.DryRun && receipt.Outcome == model.ActionDryRun)) {
		return model.NewError(model.CodeExecutionFailed, "action MCP receipt dry-run semantics do not match the delegated grant")
	}
	return nil
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
