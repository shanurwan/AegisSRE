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
	Tools    ports.ToolCaller
	Verifier ports.GrantVerifier
	Policy   ports.GrantAuthorizer
	Replay   ports.ReplayGuard
	Clock    ports.Clock
	IDs      ports.IDGenerator
	Audit    ports.Auditor

	mu       sync.Mutex
	receipts map[string]model.ActionReceipt
}

func (s *Service) Handle(ctx context.Context, envelope model.Envelope) (model.Envelope, error) {
	if s.Tools == nil || s.Verifier == nil || s.Policy == nil || s.Replay == nil || s.Clock == nil || s.IDs == nil {
		return model.Envelope{}, errors.New("operator dependencies are incomplete")
	}
	if err := envelope.Validate(); err != nil {
		return model.Envelope{}, err
	}
	if envelope.Sender != model.AgentMonitor || envelope.Recipient != model.AgentOperator || envelope.Kind != model.MessageRemediationRequest {
		return model.Envelope{}, model.NewError(model.CodeDelegationRequired, "Operator accepts only structured Monitor remediation grants")
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
	if receipt, ok := s.cachedReceipt(grant.GrantID); ok {
		return receipt, nil
	}
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
	s.storeReceipt(output.Receipt)
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
	s.storeReceipt(receipt)
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
	receipt, ok := s.receipts[grantID]
	return receipt, ok
}

func (s *Service) storeReceipt(receipt model.ActionReceipt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.receipts == nil {
		s.receipts = make(map[string]model.ActionReceipt)
	}
	s.receipts[receipt.GrantID] = receipt
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
