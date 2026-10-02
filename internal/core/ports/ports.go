// Package ports defines the application-facing boundaries of AegisSRE.
// SDK and infrastructure types deliberately do not cross these interfaces.
package ports

import (
	"context"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

// ToolCaller invokes a typed MCP tool and decodes its structured result.
type ToolCaller interface {
	Discover(context.Context) ([]string, error)
	Call(context.Context, string, any, any) error
	Close() error
}

// PeerMessenger exchanges versioned messages with another agent over A2A.
type PeerMessenger interface {
	Send(context.Context, string, model.Envelope, any) error
}

// Reasoner converts bounded, pre-collected evidence into a diagnosis. It is
// advisory: proposals are still checked and signed by the Monitor policy.
type Reasoner interface {
	Diagnose(context.Context, model.InvestigationRequest, []model.EvidenceItem) (model.DiagnosisReport, error)
}

// Clock and IDGenerator make every application service deterministic in tests.
type Clock interface {
	Now() time.Time
}

type IDGenerator interface {
	NewID() string
}

// Auditor receives immutable decision records. Implementations must redact
// credentials and raw delegation private key material.
type Auditor interface {
	Record(context.Context, model.AuditEvent) error
}

// Notifier delivers an already-sanitized, sealed incident report. Recipient
// routing and credentials belong to the adapter and never come from agent or
// model-generated input.
type Notifier interface {
	Notify(context.Context, model.IncidentReport) (model.NotificationDelivery, error)
}

// GrantSigner is held only by Monitor.
type GrantSigner interface {
	Sign(*model.DelegationGrant) error
}

// ReportRequestSigner is held only by Monitor. It authorizes a sanitized
// terminal-report request but grants no action-plane capability.
type ReportRequestSigner interface {
	SignReportRequest(*model.IncidentReportRequest) error
}

// GrantAuthorizer is used independently by Operator and the action MCP server.
type GrantAuthorizer interface {
	Authorize(model.DelegationGrant, time.Time) model.PolicyDecision
}

// ProposalAuthorizer is used by Monitor while it still has the sealed
// diagnosis, before it delegates the selected proposal to Operator.
type ProposalAuthorizer interface {
	AuthorizeProposal(model.DiagnosisReport, model.DelegationGrant, time.Time) model.PolicyDecision
}

type GrantVerifier interface {
	Verify(model.DelegationGrant, time.Time) error
}

// ReportRequestVerifier is held by Operator and is intentionally narrower
// than delegation verification.
type ReportRequestVerifier interface {
	VerifyReportRequest(model.IncidentReportRequest, time.Time) error
}

type ReplayGuard interface {
	ConsumeGrant(model.DelegationGrant, time.Time) error
}

// ObserveBackend is the implementation boundary behind the read-only MCP
// server. It has no method capable of changing cluster state.
type ObserveBackend interface {
	QueryMetrics(context.Context, toolapi.QueryMetricsInput) (toolapi.QueryMetricsOutput, error)
	QueryLogSignals(context.Context, toolapi.QueryLogSignalsInput) (toolapi.QueryLogSignalsOutput, error)
	QueryTraceSignals(context.Context, toolapi.QueryTraceSignalsInput) (toolapi.QueryTraceSignalsOutput, error)
	SearchLogs(context.Context, toolapi.SearchLogsInput) (toolapi.SearchLogsOutput, error)
	GetWorkloadSnapshot(context.Context, toolapi.GetWorkloadSnapshotInput) (toolapi.GetWorkloadSnapshotOutput, error)
	GetPodLogs(context.Context, toolapi.GetPodLogsInput) (toolapi.GetPodLogsOutput, error)
}

// OperateBackend is exposed only through the action MCP server. Execution
// receives the complete signed grant, not independently supplied target args.
type OperateBackend interface {
	ExecuteRemediation(context.Context, toolapi.ExecuteRemediationInput) (toolapi.ExecuteRemediationOutput, error)
	GetRemediationStatus(context.Context, toolapi.GetRemediationStatusInput) (toolapi.GetRemediationStatusOutput, error)
}
