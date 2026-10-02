package ports

import (
	"context"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

// MonitorLease fences one Monitor replica's access to the namespace-wide
// detection and coordination checkpoint. FencingToken is monotonically
// increasing for a namespace; writers must present the complete lease so a
// delayed former leader cannot overwrite a newer leader's checkpoint.
type MonitorLease struct {
	Namespace    string
	Owner        string
	Token        string
	FencingToken int64
	LeaseUntil   time.Time
}

// MonitorCheckpoint is an opaque, versioned application checkpoint. Keeping
// the payload opaque prevents persistence concerns from leaking Monitor's
// internal workflow model into the core port.
type MonitorCheckpoint struct {
	Payload      []byte
	Version      int64
	FencingToken int64
	UpdatedAt    time.Time
}

// MonitorStateStore provides single-writer leadership and fenced checkpoint
// persistence for a monitored namespace. A healthy leader intentionally does
// not release its lease after each scan: it renews on the next scan, while a
// replacement can take over only after expiry. Save and Load must fail closed
// when the supplied lease is no longer current.
type MonitorStateStore interface {
	AcquireMonitorLease(context.Context, string, string, time.Duration) (MonitorLease, bool, error)
	RenewMonitorLease(context.Context, MonitorLease, time.Duration) (MonitorLease, error)
	LoadMonitorCheckpoint(context.Context, MonitorLease) (MonitorCheckpoint, bool, error)
	SaveMonitorCheckpoint(context.Context, MonitorLease, []byte) (MonitorCheckpoint, error)
}

// ExecutionScope identifies an independent authorization boundary that must
// consume a delegation exactly once. A delegation intentionally has both
// Operator and MCP-action audiences, so grant IDs must never be globally
// unique without this scope.
type ExecutionScope string

const (
	ExecutionScopeOperator  ExecutionScope = "operator"
	ExecutionScopeMCPAction ExecutionScope = "mcp_action"
)

func (s ExecutionScope) Valid() bool {
	return s == ExecutionScopeOperator || s == ExecutionScopeMCPAction
}

type ExecutionStatus string

const (
	ExecutionReserved  ExecutionStatus = "reserved"
	ExecutionCompleted ExecutionStatus = "completed"
	ExecutionUncertain ExecutionStatus = "uncertain"
)

func (s ExecutionStatus) Valid() bool {
	return s == ExecutionReserved || s == ExecutionCompleted || s == ExecutionUncertain
}

// ExecutionRecord is the durable representation of one consumer's handling
// of a signed delegation. LeaseToken is returned only to the current owner and
// must be presented when completing or abandoning the reservation.
type ExecutionRecord struct {
	Scope          ExecutionScope
	Grant          model.DelegationGrant
	Status         ExecutionStatus
	Owner          bool
	RecoveredLease bool
	LeaseToken     string
	LeaseOwner     string
	LeaseUntil     time.Time
	Receipt        *model.ActionReceipt
	ErrorCode      model.ErrorCode
	StartedAt      time.Time
	CompletedAt    *time.Time
	ReportedAt     *time.Time
	RetentionUntil time.Time
	Version        int64
}

// ActionExecutionStore combines replay protection, idempotency, and receipt
// retention in one atomic ledger. ReserveExecution returns a completed record
// for an exact duplicate, an unowned reserved record while another lease is
// live, or a new/recovered owned lease. Reusing a grant ID or idempotency key
// with different signed contents must fail closed. The application must
// cryptographically authenticate a grant and enforce freshness before its
// first reservation; an exact known fingerprint may be read after expiry only
// to recover an already accepted result, never to initiate a new side effect.
type ActionExecutionStore interface {
	ReserveExecution(context.Context, ExecutionScope, model.DelegationGrant, string, time.Duration) (ExecutionRecord, error)
	GetExecution(context.Context, ExecutionScope, model.DelegationGrant) (ExecutionRecord, bool, error)
	// GetExecutionByID is a trusted internal receipt lookup for report
	// assembly. It never grants authorization, acquires a lease, or permits a
	// caller to initiate execution.
	GetExecutionByID(context.Context, ExecutionScope, string) (ExecutionRecord, bool, error)
	CompleteExecution(context.Context, ExecutionScope, string, string, model.ActionReceipt) (ExecutionRecord, error)
	MarkExecutionUncertain(context.Context, ExecutionScope, string, string, model.ErrorCode) error
	PurgeExecutions(context.Context, time.Time, int) (int64, error)
}

type OutboxStatus string

const (
	OutboxPending    OutboxStatus = "pending"
	OutboxSending    OutboxStatus = "sending"
	OutboxRetryWait  OutboxStatus = "retry_wait"
	OutboxDelivered  OutboxStatus = "delivered"
	OutboxDeadLetter OutboxStatus = "dead_letter"
)

func (s OutboxStatus) Valid() bool {
	switch s {
	case OutboxPending, OutboxSending, OutboxRetryWait, OutboxDelivered, OutboxDeadLetter:
		return true
	default:
		return false
	}
}

// StoredReport is the immutable report accepted from a signed Monitor request.
// Created is true only for the transaction that inserted the report; exact
// retries return the existing record with Created false. HasNotificationIntent
// reports whether a separately leased delivery intent exists for this report.
type StoredReport struct {
	Request               model.IncidentReportRequest
	Report                model.IncidentReport
	Created               bool
	HasNotificationIntent bool
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// ReportNotificationIntent requests one durable delivery after the report is
// committed. A nil intent deliberately persists only the terminal report.
type ReportNotificationIntent struct {
	Channel     model.NotificationChannel
	AvailableAt time.Time
}

// OutboxMessage contains only a sealed, sanitized report. Provider routing and
// credentials remain adapter configuration and are never persisted here.
type OutboxMessage struct {
	ID                int64
	Report            model.IncidentReport
	Channel           model.NotificationChannel
	IdempotencyKey    string
	Status            OutboxStatus
	Attempts          int
	AvailableAt       time.Time
	LeaseOwner        string
	LeaseToken        string
	LeaseUntil        time.Time
	ProviderMessageID string
	LastErrorCode     model.ErrorCode
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeliveredAt       *time.Time
}

// ReportOutboxStore atomically persists a terminal report and, when requested,
// a single notification intent, then exposes leased delivery operations.
// Delivery is intentionally at-least-once: a provider acceptance and the
// database update cannot participate in one transaction. The application must
// verify the report-request signature and freshness before first acceptance.
type ReportOutboxStore interface {
	AcceptReport(context.Context, model.IncidentReportRequest, model.IncidentReport, *ReportNotificationIntent) (StoredReport, error)
	GetReport(context.Context, string) (StoredReport, bool, error)
	ClaimOutbox(context.Context, string, int, time.Duration) ([]OutboxMessage, error)
	MarkOutboxDelivered(context.Context, int64, string, string, time.Time) error
	RetryOutbox(context.Context, int64, string, model.ErrorCode, time.Time) error
	DeadLetterOutbox(context.Context, int64, string, model.ErrorCode, time.Time) error
	GetOutbox(context.Context, string) (OutboxMessage, bool, error)
	PurgeDeliveredOutbox(context.Context, time.Time, int) (int64, error)
}
