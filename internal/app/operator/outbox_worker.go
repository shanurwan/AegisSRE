package operator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
)

const (
	defaultOutboxLease        = 30 * time.Second
	defaultOutboxBatchSize    = 1
	defaultOutboxMaxAttempts  = 5
	defaultOutboxPollInterval = time.Second
	defaultDeliveryTimeout    = 10 * time.Second
	defaultOutboxBaseBackoff  = time.Second
	defaultOutboxMaxBackoff   = 5 * time.Minute
	outboxLeaseSafetyMargin   = time.Second
	maxOutboxBatchSize        = 100
	maxOutboxAttempts         = 100
)

// OutboxWorker delivers reports previously committed with their notification
// intent. Provider delivery and the database acknowledgement cannot be one
// transaction, so delivery is deliberately at-least-once. Notifier adapters
// used here must disable their own retry loop; this worker owns bounded retry
// and durable scheduling.
type OutboxWorker struct {
	Store      ports.ReportOutboxStore
	Notifier   ports.Notifier
	Audit      ports.Auditor
	Clock      ports.Clock
	InstanceID string

	Lease        time.Duration
	BatchSize    int
	MaxAttempts  int
	PollInterval time.Duration
	// DeliveryTimeout bounds each provider attempt inside the database lease.
	// A batch is rejected unless every sequential attempt can finish before
	// the earliest lease expires.
	DeliveryTimeout time.Duration
	BaseBackoff     time.Duration
	MaxBackoff      time.Duration
}

type outboxSettings struct {
	lease           time.Duration
	batchSize       int
	maxAttempts     int
	pollInterval    time.Duration
	deliveryTimeout time.Duration
	baseBackoff     time.Duration
	maxBackoff      time.Duration
}

// Run processes due messages until cancellation. A store failure is returned
// to the process supervisor instead of being hidden in an in-memory retry
// loop. Provider failures are durably scheduled by RunOnce and are not Run
// failures.
func (w *OutboxWorker) Run(ctx context.Context) error {
	settings, err := w.settings()
	if err != nil {
		return err
	}
	for {
		claimed, err := w.runOnce(ctx, settings)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// Drain a full batch immediately. Wait only when the queue may be empty
		// so a backlog is not artificially rate-limited by the poll interval.
		if claimed == settings.batchSize {
			continue
		}
		timer := time.NewTimer(settings.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		case <-timer.C:
		}
	}
}

// RunOnce claims and processes one bounded batch. It is exposed so startup
// probes and deterministic integration tests can exercise the worker without
// timing a polling loop.
func (w *OutboxWorker) RunOnce(ctx context.Context) (int, error) {
	settings, err := w.settings()
	if err != nil {
		return 0, err
	}
	return w.runOnce(ctx, settings)
}

func (w *OutboxWorker) runOnce(ctx context.Context, settings outboxSettings) (int, error) {
	messages, err := w.Store.ClaimOutbox(ctx, w.InstanceID, settings.batchSize, settings.lease)
	if err != nil {
		return 0, fmt.Errorf("claim notification outbox: %w", err)
	}
	var processingErrors []error
	for _, message := range messages {
		if err := ctx.Err(); err != nil {
			processingErrors = append(processingErrors, err)
			break
		}
		if err := w.processMessage(ctx, settings, message); err != nil {
			processingErrors = append(processingErrors, err)
		}
	}
	return len(messages), errors.Join(processingErrors...)
}

func (w *OutboxWorker) processMessage(
	ctx context.Context,
	settings outboxSettings,
	message ports.OutboxMessage,
) error {
	if message.ID < 1 || message.Status != ports.OutboxSending || message.Attempts < 1 ||
		message.LeaseToken == "" || message.Channel != model.NotificationChannelWhatsApp {
		return model.NewError(model.CodeInvalidInput, "claimed notification outbox message is invalid")
	}
	if err := message.Report.VerifyDigest(); err != nil {
		return fmt.Errorf("validate claimed incident report: %w", err)
	}

	deliveryCtx, cancelDelivery := context.WithTimeout(ctx, settings.deliveryTimeout)
	delivery, deliveryErr := w.Notifier.Notify(deliveryCtx, message.Report)
	cancelDelivery()
	if ctx.Err() != nil {
		// Leave the sending lease intact on shutdown. A provider may have
		// accepted the request before observing cancellation; lease recovery
		// intentionally produces at-least-once delivery.
		return ctx.Err()
	}
	if deliveryErr == nil {
		if err := delivery.Validate(); err != nil || delivery.Channel != message.Channel {
			deliveryErr = model.NewError(model.CodeExecutionFailed, "notification provider returned an invalid delivery result")
		}
	}
	now := w.Clock.Now().UTC()
	if deliveryErr == nil {
		if err := w.Store.MarkOutboxDelivered(
			ctx, message.ID, message.LeaseToken, delivery.ProviderMessageID, now,
		); err != nil {
			// Provider acceptance happened first. Returning the error leaves the
			// lease to expire and may redeliver, which is the unavoidable
			// at-least-once failure window.
			return fmt.Errorf("record delivered notification outbox message %d: %w", message.ID, err)
		}
		w.auditAttempt(ctx, message, ports.OutboxDelivered, true, now)
		return nil
	}

	if message.Attempts >= settings.maxAttempts {
		if err := w.Store.DeadLetterOutbox(
			ctx, message.ID, message.LeaseToken, model.CodeExecutionFailed, now,
		); err != nil {
			return fmt.Errorf("dead-letter notification outbox message %d: %w", message.ID, err)
		}
		w.auditAttempt(ctx, message, ports.OutboxDeadLetter, false, now)
		return nil
	}

	availableAt := now.Add(outboxRetryDelay(message.Attempts, settings.baseBackoff, settings.maxBackoff))
	if err := w.Store.RetryOutbox(
		ctx, message.ID, message.LeaseToken, model.CodeExecutionFailed, availableAt,
	); err != nil {
		return fmt.Errorf("schedule notification outbox message %d retry: %w", message.ID, err)
	}
	w.auditAttempt(ctx, message, ports.OutboxRetryWait, false, now)
	return nil
}

func (w *OutboxWorker) auditAttempt(
	ctx context.Context,
	message ports.OutboxMessage,
	status ports.OutboxStatus,
	sideEffect bool,
	at time.Time,
) {
	if w.Audit == nil {
		return
	}
	_ = w.Audit.Record(ctx, model.AuditEvent{
		ID: durableAuditID(
			"notification-"+string(status),
			fmt.Sprintf("%d:%d", message.ID, message.Attempts),
		),
		IncidentID: message.Report.IncidentID,
		Actor:      model.AgentOperator,
		Operation:  "deliver_incident_report",
		Decision:   string(status),
		SideEffect: sideEffect,
		OccurredAt: at,
	})
}

func (w *OutboxWorker) settings() (outboxSettings, error) {
	if w == nil || w.Store == nil || w.Notifier == nil || w.Clock == nil {
		return outboxSettings{}, errors.New("operator outbox worker dependencies are incomplete")
	}
	if strings.TrimSpace(w.InstanceID) == "" || strings.TrimSpace(w.InstanceID) != w.InstanceID || len(w.InstanceID) > 512 {
		return outboxSettings{}, model.NewError(model.CodeInvalidInput, "operator outbox worker instance ID is invalid")
	}
	settings := outboxSettings{
		lease:           w.Lease,
		batchSize:       w.BatchSize,
		maxAttempts:     w.MaxAttempts,
		pollInterval:    w.PollInterval,
		deliveryTimeout: w.DeliveryTimeout,
		baseBackoff:     w.BaseBackoff,
		maxBackoff:      w.MaxBackoff,
	}
	if settings.lease == 0 {
		settings.lease = defaultOutboxLease
	}
	if settings.batchSize == 0 {
		settings.batchSize = defaultOutboxBatchSize
	}
	if settings.maxAttempts == 0 {
		settings.maxAttempts = defaultOutboxMaxAttempts
	}
	if settings.pollInterval == 0 {
		settings.pollInterval = defaultOutboxPollInterval
	}
	if settings.deliveryTimeout == 0 {
		settings.deliveryTimeout = defaultDeliveryTimeout
	}
	if settings.baseBackoff == 0 {
		settings.baseBackoff = defaultOutboxBaseBackoff
	}
	if settings.maxBackoff == 0 {
		settings.maxBackoff = defaultOutboxMaxBackoff
	}
	if settings.lease < time.Second || settings.lease > 5*time.Minute {
		return outboxSettings{}, model.NewError(model.CodeInvalidInput, "operator outbox lease must be between one second and five minutes")
	}
	if settings.batchSize < 1 || settings.batchSize > maxOutboxBatchSize {
		return outboxSettings{}, model.NewError(model.CodeInvalidInput, "operator outbox batch size must be between one and one hundred")
	}
	if settings.maxAttempts < 1 || settings.maxAttempts > maxOutboxAttempts {
		return outboxSettings{}, model.NewError(model.CodeInvalidInput, "operator outbox attempts must be between one and one hundred")
	}
	if settings.pollInterval < time.Millisecond || settings.pollInterval > 5*time.Minute {
		return outboxSettings{}, model.NewError(model.CodeInvalidInput, "operator outbox poll interval must be between one millisecond and five minutes")
	}
	if settings.deliveryTimeout < time.Second || settings.deliveryTimeout > 2*time.Minute {
		return outboxSettings{}, model.NewError(model.CodeInvalidInput, "operator outbox delivery timeout must be between one second and two minutes")
	}
	// ClaimOutbox gives every row in a batch the same lease start. Bound the
	// entire sequential batch, plus acknowledgement headroom, so another
	// worker cannot reclaim a row while this worker can still be delivering it.
	requiredLease := settings.deliveryTimeout*time.Duration(settings.batchSize) + outboxLeaseSafetyMargin
	if settings.lease <= requiredLease {
		return outboxSettings{}, model.NewError(model.CodeInvalidInput, "operator outbox lease must exceed the worst-case batch delivery window")
	}
	if settings.baseBackoff < time.Millisecond || settings.baseBackoff > 24*time.Hour ||
		settings.maxBackoff < settings.baseBackoff || settings.maxBackoff > 24*time.Hour {
		return outboxSettings{}, model.NewError(model.CodeInvalidInput, "operator outbox backoff bounds are invalid")
	}
	return settings, nil
}

func outboxRetryDelay(attempt int, base, maximum time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := base
	for step := 1; step < attempt && delay < maximum; step++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
