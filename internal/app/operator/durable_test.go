package operator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

func TestDurableExecuteReturnsCompletedReceiptAfterGrantExpiry(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, issuedAt, true)
	receipt := durableReceipt(grant, issuedAt.Add(time.Second))
	store := &durableExecutionStoreFake{found: true, record: ports.ExecutionRecord{
		Scope: ports.ExecutionScopeOperator, Grant: grant, Status: ports.ExecutionCompleted,
		Receipt: &receipt,
	}}
	tools := &durableOperatorToolFake{now: issuedAt.Add(3 * time.Minute)}
	service := newDurableOperatorService(
		t, issuedAt.Add(3*time.Minute), privateKey.Public().(ed25519.PublicKey), tools, store, true,
	)
	// Exact completed-result recovery is read-only and remains available even
	// if a restarted process has an unsafe execution-window configuration.
	service.ExecutionLease = 20 * time.Second
	service.RequestTimeout = 10 * time.Second

	got, err := service.Execute(context.Background(), grant)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !reflect.DeepEqual(got, receipt) {
		t.Fatalf("Execute() receipt = %#v, want %#v", got, receipt)
	}
	if tools.calls != 0 || store.reserveCalls != 0 {
		t.Fatalf("completed replay crossed execution boundary: tools=%d reserves=%d", tools.calls, store.reserveCalls)
	}
}

func TestDurableExecuteRejectsUnsafeLeaseWindowBeforeReservation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 2, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{89}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, now, true)
	store := &durableExecutionStoreFake{}
	tools := &durableOperatorToolFake{now: now.Add(time.Second)}
	service := newDurableOperatorService(
		t, now.Add(time.Second), privateKey.Public().(ed25519.PublicKey), tools, store, true,
	)
	service.ExecutionLease = 20 * time.Second
	service.RequestTimeout = 10 * time.Second

	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("Execute() unsafe lease error = nil")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeInvalidInput {
		t.Fatalf("Execute() unsafe lease error = %v, want %s", err, model.CodeInvalidInput)
	}
	if store.reserveCalls != 0 || tools.calls != 0 || tools.lookupCalls != 0 {
		t.Fatalf("unsafe lease crossed execution boundary: reserves=%d executions=%d lookups=%d", store.reserveCalls, tools.calls, tools.lookupCalls)
	}
}

func TestDurableExecutionStoreOutagesStayPendingAndCodedDecisionsStayExact(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 3, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{98}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, now, true)
	rawGetErr := errors.New("execution database read unavailable")
	rawReserveErr := errors.New("execution reservation commit acknowledgement unavailable")
	codedFenceErr := model.NewError(model.CodeExecutionFailed, "terminal report fenced execution")

	tests := []struct {
		name      string
		store     *durableExecutionStoreFake
		wantCode  model.ErrorCode
		wantCause error
	}{
		{name: "get outage", store: &durableExecutionStoreFake{getErr: rawGetErr}, wantCode: model.CodeExecutionPending, wantCause: rawGetErr},
		{name: "fresh reserve outage", store: &durableExecutionStoreFake{reserveErr: rawReserveErr}, wantCode: model.CodeExecutionPending, wantCause: rawReserveErr},
		{name: "recovered reserve outage", store: &durableExecutionStoreFake{
			found: true, reserveErr: rawReserveErr,
			record: ports.ExecutionRecord{Scope: ports.ExecutionScopeOperator, Grant: grant, Status: ports.ExecutionReserved},
		}, wantCode: model.CodeExecutionPending, wantCause: rawReserveErr},
		{name: "coded fence decision", store: &durableExecutionStoreFake{reserveErr: codedFenceErr}, wantCode: model.CodeExecutionFailed, wantCause: codedFenceErr},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newDurableOperatorService(
				t, now.Add(time.Second), privateKey.Public().(ed25519.PublicKey),
				&durableOperatorToolFake{now: now.Add(time.Second)}, test.store, true,
			)
			_, err := service.Execute(context.Background(), grant)
			if code, ok := model.ErrorCodeOf(err); !ok || code != test.wantCode {
				t.Fatalf("Execute() error = %v, want %s", err, test.wantCode)
			}
			if !errors.Is(err, test.wantCause) {
				t.Fatalf("Execute() error lost underlying cause: %v", err)
			}
		})
	}
}

func TestDurableExecuteRecoversActionMCPCommitAfterOperatorCrashAndGrantExpiry(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, 10, 2, 1, 5, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, issuedAt, false)
	downstreamReceipt := durableReceipt(grant, issuedAt.Add(10*time.Second))
	store := &durableExecutionStoreFake{found: true, record: ports.ExecutionRecord{
		Scope: ports.ExecutionScopeOperator, Grant: grant, Status: ports.ExecutionReserved,
		LeaseOwner: "crashed-operator", LeaseToken: "expired-lease",
		LeaseUntil: issuedAt.Add(20 * time.Second), StartedAt: issuedAt.Add(time.Second), Version: 1,
	}}
	tools := &durableOperatorToolFake{
		now: issuedAt.Add(4 * time.Minute), lookupState: toolapi.RemediationCompleted,
		lookupReceipt: &downstreamReceipt,
	}
	service := newDurableOperatorService(
		t, issuedAt.Add(4*time.Minute), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{}

	got, err := service.Execute(context.Background(), grant)
	if err != nil {
		t.Fatalf("Execute() recovery error = %v", err)
	}
	if !reflect.DeepEqual(got, downstreamReceipt) {
		t.Fatalf("Execute() receipt = %#v, want exact downstream receipt %#v", got, downstreamReceipt)
	}
	if tools.lookupCalls != 1 || tools.calls != 0 {
		t.Fatalf("recovery calls: lookups=%d executions=%d, want 1 and 0", tools.lookupCalls, tools.calls)
	}
	if store.record.Status != ports.ExecutionCompleted || store.completeCalls != 1 || store.markCalls != 0 {
		t.Fatalf("recovered Operator ledger = %#v", store.record)
	}
}

func TestDurableExecuteRecoveryNotFoundAuthorizationFailureMarksUncertain(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, 10, 2, 1, 10, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{82}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, issuedAt, false)
	store := &durableExecutionStoreFake{found: true, record: ports.ExecutionRecord{
		Scope: ports.ExecutionScopeOperator, Grant: grant, Status: ports.ExecutionReserved,
		LeaseOwner: "crashed-operator", LeaseToken: "expired-lease",
		LeaseUntil: issuedAt.Add(20 * time.Second), StartedAt: issuedAt.Add(time.Second), Version: 1,
	}}
	tools := &durableOperatorToolFake{now: issuedAt.Add(4 * time.Minute), lookupState: toolapi.RemediationNotFound}
	service := newDurableOperatorService(
		t, issuedAt.Add(4*time.Minute), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{}

	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("Execute() error = nil, want expired recovery ambiguity")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
		t.Fatalf("Execute() error = %v, want uncertain %s classification", err, model.CodeExecutionFailed)
	}
	if tools.lookupCalls != 1 || tools.calls != 0 {
		t.Fatalf("denied recovery calls: lookups=%d executions=%d, want 1 and 0", tools.lookupCalls, tools.calls)
	}
	if store.record.Status != ports.ExecutionUncertain || store.completeCalls != 0 || store.markCalls != 1 {
		t.Fatalf("denied recovery did not preserve late-acceptance ambiguity: %#v", store.record)
	}

	// The durable uncertain state is terminal for automation and replayed
	// without consulting or mutating action MCP again.
	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("Execute() uncertain replay error = nil")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
		t.Fatalf("Execute() uncertain replay error = %v, want %s", err, model.CodeExecutionFailed)
	}
	if tools.lookupCalls != 1 || tools.calls != 0 || store.reserveCalls != 1 {
		t.Fatalf("uncertain replay crossed a side-effect boundary: lookups=%d executions=%d reserves=%d", tools.lookupCalls, tools.calls, store.reserveCalls)
	}
}

func TestDurableExecuteRecoveryNotFoundPolicyDenialMarksUncertain(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, 10, 2, 1, 11, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{84}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, issuedAt, false)
	store := &durableExecutionStoreFake{found: true, record: ports.ExecutionRecord{
		Scope: ports.ExecutionScopeOperator, Grant: grant, Status: ports.ExecutionReserved,
		LeaseOwner: "crashed-operator", LeaseToken: "expired-lease",
		LeaseUntil: issuedAt.Add(20 * time.Second), StartedAt: issuedAt.Add(time.Second), Version: 1,
	}}
	tools := &durableOperatorToolFake{now: issuedAt.Add(time.Minute), lookupState: toolapi.RemediationNotFound}
	service := newDurableOperatorService(
		t, issuedAt.Add(time.Minute), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	deniedPolicy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1, MaximumGrantTTL: 5 * time.Minute,
		RequireDryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	service.Policy = deniedPolicy
	service.Audit = &durableAuditFake{}

	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("Execute() policy-denied recovery error = nil")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
		t.Fatalf("Execute() error = %v, want uncertain %s classification", err, model.CodeExecutionFailed)
	}
	if tools.lookupCalls != 1 || tools.calls != 0 || store.record.Status != ports.ExecutionUncertain || store.markCalls != 1 || store.completeCalls != 0 {
		t.Fatalf("policy-denied recovery did not become uncertain: lookups=%d executions=%d record=%#v", tools.lookupCalls, tools.calls, store.record)
	}
}

func TestDurableExecuteRecoveryLookupOutageStaysPending(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, 10, 2, 1, 11, 30, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{97}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, issuedAt, false)
	store := &durableExecutionStoreFake{found: true, record: ports.ExecutionRecord{
		Scope: ports.ExecutionScopeOperator, Grant: grant, Status: ports.ExecutionReserved,
		LeaseOwner: "crashed-operator", LeaseToken: "expired-lease",
		LeaseUntil: issuedAt.Add(20 * time.Second), StartedAt: issuedAt.Add(time.Second), Version: 1,
	}}
	lookupFailure := errors.New("action MCP lookup transport unavailable")
	tools := &durableOperatorToolFake{now: issuedAt.Add(time.Minute), lookupErr: lookupFailure}
	service := newDurableOperatorService(
		t, issuedAt.Add(time.Minute), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{}

	_, err := service.Execute(context.Background(), grant)
	if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionPending {
		t.Fatalf("Execute() recovery lookup error = %v, want %s", err, model.CodeExecutionPending)
	}
	if !errors.Is(err, lookupFailure) {
		t.Fatalf("Execute() recovery lookup error lost underlying cause: %v", err)
	}
	if tools.lookupCalls != 1 || tools.calls != 0 || store.record.Status != ports.ExecutionReserved ||
		store.markCalls != 0 || store.completeCalls != 0 {
		t.Fatalf("lookup outage did not retain recoverable reservation: lookups=%d tools=%d record=%#v", tools.lookupCalls, tools.calls, store.record)
	}
}

func TestMarkDurableUncertainPreservesPersistenceFailureUnderExecutionClassification(t *testing.T) {
	t.Parallel()
	persistErr := errors.New("database acknowledgement unavailable")
	cause := model.NewError(model.CodePolicyDenied, "sensitive current-policy detail")
	store := &durableExecutionStoreFake{markErr: persistErr}
	service := &Service{ExecutionStore: store}

	err := service.markDurableUncertain(
		context.Background(), model.DelegationGrant{GrantID: "grant-uncertain-persist"}, "lease-token", cause,
	)
	if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
		t.Fatalf("markDurableUncertain() error = %v, want %s", err, model.CodeExecutionFailed)
	}
	if !errors.Is(err, cause) || !errors.Is(err, persistErr) {
		t.Fatalf("markDurableUncertain() did not retain both causes: %v", err)
	}
}

func TestDurableExecuteRecoveryHandlesLiveReservedAndUncertainDownstream(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, 10, 2, 1, 12, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{83}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, issuedAt, false)
	for _, state := range []toolapi.RemediationExecutionState{toolapi.RemediationReserved, toolapi.RemediationUncertain} {
		state := state
		t.Run(string(state), func(t *testing.T) {
			store := &durableExecutionStoreFake{found: true, record: ports.ExecutionRecord{
				Scope: ports.ExecutionScopeOperator, Grant: grant, Status: ports.ExecutionReserved,
				LeaseOwner: "crashed-operator", LeaseToken: "expired-lease",
				LeaseUntil: issuedAt.Add(20 * time.Second), StartedAt: issuedAt.Add(time.Second), Version: 1,
			}}
			tools := &durableOperatorToolFake{now: issuedAt.Add(time.Minute), lookupState: state}
			if state == toolapi.RemediationReserved {
				tools.err = model.NewError(model.CodeReplayedGrant, "downstream execution lease is live")
			}
			service := newDurableOperatorService(
				t, issuedAt.Add(time.Minute), privateKey.Public().(ed25519.PublicKey), tools, store, false,
			)
			service.Audit = &durableAuditFake{}

			if _, err := service.Execute(context.Background(), grant); err == nil {
				t.Fatal("Execute() error = nil, want non-execution result")
			}
			wantExecuteCalls := 0
			if state == toolapi.RemediationReserved {
				wantExecuteCalls = 1
			}
			if tools.lookupCalls != 1 || tools.calls != wantExecuteCalls {
				t.Fatalf("recovery state %q calls: lookups=%d executions=%d, want executions=%d", state, tools.lookupCalls, tools.calls, wantExecuteCalls)
			}
			wantStatus := ports.ExecutionReserved
			if state == toolapi.RemediationUncertain {
				wantStatus = ports.ExecutionUncertain
			}
			if store.record.Status != wantStatus {
				t.Fatalf("recovery state %q Operator status = %q, want %q", state, store.record.Status, wantStatus)
			}
		})
	}
}

func TestDurableExecuteRecoveryConvergesExpiredDownstreamReservation(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, 10, 2, 1, 13, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{85}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, issuedAt, false)
	store := &durableExecutionStoreFake{found: true, record: ports.ExecutionRecord{
		Scope: ports.ExecutionScopeOperator, Grant: grant, Status: ports.ExecutionReserved,
		LeaseOwner: "crashed-operator", LeaseToken: "expired-lease",
		LeaseUntil: issuedAt.Add(20 * time.Second), StartedAt: issuedAt.Add(time.Second), Version: 1,
	}}
	tools := &durableOperatorToolFake{now: issuedAt.Add(4 * time.Minute), lookupState: toolapi.RemediationReserved}
	service := newDurableOperatorService(
		t, issuedAt.Add(4*time.Minute), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{}

	receipt, err := service.Execute(context.Background(), grant)
	if err != nil {
		t.Fatalf("Execute() expired downstream reservation recovery error = %v", err)
	}
	if receipt.Outcome != model.ActionSucceeded || tools.lookupCalls != 1 || tools.calls != 1 {
		t.Fatalf("expired downstream reservation did not converge: receipt=%#v lookups=%d executions=%d", receipt, tools.lookupCalls, tools.calls)
	}
	if store.record.Status != ports.ExecutionCompleted || store.completeCalls != 1 || store.markCalls != 0 {
		t.Fatalf("expired downstream convergence Operator record = %#v", store.record)
	}
}

func TestDurableExecuteVerifiesBeforeReservationAndPersistsBeforeResponse(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 15, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, now, true)
	order := make([]string, 0, 4)
	store := &durableExecutionStoreFake{order: &order}
	tools := &durableOperatorToolFake{now: now.Add(time.Second), order: &order}
	service := newDurableOperatorService(
		t, now.Add(time.Second), privateKey.Public().(ed25519.PublicKey), tools, store, true,
	)

	receipt, err := service.Execute(context.Background(), grant)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if receipt.ReceiptID != "durable-receipt-1" {
		t.Fatalf("Execute() receipt = %#v", receipt)
	}
	if want := []string{"get", "reserve", "tool", "complete"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("durable execution order = %v, want %v", order, want)
	}

	unsigned := operatorGrant(now)
	badStore := &durableExecutionStoreFake{}
	badTools := &durableOperatorToolFake{now: now}
	badService := newDurableOperatorService(
		t, now, privateKey.Public().(ed25519.PublicKey), badTools, badStore, true,
	)
	if _, err := badService.Execute(context.Background(), unsigned); err == nil {
		t.Fatal("Execute() accepted an unsigned first execution")
	}
	if badStore.reserveCalls != 0 || badTools.calls != 0 {
		t.Fatalf("unsigned execution reserved or called tools: reserves=%d tools=%d", badStore.reserveCalls, badTools.calls)
	}
}

func TestDurableExecuteRequiresAuditIntentBeforeLiveToolCall(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 30, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, now, false)
	store := &durableExecutionStoreFake{}
	tools := &durableOperatorToolFake{now: now.Add(time.Second)}
	service := newDurableOperatorService(
		t, now.Add(time.Second), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{err: errors.New("database unavailable")}

	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("Execute() error = nil, want audit failure")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionPending {
		t.Fatalf("Execute() audit error = %v, want %s", err, model.CodeExecutionPending)
	}
	if tools.calls != 0 {
		t.Fatalf("live tool calls = %d, want 0", tools.calls)
	}
	if store.markCalls != 0 {
		t.Fatalf("known pre-call failure was marked uncertain %d times", store.markCalls)
	}
	if store.record.Status != ports.ExecutionReserved {
		t.Fatalf("audit failure state = %q, want lease reservation for safe retry", store.record.Status)
	}
}

func TestDurableExecuteLeavesAmbiguousToolFailureRecoverable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 45, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{74}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, now, false)
	store := &durableExecutionStoreFake{}
	tools := &durableOperatorToolFake{now: now.Add(time.Second), err: errors.New("connection reset after write")}
	service := newDurableOperatorService(
		t, now.Add(time.Second), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{}

	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("Execute() error = nil, want ambiguous tool failure")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionPending {
		t.Fatalf("Execute() ambiguous tool error = %v, want %s", err, model.CodeExecutionPending)
	}
	if tools.calls != 1 || store.markCalls != 0 || store.record.Status != ports.ExecutionReserved {
		t.Fatalf("ambiguous failure handling: tools=%d marks=%d state=%q", tools.calls, store.markCalls, store.record.Status)
	}
	if store.completeCalls != 0 {
		t.Fatalf("ambiguous tool failure completed %d receipts", store.completeCalls)
	}
}

func TestDurableExecuteStructuredFailureReconcilesDownstreamUncertainty(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 46, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{94}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, now, false)
	store := &durableExecutionStoreFake{}
	tools := &durableOperatorToolFake{
		now:         now.Add(time.Second),
		err:         model.NewError(model.CodeExecutionFailed, "action result is durably uncertain"),
		lookupState: toolapi.RemediationUncertain,
	}
	service := newDurableOperatorService(
		t, now.Add(time.Second), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{}

	_, err := service.Execute(context.Background(), grant)
	if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
		t.Fatalf("Execute() error = %v, want terminal %s", err, model.CodeExecutionFailed)
	}
	if tools.calls != 1 || tools.lookupCalls != 1 || store.markCalls != 1 ||
		store.record.Status != ports.ExecutionUncertain {
		t.Fatalf("structured uncertainty did not terminalize Operator ledger: tools=%d lookups=%d marks=%d record=%#v", tools.calls, tools.lookupCalls, store.markCalls, store.record)
	}
}

func TestDurableExecuteStructuredFailureLookupOutageStaysWireRetryable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 46, 30, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{95}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, now, false)
	store := &durableExecutionStoreFake{}
	tools := &durableOperatorToolFake{
		now:       now.Add(time.Second),
		err:       model.NewError(model.CodeExecutionFailed, "action result requires reconciliation"),
		lookupErr: errors.New("action MCP result lookup unavailable"),
	}
	service := newDurableOperatorService(
		t, now.Add(time.Second), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{}

	_, err := service.Execute(context.Background(), grant)
	if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionPending {
		t.Fatalf("Execute() error = %v, want retryable %s", err, model.CodeExecutionPending)
	}
	if tools.calls != 1 || tools.lookupCalls != 1 || store.markCalls != 0 ||
		store.completeCalls != 0 || store.record.Status != ports.ExecutionReserved {
		t.Fatalf("lookup outage discarded recoverable reservation: tools=%d lookups=%d record=%#v", tools.calls, tools.lookupCalls, store.record)
	}
}

func TestDurableDryRunPolicyRejectionHasDurableAuditAndReceipt(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 46, 45, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{96}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, now, true)
	store := &durableExecutionStoreFake{}
	tools := &durableOperatorToolFake{
		now: now.Add(time.Second), err: model.NewError(model.CodePolicyDenied, "action MCP policy denied"),
		lookupState: toolapi.RemediationNotFound,
	}
	audit := &durableAuditFake{}
	service := newDurableOperatorService(
		t, now.Add(time.Second), privateKey.Public().(ed25519.PublicKey), tools, store, true,
	)
	service.Audit = audit

	receipt, err := service.Execute(context.Background(), grant)
	if err != nil {
		t.Fatalf("Execute() rejection error = %v", err)
	}
	if receipt.Outcome != model.ActionRejected || receipt.DryRun || receipt.AuditRef == "" ||
		store.record.Status != ports.ExecutionCompleted {
		t.Fatalf("durable rejection receipt = %#v record=%#v", receipt, store.record)
	}
	foundAudit := false
	for _, event := range audit.events {
		if event.ID == receipt.AuditRef && event.Decision == string(model.ActionRejected) && !event.SideEffect {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Fatalf("receipt audit reference %q does not name a durable rejection event: %#v", receipt.AuditRef, audit.events)
	}
}

func TestDurableExecuteMarksInvalidAuthenticatedReceiptUncertain(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 47, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{88}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, now, false)
	invalid := durableReceipt(grant, now.Add(time.Second))
	invalid.GrantID = "different-grant"
	store := &durableExecutionStoreFake{}
	tools := &durableOperatorToolFake{now: now.Add(time.Second), executeReceipt: &invalid}
	service := newDurableOperatorService(
		t, now.Add(time.Second), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{}

	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("Execute() invalid receipt error = nil")
	}
	if tools.calls != 1 || store.markCalls != 1 || store.record.Status != ports.ExecutionUncertain {
		t.Fatalf("invalid authenticated receipt handling: tools=%d marks=%d state=%q", tools.calls, store.markCalls, store.record.Status)
	}
}

func TestDurableExecuteRecoversLostActionResponseWithoutRepeatingExecution(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, 10, 2, 1, 50, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{86}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, issuedAt, false)
	downstreamReceipt := durableReceipt(grant, issuedAt.Add(2*time.Second))
	store := &durableExecutionStoreFake{}
	tools := &durableOperatorToolFake{
		now: issuedAt.Add(2 * time.Second), err: errors.New("connection reset after downstream commit"),
		lookupState: toolapi.RemediationCompleted, lookupReceipt: &downstreamReceipt,
	}
	service := newDurableOperatorService(
		t, issuedAt.Add(time.Second), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{}
	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("Execute() lost response error = nil")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionPending {
		t.Fatalf("Execute() lost response error = %v, want %s", err, model.CodeExecutionPending)
	}
	if store.record.Status != ports.ExecutionReserved || store.markCalls != 0 || tools.calls != 1 {
		t.Fatalf("lost response discarded recovery state: record=%#v marks=%d executions=%d", store.record, store.markCalls, tools.calls)
	}

	tools.err = nil
	restarted := newDurableOperatorService(
		t, issuedAt.Add(4*time.Minute), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	restarted.Audit = &durableAuditFake{}
	recovered, err := restarted.Execute(context.Background(), grant)
	if err != nil || !reflect.DeepEqual(recovered, downstreamReceipt) {
		t.Fatalf("Execute() recovery = (%#v, %v), want exact downstream receipt", recovered, err)
	}
	if tools.calls != 1 || tools.lookupCalls != 1 || store.record.Status != ports.ExecutionCompleted || store.markCalls != 0 {
		t.Fatalf("lost response recovery repeated or became uncertain: executions=%d lookups=%d record=%#v marks=%d", tools.calls, tools.lookupCalls, store.record, store.markCalls)
	}
}

func TestDurableExecuteRecoversOperatorCompletionFailureFromDownstreamTruth(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, 10, 2, 1, 55, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{87}, ed25519.SeedSize))
	grant := signedDurableGrant(t, privateKey, issuedAt, false)
	downstreamReceipt := durableReceipt(grant, issuedAt.Add(2*time.Second))
	store := &durableExecutionStoreFake{completeErr: errors.New("database acknowledgement unavailable")}
	tools := &durableOperatorToolFake{
		now: issuedAt.Add(2 * time.Second), lookupState: toolapi.RemediationCompleted,
		lookupReceipt: &downstreamReceipt,
	}
	service := newDurableOperatorService(
		t, issuedAt.Add(time.Second), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	service.Audit = &durableAuditFake{}
	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("Execute() completion failure error = nil")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionPending {
		t.Fatalf("Execute() completion failure error = %v, want %s", err, model.CodeExecutionPending)
	}
	if store.record.Status != ports.ExecutionReserved || store.markCalls != 0 || tools.calls != 1 {
		t.Fatalf("completion failure discarded recovery state: record=%#v marks=%d executions=%d", store.record, store.markCalls, tools.calls)
	}

	store.completeErr = nil
	restarted := newDurableOperatorService(
		t, issuedAt.Add(4*time.Minute), privateKey.Public().(ed25519.PublicKey), tools, store, false,
	)
	restarted.Audit = &durableAuditFake{}
	recovered, err := restarted.Execute(context.Background(), grant)
	if err != nil || !reflect.DeepEqual(recovered, downstreamReceipt) {
		t.Fatalf("Execute() completion recovery = (%#v, %v), want exact downstream receipt", recovered, err)
	}
	if tools.calls != 1 || tools.lookupCalls != 1 || store.record.Status != ports.ExecutionCompleted || store.markCalls != 0 {
		t.Fatalf("completion recovery repeated or became uncertain: executions=%d lookups=%d record=%#v marks=%d", tools.calls, tools.lookupCalls, store.record, store.markCalls)
	}
}

func TestDurableReportCommitsOutboxBeforeReturningQueuedAndReplaysAfterExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 2, 0, 0, 0, time.UTC)
	notifier := &operatorNotifierFake{}
	service := newReportOperatorService(t, now, notifier)
	receipt := operatorReportReceipt(now, model.ActionSucceeded, false)
	executionStore := &durableExecutionStoreFake{found: true, record: ports.ExecutionRecord{
		Scope: ports.ExecutionScopeOperator, Status: ports.ExecutionCompleted, Receipt: &receipt,
	}}
	outbox := newDurableReportOutboxFake()
	service.ExecutionStore = executionStore
	service.ReportOutbox = outbox
	request := unsignedOperatorReportRequest(now, model.IncidentResolved, model.ReportReasonRecoveryVerified)
	request.GrantID, request.ReceiptID = receipt.GrantID, receipt.ReceiptID
	request = signOperatorReportRequest(t, request)

	first, err := service.Report(context.Background(), request)
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	if first.Notification.Status != model.NotificationQueued || outbox.acceptCalls != 1 {
		t.Fatalf("first report was not durably queued: result=%#v accepts=%d", first, outbox.acceptCalls)
	}
	if notifier.calls != 0 {
		t.Fatalf("durable report notified inline %d times", notifier.calls)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("queued report result validation error = %v", err)
	}

	// A new process can recover the exact accepted result after request expiry
	// without signature freshness granting a new notification intent.
	restarted := newReportOperatorService(t, now.Add(3*time.Minute), notifier)
	restarted.ExecutionStore = executionStore
	restarted.ReportOutbox = outbox
	second, err := restarted.Report(context.Background(), request)
	if err != nil {
		t.Fatalf("expired accepted Report() error = %v", err)
	}
	if second.Report.Digest != first.Report.Digest || second.Notification.Status != model.NotificationQueued {
		t.Fatalf("recovered report = %#v, want original queued report", second)
	}
	if outbox.acceptCalls != 1 || notifier.calls != 0 {
		t.Fatalf("replay duplicated side effects: accepts=%d notifications=%d", outbox.acceptCalls, notifier.calls)
	}

	// A fresh v2 signature may rotate only the authorization window. The
	// logical request/report identity and immutable ReportCreatedAt remain exact.
	renewed := request
	renewed.RequestedAt = now.Add(3 * time.Minute)
	renewed.ExpiresAt = renewed.RequestedAt.Add(2 * time.Minute)
	renewed.Signature = model.ReportRequestSignature{}
	renewed = signOperatorReportRequest(t, renewed)
	renewedResult, err := restarted.Report(context.Background(), renewed)
	if err != nil || renewedResult.Report.Digest != first.Report.Digest {
		t.Fatalf("semantic report renewal recovery = (%#v, %v), want original report", renewedResult, err)
	}
	if outbox.acceptCalls != 1 {
		t.Fatalf("semantic renewal duplicated report acceptance: %d", outbox.acceptCalls)
	}

	tampered := renewed
	tampered.ReportCreatedAt = tampered.ReportCreatedAt.Add(time.Second)
	tampered.Signature = model.ReportRequestSignature{}
	tampered = signOperatorReportRequest(t, tampered)
	if _, err := restarted.Report(context.Background(), tampered); err == nil {
		t.Fatal("freshly signed renewal changed immutable ReportCreatedAt")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeInvalidInput {
		t.Fatalf("tampered renewal error = %v, want %s", err, model.CodeInvalidInput)
	}
}

func TestDurableReportPersistsWithoutNotificationIntentAndReplaysAfterExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 2, 10, 0, 0, time.UTC)
	service := newReportOperatorService(t, now, nil)
	service.Notifier = nil
	store := newDurableReportOutboxFake()
	service.ReportOutbox = store
	request := operatorReportRequest(
		t, now, model.IncidentEscalated, model.ReportReasonDiagnosisInconclusive,
	)

	first, err := service.Report(context.Background(), request)
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	if first.Notification.Status != model.NotificationFailed ||
		first.Notification.ErrorMessage != "notification service is unavailable" {
		t.Fatalf("notification-disabled result = %#v, want durable report with unavailable delivery", first)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("notification-disabled result validation error = %v", err)
	}
	if store.acceptCalls != 1 || store.notificationIntents != 0 {
		t.Fatalf("durable acceptance = %d, notification intents = %d; want 1, 0", store.acceptCalls, store.notificationIntents)
	}

	// Simulate a new Operator process after the signed request has expired. It
	// must recover the immutable report without creating a notification intent.
	restarted := newReportOperatorService(t, now.Add(3*time.Minute), nil)
	restarted.ReportOutbox = store
	second, err := restarted.Report(context.Background(), request)
	if err != nil {
		t.Fatalf("expired accepted Report() error = %v", err)
	}
	if second.Report.Digest != first.Report.Digest || second.Notification.Status != model.NotificationFailed {
		t.Fatalf("recovered notification-disabled report = %#v", second)
	}
	if store.acceptCalls != 1 || store.notificationIntents != 0 {
		t.Fatalf("restart duplicated durable state: accepts=%d intents=%d", store.acceptCalls, store.notificationIntents)
	}
}

func TestOutboxWorkerRetriesDeliversAndDeadLettersDeterministically(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 2, 15, 0, 0, time.UTC)
	report := durableTestReport(t, now)

	t.Run("retry", func(t *testing.T) {
		store := newDurableReportOutboxFake()
		store.claimed = []ports.OutboxMessage{durableOutboxMessage(report, 1)}
		worker := &OutboxWorker{
			Store: store, Notifier: &operatorNotifierFake{err: errors.New("provider unavailable")},
			Clock: operatorClock{now: now}, InstanceID: "operator-1",
			BaseBackoff: 2 * time.Second, MaxBackoff: 10 * time.Second, MaxAttempts: 3,
		}
		claimed, err := worker.RunOnce(context.Background())
		if err != nil || claimed != 1 {
			t.Fatalf("RunOnce() = (%d, %v), want (1, nil)", claimed, err)
		}
		if store.retryCalls != 1 || !store.retryAt.Equal(now.Add(2*time.Second)) {
			t.Fatalf("retry state: calls=%d at=%s", store.retryCalls, store.retryAt)
		}
		if store.deadLetterCalls != 0 || store.deliveredCalls != 0 {
			t.Fatalf("retry performed terminal transition: dead=%d delivered=%d", store.deadLetterCalls, store.deliveredCalls)
		}
	})

	t.Run("delivery", func(t *testing.T) {
		store := newDurableReportOutboxFake()
		store.claimed = []ports.OutboxMessage{durableOutboxMessage(report, 2)}
		worker := &OutboxWorker{
			Store: store, Notifier: &operatorNotifierFake{}, Clock: operatorClock{now: now},
			InstanceID: "operator-1", MaxAttempts: 3,
		}
		if claimed, err := worker.RunOnce(context.Background()); err != nil || claimed != 1 {
			t.Fatalf("RunOnce() = (%d, %v), want (1, nil)", claimed, err)
		}
		if store.deliveredCalls != 1 || store.providerMessageID != "whatsapp-message-1" {
			t.Fatalf("delivery state: calls=%d provider=%q", store.deliveredCalls, store.providerMessageID)
		}
	})

	t.Run("dead letter", func(t *testing.T) {
		store := newDurableReportOutboxFake()
		store.claimed = []ports.OutboxMessage{durableOutboxMessage(report, 3)}
		worker := &OutboxWorker{
			Store: store, Notifier: &operatorNotifierFake{err: errors.New("provider unavailable")},
			Clock: operatorClock{now: now}, InstanceID: "operator-1", MaxAttempts: 3,
		}
		if claimed, err := worker.RunOnce(context.Background()); err != nil || claimed != 1 {
			t.Fatalf("RunOnce() = (%d, %v), want (1, nil)", claimed, err)
		}
		if store.deadLetterCalls != 1 || store.retryCalls != 0 {
			t.Fatalf("dead-letter state: dead=%d retries=%d", store.deadLetterCalls, store.retryCalls)
		}
	})
}

func TestOutboxWorkerLeavesLeaseForAtLeastOnceRecoveryWhenDeliveryAckFails(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 2, 30, 0, 0, time.UTC)
	store := newDurableReportOutboxFake()
	store.claimed = []ports.OutboxMessage{durableOutboxMessage(durableTestReport(t, now), 1)}
	store.deliveredErr = errors.New("database commit result unknown")
	worker := &OutboxWorker{
		Store: store, Notifier: &operatorNotifierFake{}, Clock: operatorClock{now: now},
		InstanceID: "operator-1",
	}

	claimed, err := worker.RunOnce(context.Background())
	if err == nil || claimed != 1 {
		t.Fatalf("RunOnce() = (%d, %v), want acknowledgement error", claimed, err)
	}
	if store.retryCalls != 0 || store.deadLetterCalls != 0 {
		t.Fatalf("acknowledgement error rewrote lease: retries=%d dead=%d", store.retryCalls, store.deadLetterCalls)
	}
}

func TestOutboxWorkerRejectsLeaseShorterThanClaimedDeliveryWindow(t *testing.T) {
	t.Parallel()
	worker := &OutboxWorker{
		Store: newDurableReportOutboxFake(), Notifier: &operatorNotifierFake{},
		Clock: operatorClock{now: time.Now().UTC()}, InstanceID: "operator-1",
		Lease: 20 * time.Second, BatchSize: 2, DeliveryTimeout: 10 * time.Second,
	}
	if _, err := worker.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "batch delivery window") {
		t.Fatalf("RunOnce() error = %v, want unsafe lease rejection", err)
	}
}

func TestOutboxWorkerCancelsSlowProviderBeforeLeaseExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 2, 45, 0, 0, time.UTC)
	store := newDurableReportOutboxFake()
	store.claimed = []ports.OutboxMessage{durableOutboxMessage(durableTestReport(t, now), 1)}
	worker := &OutboxWorker{
		Store: store, Notifier: blockingNotifier{}, Clock: operatorClock{now: now},
		InstanceID: "operator-1", Lease: 3 * time.Second, DeliveryTimeout: time.Second,
	}
	started := time.Now()
	claimed, err := worker.RunOnce(context.Background())
	if err != nil || claimed != 1 {
		t.Fatalf("RunOnce() = (%d, %v), want timed-out attempt durably retried", claimed, err)
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond || elapsed >= 3*time.Second {
		t.Fatalf("provider attempt elapsed %s, want cancellation before lease expiry", elapsed)
	}
	if store.retryCalls != 1 || store.deliveredCalls != 0 {
		t.Fatalf("slow provider state: retries=%d delivered=%d", store.retryCalls, store.deliveredCalls)
	}
}

func signedDurableGrant(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, dryRun bool) model.DelegationGrant {
	t.Helper()
	grant := operatorGrant(now)
	grant.DryRun = dryRun
	signed, err := security.SignGrant(privateKey, "operator-test-key", grant)
	if err != nil {
		t.Fatalf("SignGrant() error = %v", err)
	}
	return signed
}

func newDurableOperatorService(
	t *testing.T,
	now time.Time,
	publicKey ed25519.PublicKey,
	tools ports.ToolCaller,
	store ports.ActionExecutionStore,
	requireDryRun bool,
) *Service {
	t.Helper()
	verifier, err := security.NewVerifier(publicKey, "operator-test-key", model.AgentOperator)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	policy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1, MaximumGrantTTL: 5 * time.Minute,
		RequireDryRun: requireDryRun,
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return &Service{
		Tools: tools, Verifier: verifier, Policy: policy, Clock: operatorClock{now: now}, IDs: &operatorIDs{},
		ExecutionStore: store, InstanceID: "operator-1", ExecutionLease: 30 * time.Second,
	}
}

func durableReceipt(grant model.DelegationGrant, at time.Time) model.ActionReceipt {
	outcome := model.ActionSucceeded
	if grant.DryRun {
		outcome = model.ActionDryRun
	}
	return model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1, ReceiptID: "durable-receipt-1",
		GrantID: grant.GrantID, IncidentID: grant.IncidentID, Action: grant.Action,
		Outcome: outcome, DryRun: grant.DryRun, StartedAt: at, CompletedAt: at, AuditRef: "audit-durable-1",
	}
}

type durableExecutionStoreFake struct {
	mu            sync.Mutex
	found         bool
	record        ports.ExecutionRecord
	order         *[]string
	getErr        error
	reserveErr    error
	completeErr   error
	markErr       error
	reserveCalls  int
	completeCalls int
	markCalls     int
}

func (f *durableExecutionStoreFake) note(value string) {
	if f.order != nil {
		*f.order = append(*f.order, value)
	}
}

func (f *durableExecutionStoreFake) GetExecution(
	_ context.Context,
	_ ports.ExecutionScope,
	_ model.DelegationGrant,
) (ports.ExecutionRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("get")
	return cloneExecutionRecord(f.record), f.found, f.getErr
}

func (f *durableExecutionStoreFake) GetExecutionByID(
	_ context.Context,
	_ ports.ExecutionScope,
	grantID string,
) (ports.ExecutionRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.found || f.record.Receipt == nil || f.record.Receipt.GrantID != grantID {
		return ports.ExecutionRecord{}, false, f.getErr
	}
	return cloneExecutionRecord(f.record), true, f.getErr
}

func (f *durableExecutionStoreFake) ReserveExecution(
	_ context.Context,
	scope ports.ExecutionScope,
	grant model.DelegationGrant,
	owner string,
	lease time.Duration,
) (ports.ExecutionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("reserve")
	f.reserveCalls++
	if f.reserveErr != nil {
		return ports.ExecutionRecord{}, f.reserveErr
	}
	if f.found && f.record.Status == ports.ExecutionReserved {
		f.record.Scope = scope
		f.record.Grant = grant
		f.record.Owner = true
		f.record.RecoveredLease = true
		f.record.LeaseToken = "lease-token-recovered"
		f.record.LeaseOwner = owner
		f.record.LeaseUntil = time.Now().Add(lease)
		f.record.Version++
		return cloneExecutionRecord(f.record), nil
	}
	f.record = ports.ExecutionRecord{
		Scope: scope, Grant: grant, Status: ports.ExecutionReserved, Owner: true,
		LeaseToken: "lease-token-1", LeaseOwner: owner, LeaseUntil: time.Now().Add(lease), StartedAt: time.Now().UTC(), Version: 1,
	}
	f.found = true
	return cloneExecutionRecord(f.record), nil
}

func (f *durableExecutionStoreFake) CompleteExecution(
	_ context.Context,
	_ ports.ExecutionScope,
	_ string,
	_ string,
	receipt model.ActionReceipt,
) (ports.ExecutionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("complete")
	f.completeCalls++
	if f.completeErr != nil {
		return ports.ExecutionRecord{}, f.completeErr
	}
	copyReceipt := cloneActionReceipt(receipt)
	f.record.Status = ports.ExecutionCompleted
	f.record.Owner = false
	f.record.Receipt = &copyReceipt
	return cloneExecutionRecord(f.record), nil
}

func (f *durableExecutionStoreFake) MarkExecutionUncertain(
	_ context.Context,
	_ ports.ExecutionScope,
	_ string,
	_ string,
	code model.ErrorCode,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("uncertain")
	f.markCalls++
	if f.markErr != nil {
		return f.markErr
	}
	f.record.Status = ports.ExecutionUncertain
	f.record.ErrorCode = code
	f.record.Owner = false
	return nil
}

func (*durableExecutionStoreFake) PurgeExecutions(context.Context, time.Time, int) (int64, error) {
	return 0, nil
}

func cloneExecutionRecord(record ports.ExecutionRecord) ports.ExecutionRecord {
	if record.Receipt != nil {
		receipt := cloneActionReceipt(*record.Receipt)
		record.Receipt = &receipt
	}
	return record
}

type durableOperatorToolFake struct {
	calls          int
	lookupCalls    int
	now            time.Time
	err            error
	lookupErr      error
	lookupState    toolapi.RemediationExecutionState
	lookupReceipt  *model.ActionReceipt
	executeReceipt *model.ActionReceipt
	order          *[]string
}

func (*durableOperatorToolFake) Discover(context.Context) ([]string, error) {
	return []string{toolapi.ToolExecuteRemediation, toolapi.ToolGetRemediationResult}, nil
}

func (f *durableOperatorToolFake) Call(_ context.Context, name string, input, output any) error {
	if name == toolapi.ToolGetRemediationResult {
		if _, ok := input.(toolapi.GetRemediationResultInput); !ok {
			return fmt.Errorf("unexpected remediation lookup input %T", input)
		}
		result, ok := output.(*toolapi.GetRemediationResultOutput)
		if !ok {
			return fmt.Errorf("unexpected remediation lookup output %T", output)
		}
		f.lookupCalls++
		if f.lookupErr != nil {
			return f.lookupErr
		}
		result.State = f.lookupState
		if result.State == "" {
			result.State = toolapi.RemediationNotFound
		}
		if f.lookupReceipt != nil {
			copy := cloneActionReceipt(*f.lookupReceipt)
			result.Receipt = &copy
		}
		return nil
	}
	if name != toolapi.ToolExecuteRemediation {
		return fmt.Errorf("unexpected tool %q", name)
	}
	grantInput, ok := input.(toolapi.ExecuteRemediationInput)
	if !ok {
		return fmt.Errorf("unexpected remediation input %T", input)
	}
	result, ok := output.(*toolapi.ExecuteRemediationOutput)
	if !ok {
		return fmt.Errorf("unexpected remediation output %T", output)
	}
	f.calls++
	if f.order != nil {
		*f.order = append(*f.order, "tool")
	}
	if f.err != nil {
		return f.err
	}
	if f.executeReceipt != nil {
		result.Receipt = cloneActionReceipt(*f.executeReceipt)
		return nil
	}
	result.Receipt = durableReceipt(grantInput.Grant, f.now)
	return nil
}

func (*durableOperatorToolFake) Close() error { return nil }

type durableAuditFake struct {
	mu     sync.Mutex
	err    error
	events []model.AuditEvent
}

type blockingNotifier struct{}

func (blockingNotifier) Notify(ctx context.Context, _ model.IncidentReport) (model.NotificationDelivery, error) {
	<-ctx.Done()
	return model.NotificationDelivery{}, ctx.Err()
}

func (f *durableAuditFake) Record(_ context.Context, event model.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
	return f.err
}

type durableReportOutboxFake struct {
	mu                  sync.Mutex
	reports             map[string]ports.StoredReport
	acceptCalls         int
	notificationIntents int
	claimed             []ports.OutboxMessage
	claimErr            error
	deliveredErr        error
	retryErr            error
	deadLetterErr       error
	deliveredCalls      int
	retryCalls          int
	deadLetterCalls     int
	providerMessageID   string
	retryAt             time.Time
}

func newDurableReportOutboxFake() *durableReportOutboxFake {
	return &durableReportOutboxFake{reports: make(map[string]ports.StoredReport)}
}

func (f *durableReportOutboxFake) AcceptReport(
	_ context.Context,
	request model.IncidentReportRequest,
	report model.IncidentReport,
	intent *ports.ReportNotificationIntent,
) (ports.StoredReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acceptCalls++
	if existing, ok := f.reports[request.RequestID]; ok {
		existing.Created = false
		return existing, nil
	}
	at := request.RequestedAt
	if intent != nil {
		f.notificationIntents++
		at = intent.AvailableAt
	}
	stored := ports.StoredReport{
		Request: request, Report: report, Created: true,
		HasNotificationIntent: intent != nil, CreatedAt: at, UpdatedAt: at,
	}
	f.reports[request.RequestID] = stored
	return stored, nil
}

func (f *durableReportOutboxFake) GetReport(
	_ context.Context,
	requestID string,
) (ports.StoredReport, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	report, ok := f.reports[requestID]
	return report, ok, nil
}

func (f *durableReportOutboxFake) ClaimOutbox(
	_ context.Context,
	_ string,
	_ int,
	_ time.Duration,
) ([]ports.OutboxMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ports.OutboxMessage(nil), f.claimed...), f.claimErr
}

func (f *durableReportOutboxFake) MarkOutboxDelivered(
	_ context.Context,
	_ int64,
	_ string,
	providerMessageID string,
	_ time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deliveredCalls++
	f.providerMessageID = providerMessageID
	return f.deliveredErr
}

func (f *durableReportOutboxFake) RetryOutbox(
	_ context.Context,
	_ int64,
	_ string,
	_ model.ErrorCode,
	availableAt time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retryCalls++
	f.retryAt = availableAt
	return f.retryErr
}

func (f *durableReportOutboxFake) DeadLetterOutbox(
	_ context.Context,
	_ int64,
	_ string,
	_ model.ErrorCode,
	_ time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadLetterCalls++
	return f.deadLetterErr
}

func (*durableReportOutboxFake) GetOutbox(context.Context, string) (ports.OutboxMessage, bool, error) {
	return ports.OutboxMessage{}, false, nil
}

func (*durableReportOutboxFake) PurgeDeliveredOutbox(context.Context, time.Time, int) (int64, error) {
	return 0, nil
}

func durableTestReport(t *testing.T, now time.Time) model.IncidentReport {
	t.Helper()
	request := operatorReportRequest(t, now, model.IncidentEscalated, model.ReportReasonPolicyDenied)
	report, err := (&Service{}).buildReport(context.Background(), request, false)
	if err != nil {
		t.Fatalf("buildReport() error = %v", err)
	}
	return report
}

func durableOutboxMessage(report model.IncidentReport, attempts int) ports.OutboxMessage {
	return ports.OutboxMessage{
		ID: 1, Report: report, Channel: model.NotificationChannelWhatsApp,
		IdempotencyKey: report.RequestID, Status: ports.OutboxSending,
		Attempts: attempts, LeaseOwner: "operator-1", LeaseToken: "outbox-lease-1",
	}
}
