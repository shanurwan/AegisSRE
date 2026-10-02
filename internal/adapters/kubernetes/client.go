package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type Client struct {
	Kube           kubernetes.Interface
	Namespace      string
	Verifier       ports.GrantVerifier
	Policy         ports.GrantAuthorizer
	Replay         ports.ReplayGuard
	Clock          ports.Clock
	IDs            ports.IDGenerator
	Audit          ports.Auditor
	AllowMutations bool
	ExecutionStore ports.ActionExecutionStore
	InstanceID     string
	ExecutionLease time.Duration
	RequestTimeout time.Duration

	mu            sync.Mutex
	receipts      map[string]model.ActionReceipt
	receiptGrants map[string]model.DelegationGrant
}

func New(kubeconfig, namespace string) (*Client, error) {
	config, err := clusterConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	config.Timeout = 10 * time.Second
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return &Client{
		Kube: clientset, Namespace: namespace,
		receipts: make(map[string]model.ActionReceipt), receiptGrants: make(map[string]model.DelegationGrant),
	}, nil
}

func clusterConfig(kubeconfig string) (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}
	config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load in-cluster or kubeconfig credentials: %w", err)
	}
	return config, nil
}

func (c *Client) GetWorkloadSnapshot(ctx context.Context, input toolapi.GetWorkloadSnapshotInput) (toolapi.GetWorkloadSnapshotOutput, error) {
	if err := c.validateTarget(input.Namespace, input.Kind, input.Name); err != nil {
		return toolapi.GetWorkloadSnapshotOutput{}, err
	}
	deployment, err := c.Kube.AppsV1().Deployments(input.Namespace).Get(ctx, input.Name, metav1.GetOptions{})
	if err != nil {
		return toolapi.GetWorkloadSnapshotOutput{}, fmt.Errorf("get deployment: %w", err)
	}
	selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
	if err != nil {
		return toolapi.GetWorkloadSnapshotOutput{}, fmt.Errorf("deployment selector: %w", err)
	}
	pods, err := c.Kube.CoreV1().Pods(input.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 100})
	if err != nil {
		return toolapi.GetWorkloadSnapshotOutput{}, fmt.Errorf("list deployment pods: %w", err)
	}
	podNames := make(map[string]struct{}, len(pods.Items))
	result := toolapi.WorkloadSnapshot{
		Target:          model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: input.Namespace, Name: input.Name},
		ResourceVersion: deployment.ResourceVersion, Generation: deployment.Generation,
		ObservedGeneration: deployment.Status.ObservedGeneration,
		DesiredReplicas:    valueOrZero(deployment.Spec.Replicas), ReadyReplicas: deployment.Status.ReadyReplicas,
		AvailableReplicas: deployment.Status.AvailableReplicas, UnavailableReplicas: deployment.Status.UnavailableReplicas,
		Selector: selector.String(), ObservedAt: c.now(),
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		podNames[pod.Name] = struct{}{}
		result.Pods = append(result.Pods, podSnapshot(pod))
	}
	sort.Slice(result.Pods, func(i, j int) bool { return result.Pods[i].Name < result.Pods[j].Name })
	events, err := c.Kube.CoreV1().Events(input.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("type", corev1.EventTypeWarning).String(), Limit: 200,
	})
	if err == nil {
		for i := range events.Items {
			event := &events.Items[i]
			_, podEvent := podNames[event.InvolvedObject.Name]
			if !(event.InvolvedObject.Kind == "Deployment" && event.InvolvedObject.Name == input.Name) && !podEvent {
				continue
			}
			result.Events = append(result.Events, eventSnapshot(event))
			if len(result.Events) == 50 {
				break
			}
		}
	}
	return toolapi.GetWorkloadSnapshotOutput{Snapshot: result}, nil
}

func (c *Client) GetPodLogs(ctx context.Context, input toolapi.GetPodLogsInput) (toolapi.GetPodLogsOutput, error) {
	if input.Namespace != c.Namespace {
		return toolapi.GetPodLogsOutput{}, model.NewError(model.CodeOutOfScope, "pod log namespace is not allowed")
	}
	if errs := validation.IsDNS1123Subdomain(input.Pod); len(errs) > 0 {
		return toolapi.GetPodLogsOutput{}, model.NewError(model.CodeInvalidInput, "invalid pod name")
	}
	if input.Container != "" {
		if errs := validation.IsDNS1123Label(input.Container); len(errs) > 0 {
			return toolapi.GetPodLogsOutput{}, model.NewError(model.CodeInvalidInput, "invalid container name")
		}
	}
	tail := input.TailLines
	if tail == 0 {
		tail = 100
	}
	if tail < 1 || tail > 500 {
		return toolapi.GetPodLogsOutput{}, errors.New("tail_lines must be between 1 and 500")
	}
	maxBytes := input.MaxBytes
	if maxBytes == 0 {
		maxBytes = 32768
	}
	if maxBytes < 1024 || maxBytes > 131072 {
		return toolapi.GetPodLogsOutput{}, errors.New("max_bytes must be between 1024 and 131072")
	}
	stream, err := c.Kube.CoreV1().Pods(input.Namespace).GetLogs(input.Pod, &corev1.PodLogOptions{
		Container: input.Container, TailLines: &tail, Previous: input.Previous, Timestamps: true,
	}).Stream(ctx)
	if err != nil {
		return toolapi.GetPodLogsOutput{}, fmt.Errorf("open pod logs: %w", err)
	}
	defer stream.Close()
	data, err := io.ReadAll(io.LimitReader(stream, int64(maxBytes+1)))
	if err != nil {
		return toolapi.GetPodLogsOutput{}, fmt.Errorf("read pod logs: %w", err)
	}
	truncated := len(data) > maxBytes
	if truncated {
		data = data[:maxBytes]
	}
	return toolapi.GetPodLogsOutput{
		Pod: input.Pod, Container: input.Container, Logs: string(data), Truncated: truncated,
	}, nil
}

// ResolvePodDeployment proves the current Kubernetes controller chain for a
// Pod. Names and labels are not authorization evidence: both owner-reference
// UIDs must match the live ReplicaSet and Deployment objects or the lookup
// fails closed.
func (c *Client) ResolvePodDeployment(ctx context.Context, namespace, podName string) (model.ResourceTarget, error) {
	if c == nil || c.Kube == nil {
		return model.ResourceTarget{}, errors.New("Kubernetes client is unavailable")
	}
	if namespace != c.Namespace {
		return model.ResourceTarget{}, model.NewError(model.CodeOutOfScope, "pod namespace is not allowed")
	}
	if errs := validation.IsDNS1123Subdomain(podName); len(errs) > 0 {
		return model.ResourceTarget{}, model.NewError(model.CodeInvalidInput, "invalid pod name")
	}
	pod, err := c.Kube.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return model.ResourceTarget{}, fmt.Errorf("get pod ownership: %w", err)
	}
	replicaSetOwner := metav1.GetControllerOf(pod)
	if replicaSetOwner == nil || replicaSetOwner.APIVersion != "apps/v1" || replicaSetOwner.Kind != "ReplicaSet" ||
		replicaSetOwner.Name == "" || replicaSetOwner.UID == "" {
		return model.ResourceTarget{}, model.NewError(model.CodeOutOfScope, "pod is not controlled by an apps/v1 ReplicaSet")
	}
	replicaSet, err := c.Kube.AppsV1().ReplicaSets(namespace).Get(ctx, replicaSetOwner.Name, metav1.GetOptions{})
	if err != nil {
		return model.ResourceTarget{}, fmt.Errorf("get pod ReplicaSet owner: %w", err)
	}
	if replicaSet.UID == "" || replicaSet.UID != replicaSetOwner.UID {
		return model.ResourceTarget{}, model.NewError(model.CodeOutOfScope, "pod ReplicaSet owner UID does not match the live object")
	}
	deploymentOwner := metav1.GetControllerOf(replicaSet)
	if deploymentOwner == nil || deploymentOwner.APIVersion != "apps/v1" || deploymentOwner.Kind != "Deployment" ||
		deploymentOwner.Name == "" || deploymentOwner.UID == "" {
		return model.ResourceTarget{}, model.NewError(model.CodeOutOfScope, "pod ReplicaSet is not controlled by an apps/v1 Deployment")
	}
	deployment, err := c.Kube.AppsV1().Deployments(namespace).Get(ctx, deploymentOwner.Name, metav1.GetOptions{})
	if err != nil {
		return model.ResourceTarget{}, fmt.Errorf("get pod Deployment owner: %w", err)
	}
	if deployment.UID == "" || deployment.UID != deploymentOwner.UID {
		return model.ResourceTarget{}, model.NewError(model.CodeOutOfScope, "pod Deployment owner UID does not match the live object")
	}
	return model.ResourceTarget{
		APIVersion: "apps/v1", Kind: "Deployment", Namespace: namespace, Name: deployment.Name,
	}, nil
}

func (c *Client) ExecuteRemediation(ctx context.Context, input toolapi.ExecuteRemediationInput) (toolapi.ExecuteRemediationOutput, error) {
	if c.ExecutionStore != nil {
		return c.executeRemediationDurable(ctx, input)
	}
	return c.executeRemediationMemory(ctx, input)
}

func (c *Client) executeRemediationMemory(ctx context.Context, input toolapi.ExecuteRemediationInput) (toolapi.ExecuteRemediationOutput, error) {
	if c.Verifier == nil || c.Policy == nil || c.Replay == nil || c.Clock == nil || c.IDs == nil {
		return toolapi.ExecuteRemediationOutput{}, errors.New("action backend security dependencies are incomplete")
	}
	grant := input.Grant
	now := c.now()
	if err := c.Verifier.Verify(grant, now); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	decision := c.Policy.Authorize(grant, now)
	if !decision.Allowed {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(decision.Code, decision.Reason)
	}
	if input.DryRun != grant.DryRun {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodePolicyDenied, "tool dry-run mode differs from signed grant")
	}
	if !grant.DryRun && !c.AllowMutations {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodePolicyDenied, "action MCP mutation switch is disabled")
	}
	if cached, ok, err := c.cachedReceipt(grant); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	} else if ok {
		return toolapi.ExecuteRemediationOutput{Receipt: cached}, nil
	}
	if err := c.Replay.ConsumeGrant(grant, now); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	if err := c.validateTarget(grant.Action.Target.Namespace, grant.Action.Target.Kind, grant.Action.Target.Name); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	deployment, err := c.Kube.AppsV1().Deployments(c.Namespace).Get(ctx, grant.Action.Target.Name, metav1.GetOptions{})
	if err != nil {
		return toolapi.ExecuteRemediationOutput{}, fmt.Errorf("read action precondition: %w", err)
	}
	if grant.Preconditions.ResourceVersion != "" && deployment.ResourceVersion != grant.Preconditions.ResourceVersion {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeStalePrecondition, "deployment resourceVersion changed after delegation")
	}
	beforeReplicas := valueOrZero(deployment.Spec.Replicas)
	if expected := grant.Preconditions.ExpectedReplicas; expected != nil && beforeReplicas != *expected {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeStalePrecondition, "deployment replica count changed after delegation")
	}
	before := resourceSnapshot(deployment)
	after, err := c.apply(ctx, deployment, grant)
	if err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	outcome := model.ActionSucceeded
	if grant.DryRun {
		outcome = model.ActionDryRun
	}
	completed := c.now()
	receipt := model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1, ReceiptID: "receipt-" + c.IDs.NewID(),
		GrantID: grant.GrantID, IncidentID: grant.IncidentID, Action: grant.Action,
		Outcome: outcome, DryRun: grant.DryRun, StartedAt: now, CompletedAt: completed,
		Before: &before, After: &after, AuditRef: "audit-" + c.IDs.NewID(),
	}
	if err := receipt.Validate(); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	c.storeReceipt(grant, receipt)
	if c.Audit != nil {
		_ = c.Audit.Record(ctx, model.AuditEvent{
			ID: receipt.AuditRef, IncidentID: grant.IncidentID, Actor: model.AgentMCPAction,
			Operation: string(grant.Action.Kind), Decision: string(outcome),
			SideEffect: outcome == model.ActionSucceeded, OccurredAt: completed,
		})
	}
	return toolapi.ExecuteRemediationOutput{Receipt: receipt}, nil
}

const (
	actionGrantAnnotation   = "aegissre.io/grant-id"
	restartTimeAnnotation   = "aegissre.io/restarted-at"
	defaultExecutionLease   = 30 * time.Second
	defaultRequestTimeout   = 10 * time.Second
	maxExecutionLease       = 5 * time.Minute
	maxMutationLeaseVersion = int64(2)
	durableWriteTimeout     = 10 * time.Second
)

func (c *Client) executeRemediationDurable(ctx context.Context, input toolapi.ExecuteRemediationInput) (toolapi.ExecuteRemediationOutput, error) {
	grant := input.Grant
	lease := c.executionLease()
	requestTimeout := c.executionRequestTimeout()
	if err := grant.ValidateSigned(); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	if input.DryRun != grant.DryRun {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodePolicyDenied, "tool dry-run mode differs from signed grant")
	}
	if err := c.validateTarget(grant.Action.Target.Namespace, grant.Action.Target.Kind, grant.Action.Target.Name); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}

	// An exact completed record is a result lookup, not a new authorization.
	// Looking it up before freshness enforcement lets a caller recover the
	// durable receipt after an accepted grant expires without enabling a new
	// side effect.
	existing, found, err := c.ExecutionStore.GetExecution(ctx, ports.ExecutionScopeMCPAction, grant)
	if err != nil {
		return toolapi.ExecuteRemediationOutput{}, fmt.Errorf("load durable action MCP execution: %w", err)
	}
	if found {
		if err := validateDurableExecutionRecord(existing, grant); err != nil {
			return toolapi.ExecuteRemediationOutput{}, err
		}
		switch existing.Status {
		case ports.ExecutionCompleted:
			return completedDurableOutput(existing, grant)
		case ports.ExecutionUncertain:
			return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeExecutionFailed, "previous action MCP execution has an uncertain outcome")
		case ports.ExecutionReserved:
			// Continue below. ReserveExecution either reports the live owner or
			// atomically transfers an expired lease to this instance.
		default:
			return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeExecutionFailed, "durable action MCP execution has an invalid state")
		}
	}

	if c.Kube == nil || c.Clock == nil {
		return toolapi.ExecuteRemediationOutput{}, errors.New("durable action backend execution dependencies are incomplete")
	}
	instanceID := strings.TrimSpace(c.InstanceID)
	if instanceID == "" || instanceID != c.InstanceID || len(instanceID) > 512 {
		return toolapi.ExecuteRemediationOutput{}, errors.New("action backend instance ID is required with a durable execution store")
	}
	if !grant.DryRun && c.Audit == nil {
		return toolapi.ExecuteRemediationOutput{}, errors.New("durable audit sink is required before a live action MCP mutation")
	}
	if err := c.validateDurableExecutionWindow(lease); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}

	if !found {
		if !grant.DryRun && !c.AllowMutations {
			return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodePolicyDenied, "action MCP mutation switch is disabled")
		}
		if err := c.authorizeCurrentGrant(grant); err != nil {
			return toolapi.ExecuteRemediationOutput{}, err
		}
	}

	reservation, err := c.ExecutionStore.ReserveExecution(
		ctx, ports.ExecutionScopeMCPAction, grant, instanceID, lease,
	)
	if err != nil {
		return toolapi.ExecuteRemediationOutput{}, fmt.Errorf("reserve durable action MCP execution: %w", err)
	}
	if err := validateDurableExecutionRecord(reservation, grant); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	switch reservation.Status {
	case ports.ExecutionCompleted:
		return completedDurableOutput(reservation, grant)
	case ports.ExecutionUncertain:
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeExecutionFailed, "action MCP execution has an uncertain outcome")
	case ports.ExecutionReserved:
		if !reservation.Owner || reservation.LeaseToken == "" {
			return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeReplayedGrant, "action MCP execution is already in progress")
		}
	default:
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeExecutionFailed, "durable action MCP execution has an invalid state")
	}

	fencedCtx := context.WithValue(
		ctx, durableExecutionDeadlineKey{}, time.Now().Add(requestTimeout+durableWriteTimeout),
	)
	operationCtx, cancel := context.WithTimeout(fencedCtx, requestTimeout)
	defer cancel()
	if c.Audit != nil {
		intent := model.AuditEvent{
			ID: durableActionID("intent", grant.GrantID, 0), IncidentID: grant.IncidentID,
			Actor: model.AgentMCPAction, Operation: string(grant.Action.Kind), Decision: "execution_reserved",
			SideEffect: false, OccurredAt: reservation.StartedAt.UTC(),
		}
		if err := c.Audit.Record(operationCtx, intent); err != nil {
			return toolapi.ExecuteRemediationOutput{}, fmt.Errorf("persist durable action MCP audit intent: %w", err)
		}
	}

	if reservation.RecoveredLease {
		return c.executeRecoveredReservation(operationCtx, grant, reservation)
	}
	return c.executeOwnedReservation(operationCtx, grant, reservation, nil)
}

func (c *Client) executeRecoveredReservation(
	ctx context.Context,
	grant model.DelegationGrant,
	reservation ports.ExecutionRecord,
) (toolapi.ExecuteRemediationOutput, error) {
	deployment, err := c.Kube.AppsV1().Deployments(grant.Action.Target.Namespace).Get(
		ctx, grant.Action.Target.Name, metav1.GetOptions{},
	)
	if err != nil {
		return toolapi.ExecuteRemediationOutput{}, c.markMutationUncertain(
			ctx, grant, reservation, fmt.Errorf("reconcile recovered action MCP lease: %w", err),
		)
	}

	state := classifyMutationState(deployment, grant)
	switch state {
	case mutationApplied:
		return c.completeDurableExecution(ctx, grant, reservation, nil, resourceSnapshot(deployment))
	case mutationRetrySafe:
		// An unchanged signed precondition proves that the earlier owner did not
		// visibly mutate this object at reconciliation time. It does not prove a
		// canceled Kubernetes request cannot be accepted later, and it does not
		// extend the grant's authority. A recovered owner must re-establish
		// signature freshness and current policy authorization before retrying.
		// If authorization is now unavailable, terminal rejection would be a
		// false no-mutation claim, so preserve the prior attempt as uncertain.
		if !grant.DryRun && !c.AllowMutations {
			return toolapi.ExecuteRemediationOutput{}, c.markMutationUncertain(
				ctx, grant, reservation,
				model.NewError(model.CodePolicyDenied, "action MCP mutation switch is disabled"),
			)
		}
		if err := c.authorizeCurrentGrant(grant); err != nil {
			return toolapi.ExecuteRemediationOutput{}, c.markMutationUncertain(ctx, grant, reservation, err)
		}
		if reservation.Version > maxMutationLeaseVersion {
			return toolapi.ExecuteRemediationOutput{}, c.markMutationUncertain(
				ctx, grant, reservation,
				model.NewError(model.CodeExecutionFailed, "action MCP exhausted its bounded mutation retry"),
			)
		}
		return c.executeOwnedReservation(ctx, grant, reservation, deployment)
	default:
		return toolapi.ExecuteRemediationOutput{}, c.markMutationUncertain(
			ctx, grant, reservation,
			model.NewError(model.CodeExecutionFailed, "Kubernetes state cannot prove whether the reserved mutation ran"),
		)
	}
}

func (c *Client) authorizeCurrentGrant(grant model.DelegationGrant) error {
	if c.Verifier == nil || c.Policy == nil {
		return errors.New("durable action backend authorization dependencies are incomplete")
	}
	now := c.now()
	if err := c.Verifier.Verify(grant, now); err != nil {
		return err
	}
	decision := c.Policy.Authorize(grant, now)
	if !decision.Allowed {
		return model.NewError(decision.Code, decision.Reason)
	}
	return nil
}

func (c *Client) executeOwnedReservation(
	ctx context.Context,
	grant model.DelegationGrant,
	reservation ports.ExecutionRecord,
	deployment *appsv1.Deployment,
) (toolapi.ExecuteRemediationOutput, error) {
	var err error
	if deployment == nil {
		deployment, err = c.Kube.AppsV1().Deployments(grant.Action.Target.Namespace).Get(
			ctx, grant.Action.Target.Name, metav1.GetOptions{},
		)
		if err != nil {
			return toolapi.ExecuteRemediationOutput{}, fmt.Errorf("read action precondition: %w", err)
		}
	}
	if err := validateActionPreconditions(deployment, grant); err != nil {
		markCtx, cancel := durableContext(ctx)
		defer cancel()
		if markErr := c.ExecutionStore.MarkExecutionUncertain(
			markCtx, ports.ExecutionScopeMCPAction, grant.GrantID, reservation.LeaseToken, model.CodeStalePrecondition,
		); markErr != nil {
			return toolapi.ExecuteRemediationOutput{}, errors.Join(err, fmt.Errorf("persist stale action MCP execution: %w", markErr))
		}
		return toolapi.ExecuteRemediationOutput{}, err
	}

	before := resourceSnapshot(deployment)
	after, err := c.apply(ctx, deployment, grant)
	if err != nil {
		if grant.DryRun {
			return toolapi.ExecuteRemediationOutput{}, err
		}
		return c.reconcileMutationFailure(ctx, grant, reservation, before, err)
	}
	return c.completeDurableExecution(ctx, grant, reservation, &before, after)
}

func (c *Client) reconcileMutationFailure(
	ctx context.Context,
	grant model.DelegationGrant,
	reservation ports.ExecutionRecord,
	before model.ResourceSnapshot,
	mutationErr error,
) (toolapi.ExecuteRemediationOutput, error) {
	reconcileCtx, cancel := durableContext(ctx)
	defer cancel()
	deployment, err := c.Kube.AppsV1().Deployments(grant.Action.Target.Namespace).Get(
		reconcileCtx, grant.Action.Target.Name, metav1.GetOptions{},
	)
	if err != nil {
		return toolapi.ExecuteRemediationOutput{}, c.markMutationUncertain(
			reconcileCtx, grant, reservation,
			errors.Join(mutationErr, fmt.Errorf("reconcile failed Kubernetes mutation: %w", err)),
		)
	}
	switch classifyMutationState(deployment, grant) {
	case mutationApplied:
		return c.completeDurableExecution(reconcileCtx, grant, reservation, &before, resourceSnapshot(deployment))
	case mutationRetrySafe:
		// The exact signed resourceVersion proves that this patch did not
		// mutate the object. Keep the lease reserved for one bounded retry.
		return toolapi.ExecuteRemediationOutput{}, mutationErr
	default:
		return toolapi.ExecuteRemediationOutput{}, c.markMutationUncertain(reconcileCtx, grant, reservation, mutationErr)
	}
}

func (c *Client) completeDurableExecution(
	ctx context.Context,
	grant model.DelegationGrant,
	reservation ports.ExecutionRecord,
	before *model.ResourceSnapshot,
	after model.ResourceSnapshot,
) (toolapi.ExecuteRemediationOutput, error) {
	outcome := model.ActionSucceeded
	if grant.DryRun {
		outcome = model.ActionDryRun
	}
	completedAt := c.now()
	if completedAt.Before(reservation.StartedAt) {
		completedAt = reservation.StartedAt.UTC()
	}
	receipt := model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1,
		ReceiptID:     durableActionID("receipt", grant.GrantID, reservation.Version),
		GrantID:       grant.GrantID,
		IncidentID:    grant.IncidentID,
		Action:        grant.Action,
		Outcome:       outcome,
		DryRun:        grant.DryRun,
		StartedAt:     reservation.StartedAt.UTC(),
		CompletedAt:   completedAt,
		Before:        before,
		After:         &after,
		AuditRef:      durableActionID("result", grant.GrantID, reservation.Version),
	}
	if err := validateReceiptForDurableGrant(receipt, grant); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}

	writeCtx, cancel := durableContext(ctx)
	defer cancel()
	if c.Audit != nil {
		if err := c.Audit.Record(writeCtx, model.AuditEvent{
			ID: receipt.AuditRef, IncidentID: grant.IncidentID, Actor: model.AgentMCPAction,
			Operation: string(grant.Action.Kind), Decision: string(outcome),
			SideEffect: outcome == model.ActionSucceeded, OccurredAt: completedAt,
		}); err != nil {
			return toolapi.ExecuteRemediationOutput{}, fmt.Errorf("persist durable action MCP result audit: %w", err)
		}
	}
	persisted, err := c.ExecutionStore.CompleteExecution(
		writeCtx, ports.ExecutionScopeMCPAction, grant.GrantID, reservation.LeaseToken, receipt,
	)
	if err != nil {
		return toolapi.ExecuteRemediationOutput{}, fmt.Errorf("persist durable action MCP receipt: %w", err)
	}
	if err := validateDurableExecutionRecord(persisted, grant); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	if persisted.Status != ports.ExecutionCompleted {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeExecutionFailed, "durable action MCP completion returned a non-completed state")
	}
	return completedDurableOutput(persisted, grant)
}

func (c *Client) markMutationUncertain(
	ctx context.Context,
	grant model.DelegationGrant,
	reservation ports.ExecutionRecord,
	cause error,
) error {
	markCtx, cancel := durableContext(ctx)
	defer cancel()
	err := c.ExecutionStore.MarkExecutionUncertain(
		markCtx, ports.ExecutionScopeMCPAction, grant.GrantID, reservation.LeaseToken, model.CodeExecutionFailed,
	)
	result := model.WrapError(model.CodeExecutionFailed, "Kubernetes mutation outcome is uncertain and requires reconciliation", cause)
	if err != nil {
		return errors.Join(result, fmt.Errorf("persist uncertain action MCP execution: %w", err))
	}
	return result
}

type mutationState uint8

const (
	mutationAmbiguous mutationState = iota
	mutationApplied
	mutationRetrySafe
)

func classifyMutationState(deployment *appsv1.Deployment, grant model.DelegationGrant) mutationState {
	if deployment == nil {
		return mutationAmbiguous
	}
	// A Kubernetes dry-run never persists the marker. Recovery can safely
	// repeat validation only while the signed precondition remains exact; a
	// coincidental marker must not be mistaken for this dry-run's result.
	if grant.DryRun {
		if validateActionPreconditions(deployment, grant) == nil {
			return mutationRetrySafe
		}
		return mutationAmbiguous
	}
	marker := ""
	applied := false
	switch grant.Action.Kind {
	case model.ActionRestartDeployment:
		marker = deployment.Spec.Template.Annotations[actionGrantAnnotation]
		applied = marker == grant.GrantID && deployment.Spec.Template.Annotations[restartTimeAnnotation] != ""
	case model.ActionScaleDeployment:
		marker = deployment.Annotations[actionGrantAnnotation]
		applied = marker == grant.GrantID && grant.Action.Parameters.Replicas != nil &&
			valueOrZero(deployment.Spec.Replicas) == *grant.Action.Parameters.Replicas
	default:
		return mutationAmbiguous
	}
	if applied {
		return mutationApplied
	}
	// A marker from an older grant may already have existed when this grant's
	// exact resourceVersion and replica preconditions were signed. Those
	// preconditions still prove that this grant did not mutate the object, so
	// the unrelated marker alone must not turn crash-before-mutation recovery
	// into an ambiguous outcome.
	if validateActionPreconditions(deployment, grant) == nil {
		return mutationRetrySafe
	}
	return mutationAmbiguous
}

func validateActionPreconditions(deployment *appsv1.Deployment, grant model.DelegationGrant) error {
	if grant.Preconditions.ResourceVersion == "" || deployment.ResourceVersion != grant.Preconditions.ResourceVersion {
		return model.NewError(model.CodeStalePrecondition, "deployment resourceVersion changed after delegation")
	}
	if expected := grant.Preconditions.ExpectedReplicas; expected != nil && valueOrZero(deployment.Spec.Replicas) != *expected {
		return model.NewError(model.CodeStalePrecondition, "deployment replica count changed after delegation")
	}
	return nil
}

func validateDurableExecutionRecord(record ports.ExecutionRecord, grant model.DelegationGrant) error {
	if record.Scope != ports.ExecutionScopeMCPAction || !record.Status.Valid() || record.Version < 1 || record.StartedAt.IsZero() {
		return model.NewError(model.CodeExecutionFailed, "durable action MCP execution record is invalid")
	}
	want, err := json.Marshal(grant)
	if err != nil {
		return fmt.Errorf("encode requested durable grant: %w", err)
	}
	got, err := json.Marshal(record.Grant)
	if err != nil {
		return fmt.Errorf("encode stored durable grant: %w", err)
	}
	if !bytes.Equal(got, want) {
		return model.NewError(model.CodeExecutionFailed, "durable action MCP execution does not match the signed grant")
	}
	return nil
}

func completedDurableOutput(record ports.ExecutionRecord, grant model.DelegationGrant) (toolapi.ExecuteRemediationOutput, error) {
	if record.Receipt == nil {
		return toolapi.ExecuteRemediationOutput{}, model.NewError(model.CodeExecutionFailed, "completed durable action MCP execution omitted its receipt")
	}
	if err := validateReceiptForDurableGrant(*record.Receipt, grant); err != nil {
		return toolapi.ExecuteRemediationOutput{}, err
	}
	return toolapi.ExecuteRemediationOutput{Receipt: cloneActionReceipt(*record.Receipt)}, nil
}

func validateReceiptForDurableGrant(receipt model.ActionReceipt, grant model.DelegationGrant) error {
	if err := receipt.Validate(); err != nil {
		return model.WrapError(model.CodeExecutionFailed, "durable action MCP receipt is invalid", err)
	}
	if receipt.GrantID != grant.GrantID || receipt.IncidentID != grant.IncidentID || !receipt.Action.Equal(grant.Action) {
		return model.NewError(model.CodeExecutionFailed, "durable action MCP receipt does not match the signed grant")
	}
	if receipt.Outcome != model.ActionRejected && (receipt.DryRun != grant.DryRun ||
		(grant.DryRun && receipt.Outcome != model.ActionDryRun) ||
		(!grant.DryRun && receipt.Outcome == model.ActionDryRun)) {
		return model.NewError(model.CodeExecutionFailed, "durable action MCP receipt dry-run semantics do not match the signed grant")
	}
	return nil
}

func cloneActionReceipt(receipt model.ActionReceipt) model.ActionReceipt {
	clone := receipt
	if receipt.Action.Parameters.Replicas != nil {
		value := *receipt.Action.Parameters.Replicas
		clone.Action.Parameters.Replicas = &value
	}
	if receipt.Before != nil {
		value := *receipt.Before
		clone.Before = &value
	}
	if receipt.After != nil {
		value := *receipt.After
		clone.After = &value
	}
	return clone
}

func (c *Client) executionLease() time.Duration {
	if c.ExecutionLease < time.Second || c.ExecutionLease > maxExecutionLease {
		return defaultExecutionLease
	}
	return c.ExecutionLease
}

func (c *Client) executionRequestTimeout() time.Duration {
	if c.RequestTimeout <= 0 || c.RequestTimeout > 2*time.Minute {
		return defaultRequestTimeout
	}
	return c.RequestTimeout
}

func (c *Client) validateDurableExecutionWindow(lease time.Duration) error {
	if lease <= c.executionRequestTimeout()+durableWriteTimeout {
		return model.NewError(
			model.CodeInvalidInput,
			"action MCP execution lease must outlive its request and durable recovery windows",
		)
	}
	return nil
}

func durableActionID(domain, grantID string, version int64) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("mcp-action:%s:%s:%d", domain, grantID, version)))
	return fmt.Sprintf("%s-%x", domain, digest[:])
}

type durableExecutionDeadlineKey struct{}

func durableContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Value(durableExecutionDeadlineKey{}).(time.Time); ok {
		return context.WithDeadline(base, deadline)
	}
	return context.WithTimeout(base, durableWriteTimeout)
}

// GetRemediationResult is deliberately narrower than remediation status. It
// consults only the exact signed-grant execution record and never evaluates
// freshness, acquires a lease, reads Kubernetes, or performs a mutation.
func (c *Client) GetRemediationResult(
	ctx context.Context,
	input toolapi.GetRemediationResultInput,
) (toolapi.GetRemediationResultOutput, error) {
	grant := input.Grant
	if err := grant.ValidateSigned(); err != nil {
		return toolapi.GetRemediationResultOutput{}, err
	}
	if c.ExecutionStore == nil {
		receipt, found, err := c.cachedReceipt(grant)
		if err != nil {
			return toolapi.GetRemediationResultOutput{}, err
		}
		if !found {
			return toolapi.GetRemediationResultOutput{State: toolapi.RemediationNotFound}, nil
		}
		copy := cloneActionReceipt(receipt)
		return toolapi.GetRemediationResultOutput{State: toolapi.RemediationCompleted, Receipt: &copy}, nil
	}

	record, found, err := c.ExecutionStore.GetExecution(ctx, ports.ExecutionScopeMCPAction, grant)
	if err != nil {
		return toolapi.GetRemediationResultOutput{}, fmt.Errorf("look up durable action MCP result: %w", err)
	}
	if !found {
		return toolapi.GetRemediationResultOutput{State: toolapi.RemediationNotFound}, nil
	}
	if err := validateDurableExecutionRecord(record, grant); err != nil {
		return toolapi.GetRemediationResultOutput{}, err
	}
	switch record.Status {
	case ports.ExecutionReserved:
		return toolapi.GetRemediationResultOutput{State: toolapi.RemediationReserved}, nil
	case ports.ExecutionUncertain:
		return toolapi.GetRemediationResultOutput{State: toolapi.RemediationUncertain}, nil
	case ports.ExecutionCompleted:
		completed, err := completedDurableOutput(record, grant)
		if err != nil {
			return toolapi.GetRemediationResultOutput{}, err
		}
		receipt := cloneActionReceipt(completed.Receipt)
		return toolapi.GetRemediationResultOutput{State: toolapi.RemediationCompleted, Receipt: &receipt}, nil
	default:
		return toolapi.GetRemediationResultOutput{}, model.NewError(model.CodeExecutionFailed, "durable action MCP result has an invalid state")
	}
}

func (c *Client) GetRemediationStatus(ctx context.Context, input toolapi.GetRemediationStatusInput) (toolapi.GetRemediationStatusOutput, error) {
	if c.Verifier == nil || c.Policy == nil || c.Clock == nil {
		return toolapi.GetRemediationStatusOutput{}, errors.New("action backend security dependencies are incomplete")
	}
	if err := c.Verifier.Verify(input.Grant, c.now()); err != nil {
		return toolapi.GetRemediationStatusOutput{}, err
	}
	decision := c.Policy.Authorize(input.Grant, c.now())
	if !decision.Allowed {
		return toolapi.GetRemediationStatusOutput{}, model.NewError(decision.Code, decision.Reason)
	}
	target := input.Grant.Action.Target
	if err := c.validateTarget(target.Namespace, target.Kind, target.Name); err != nil {
		return toolapi.GetRemediationStatusOutput{}, err
	}
	deployment, err := c.Kube.AppsV1().Deployments(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
	if err != nil {
		return toolapi.GetRemediationStatusOutput{}, err
	}
	snapshot := toolapi.WorkloadSnapshot{
		Target: target, ResourceVersion: deployment.ResourceVersion, Generation: deployment.Generation,
		ObservedGeneration: deployment.Status.ObservedGeneration,
		DesiredReplicas:    valueOrZero(deployment.Spec.Replicas), ReadyReplicas: deployment.Status.ReadyReplicas,
		AvailableReplicas: deployment.Status.AvailableReplicas, UnavailableReplicas: deployment.Status.UnavailableReplicas,
		ObservedAt: c.now(),
	}
	rolloutAvailable := snapshot.ObservedGeneration >= snapshot.Generation && snapshot.AvailableReplicas >= snapshot.DesiredReplicas
	satisfied := false
	detail := "workload has not reached the delegated remediation postcondition"
	switch input.Grant.Action.Kind {
	case model.ActionRestartDeployment:
		satisfied = rolloutAvailable && deployment.Spec.Template.Annotations[actionGrantAnnotation] == input.Grant.GrantID
	case model.ActionScaleDeployment:
		satisfied = rolloutAvailable && input.Grant.Action.Parameters.Replicas != nil &&
			snapshot.DesiredReplicas == *input.Grant.Action.Parameters.Replicas &&
			deployment.Annotations[actionGrantAnnotation] == input.Grant.GrantID
	}
	if satisfied {
		detail = "workload meets the exact delegated remediation postcondition"
	}
	return toolapi.GetRemediationStatusOutput{Snapshot: snapshot, Satisfied: satisfied, Detail: detail}, nil
}

func (c *Client) apply(ctx context.Context, deployment *appsv1.Deployment, grant model.DelegationGrant) (model.ResourceSnapshot, error) {
	dryRun := []string(nil)
	if grant.DryRun {
		dryRun = []string{metav1.DryRunAll}
	}
	switch grant.Action.Kind {
	case model.ActionRestartDeployment:
		patch := map[string]any{
			"metadata": map[string]string{"resourceVersion": deployment.ResourceVersion},
			"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{
				"annotations": map[string]string{
					restartTimeAnnotation: c.now().Format(time.RFC3339Nano),
					actionGrantAnnotation: grant.GrantID,
				},
			}}},
		}
		body, _ := json.Marshal(patch)
		updated, err := c.Kube.AppsV1().Deployments(c.Namespace).Patch(ctx, deployment.Name, types.MergePatchType, body, metav1.PatchOptions{DryRun: dryRun})
		if err != nil {
			return model.ResourceSnapshot{}, fmt.Errorf("restart deployment rollout: %w", err)
		}
		return resourceSnapshot(updated), nil
	case model.ActionScaleDeployment:
		patch := map[string]any{
			"metadata": map[string]any{
				"resourceVersion": deployment.ResourceVersion,
				"annotations": map[string]string{
					actionGrantAnnotation: grant.GrantID,
				},
			},
			"spec": map[string]int32{"replicas": *grant.Action.Parameters.Replicas},
		}
		body, _ := json.Marshal(patch)
		updated, err := c.Kube.AppsV1().Deployments(c.Namespace).Patch(ctx, deployment.Name, types.MergePatchType, body, metav1.PatchOptions{DryRun: dryRun})
		if err != nil {
			return model.ResourceSnapshot{}, fmt.Errorf("scale deployment: %w", err)
		}
		return resourceSnapshot(updated), nil
	default:
		return model.ResourceSnapshot{}, model.NewError(model.CodePolicyDenied, "unsupported action")
	}
}

func (c *Client) validateTarget(namespace, kind, name string) error {
	if namespace != c.Namespace {
		return model.NewError(model.CodeOutOfScope, "resource namespace is not allowed")
	}
	if kind != "Deployment" {
		return model.NewError(model.CodeOutOfScope, "only Deployment resources are supported")
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return model.NewError(model.CodeInvalidInput, "invalid Kubernetes resource name")
	}
	return nil
}

func (c *Client) now() time.Time {
	if c.Clock != nil {
		return c.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *Client) cachedReceipt(grant model.DelegationGrant) (model.ActionReceipt, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	receipt, ok := c.receipts[grant.GrantID]
	if !ok {
		return model.ActionReceipt{}, false, nil
	}
	storedGrant, ok := c.receiptGrants[grant.GrantID]
	if !ok || !sameSignedGrant(storedGrant, grant) {
		return model.ActionReceipt{}, false, model.NewError(model.CodeInvalidInput, "grant ID was reused with different signed contents")
	}
	return cloneActionReceipt(receipt), true, nil
}

func (c *Client) storeReceipt(grant model.DelegationGrant, receipt model.ActionReceipt) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.receipts == nil {
		c.receipts = make(map[string]model.ActionReceipt)
	}
	if c.receiptGrants == nil {
		c.receiptGrants = make(map[string]model.DelegationGrant)
	}
	c.receipts[receipt.GrantID] = receipt
	c.receiptGrants[receipt.GrantID] = grant
}

func sameSignedGrant(left, right model.DelegationGrant) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func valueOrZero(value *int32) int32 {
	if value == nil {
		return 0
	}
	return *value
}

func resourceSnapshot(deployment *appsv1.Deployment) model.ResourceSnapshot {
	return model.ResourceSnapshot{
		ResourceVersion: deployment.ResourceVersion, DesiredReplicas: valueOrZero(deployment.Spec.Replicas),
		ReadyReplicas: deployment.Status.ReadyReplicas, AvailableReplicas: deployment.Status.AvailableReplicas,
	}
}

func podSnapshot(pod *corev1.Pod) toolapi.PodSnapshot {
	result := toolapi.PodSnapshot{
		Name: pod.Name, Phase: string(pod.Status.Phase), Node: pod.Spec.NodeName,
		CreatedAt: pod.CreationTimestamp.Time.UTC(),
	}
	ready := len(pod.Status.ContainerStatuses) > 0
	for _, status := range pod.Status.ContainerStatuses {
		container := toolapi.ContainerSnapshot{Name: status.Name, Ready: status.Ready, RestartCount: status.RestartCount}
		ready = ready && status.Ready
		switch {
		case status.State.Waiting != nil:
			container.Reason, container.Message = status.State.Waiting.Reason, truncate(status.State.Waiting.Message, 1024)
		case status.State.Terminated != nil:
			container.Reason, container.Message = status.State.Terminated.Reason, truncate(status.State.Terminated.Message, 1024)
		}
		if status.LastTerminationState.Terminated != nil {
			container.LastReason = status.LastTerminationState.Terminated.Reason
		}
		result.Containers = append(result.Containers, container)
	}
	result.Ready = ready
	return result
}

func eventSnapshot(event *corev1.Event) toolapi.EventSnapshot {
	lastSeen := event.CreationTimestamp.Time
	if !event.LastTimestamp.IsZero() {
		lastSeen = event.LastTimestamp.Time
	} else if !event.EventTime.IsZero() {
		lastSeen = event.EventTime.Time
	}
	return toolapi.EventSnapshot{
		Type: event.Type, Reason: event.Reason, Message: truncate(event.Message, 1024),
		Object: strings.ToLower(event.InvolvedObject.Kind) + "/" + event.InvolvedObject.Name,
		Count:  event.Count, LastSeen: lastSeen.UTC(),
	}
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
