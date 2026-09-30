package kubernetes

import (
	"context"
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

	mu       sync.Mutex
	receipts map[string]model.ActionReceipt
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
	return &Client{Kube: clientset, Namespace: namespace, receipts: make(map[string]model.ActionReceipt)}, nil
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

func (c *Client) ExecuteRemediation(ctx context.Context, input toolapi.ExecuteRemediationInput) (toolapi.ExecuteRemediationOutput, error) {
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
	if cached, ok := c.cachedReceipt(grant.GrantID); ok {
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
	c.storeReceipt(receipt)
	if c.Audit != nil {
		_ = c.Audit.Record(ctx, model.AuditEvent{
			ID: receipt.AuditRef, IncidentID: grant.IncidentID, Actor: model.AgentMCPAction,
			Operation: string(grant.Action.Kind), Decision: string(outcome),
			SideEffect: outcome == model.ActionSucceeded, OccurredAt: completed,
		})
	}
	return toolapi.ExecuteRemediationOutput{Receipt: receipt}, nil
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
		satisfied = rolloutAvailable && deployment.Spec.Template.Annotations["aegissre.io/grant-id"] == input.Grant.GrantID
	case model.ActionScaleDeployment:
		satisfied = rolloutAvailable && input.Grant.Action.Parameters.Replicas != nil &&
			snapshot.DesiredReplicas == *input.Grant.Action.Parameters.Replicas &&
			deployment.Annotations["aegissre.io/grant-id"] == input.Grant.GrantID
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
					"aegissre.io/restarted-at": c.now().Format(time.RFC3339Nano),
					"aegissre.io/grant-id":     grant.GrantID,
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
					"aegissre.io/grant-id": grant.GrantID,
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

func (c *Client) cachedReceipt(grantID string) (model.ActionReceipt, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	receipt, ok := c.receipts[grantID]
	return receipt, ok
}

func (c *Client) storeReceipt(receipt model.ActionReceipt) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.receipts == nil {
		c.receipts = make(map[string]model.ActionReceipt)
	}
	c.receipts[receipt.GrantID] = receipt
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
