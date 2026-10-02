package kubernetes

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

func TestResolvePodDeploymentVerifiesLiveOwnerUIDChain(t *testing.T) {
	t.Parallel()
	controller := true
	deploymentUID := types.UID("deployment-uid")
	replicaSetUID := types.UID("replicaset-uid")
	client := &Client{
		Namespace: "outage-arena",
		Kube: fake.NewSimpleClientset(
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "demo-api", Namespace: "outage-arena", UID: deploymentUID}},
			&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
				Name: "demo-api-rs", Namespace: "outage-arena", UID: replicaSetUID,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "Deployment", Name: "demo-api", UID: deploymentUID, Controller: &controller,
				}},
			}},
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "demo-api-pod", Namespace: "outage-arena",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "demo-api-rs", UID: replicaSetUID, Controller: &controller,
				}},
			}},
		),
	}
	want := model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api"}
	got, err := client.ResolvePodDeployment(context.Background(), "outage-arena", "demo-api-pod")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("owner = %#v, want %#v", got, want)
	}
}

func TestResolvePodDeploymentRejectsStaleOrIncompleteOwnerChain(t *testing.T) {
	t.Parallel()
	controller := true
	for name, pod := range map[string]*corev1.Pod{
		"direct-deployment-owner": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "direct", Namespace: "outage-arena",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "Deployment", Name: "demo-api", UID: "deployment-uid", Controller: &controller,
				}},
			},
		},
		"stale-replicaset-uid": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "stale", Namespace: "outage-arena",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "demo-api-rs", UID: "old-uid", Controller: &controller,
				}},
			},
		},
	} {
		name, pod := name, pod
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := &Client{
				Namespace: "outage-arena",
				Kube: fake.NewSimpleClientset(
					&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "demo-api", Namespace: "outage-arena", UID: "deployment-uid"}},
					&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
						Name: "demo-api-rs", Namespace: "outage-arena", UID: "new-uid",
						OwnerReferences: []metav1.OwnerReference{{
							APIVersion: "apps/v1", Kind: "Deployment", Name: "demo-api", UID: "deployment-uid", Controller: &controller,
						}},
					}},
					pod,
				),
			}
			_, err := client.ResolvePodDeployment(context.Background(), "outage-arena", pod.Name)
			if err == nil {
				t.Fatal("untrusted owner chain was accepted")
			}
			code, ok := model.ErrorCodeOf(err)
			if !ok || code != model.CodeOutOfScope {
				t.Fatalf("error = %v, code = %q", err, code)
			}
		})
	}
}
