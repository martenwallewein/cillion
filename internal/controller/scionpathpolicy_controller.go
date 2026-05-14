/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	cilionv1alpha1 "github.com/martenwallewein/cilion/api/v1alpha1"
)

const cilionFinalizer = "cilion.io/finalizer"

// EBPFManager handles eBPF map operations for SCION path policies.
type EBPFManager interface {
	CheckIfPolicyExists(name string) bool
	InjectPolicy(spec cilionv1alpha1.ScionPathPolicySpec) error
	RemovePolicy(name string) error
}

// ScionClient communicates with the SCION Control Service.
type ScionClient interface {
	FetchPath(preference string) (bool, error)
}

// ScionPathPolicyReconciler reconciles a ScionPathPolicy object
type ScionPathPolicyReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	EBPFManager EBPFManager
	ScionClient ScionClient
}

// +kubebuilder:rbac:groups=cilion.cilion.io,resources=scionpathpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cilion.cilion.io,resources=scionpathpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cilion.cilion.io,resources=scionpathpolicies/finalizers,verbs=update

func (r *ScionPathPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// 1. Fetch the Custom Resource (reads from cache — level-triggered)
	var policy cilionv1alpha1.ScionPathPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Handle deletion: run cleanup logic and remove finalizer
	if !policy.ObjectMeta.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&policy, cilionFinalizer) {
			if r.EBPFManager != nil {
				if err := r.EBPFManager.RemovePolicy(policy.Name); err != nil {
					log.Error(err, "Failed to remove policy from eBPF datapath", "name", policy.Name)
					return ctrl.Result{}, err
				}
			}
			controllerutil.RemoveFinalizer(&policy, cilionFinalizer)
			if err := r.Update(ctx, &policy); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// 3. Add finalizer on first reconcile so cleanup runs on deletion
	if !controllerutil.ContainsFinalizer(&policy, cilionFinalizer) {
		controllerutil.AddFinalizer(&policy, cilionFinalizer)
		if err := r.Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		// Return so the update triggers a new reconciliation with the finalizer in place
		return ctrl.Result{}, nil
	}

	// 4. Idempotency check: skip injection if eBPF datapath already matches desired state
	isPolicyActive := false
	if r.EBPFManager != nil {
		isPolicyActive = r.EBPFManager.CheckIfPolicyExists(policy.Name)
	}
	if isPolicyActive && apimeta.IsStatusConditionTrue(policy.Status.Conditions, "Active") {
		log.Info("Policy already active in eBPF datapath, no action needed")
		return ctrl.Result{}, nil
	}

	// 5. Graceful requeue: wait for SCION path without triggering exponential backoff
	if r.ScionClient != nil {
		scionPathReady, err := r.ScionClient.FetchPath(*policy.Spec.Preference)
		if err != nil {
			log.Error(err, "Failed to contact SCION Control Service")
			return ctrl.Result{}, err
		}
		if !scionPathReady {
			log.Info("SCION path not ready, requeueing")
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
	}

	// 6. Apply desired state to eBPF datapath
	if r.EBPFManager != nil {
		if err := r.EBPFManager.InjectPolicy(policy.Spec); err != nil {
			log.Error(err, "Failed to inject policy into eBPF datapath")
			return ctrl.Result{}, err
		}
	}
	log.Info("Injected policy into eBPF datapath", "name", policy.Name)

	// 7. Update status separately — never modify Spec here
	apimeta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               "Active",
		Status:             metav1.ConditionTrue,
		Reason:             "PolicyInjected",
		Message:            "Policy is active in the eBPF datapath",
		ObservedGeneration: policy.Generation,
	})
	if err := r.Status().Update(ctx, &policy); err != nil {
		log.Error(err, "Failed to update ScionPathPolicy status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ScionPathPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Only reconcile on Spec changes (generation bump), not Status-only updates
	podLabelChangedPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPod, okOld := e.ObjectOld.(*corev1.Pod)
			newPod, okNew := e.ObjectNew.(*corev1.Pod)
			if !okOld || !okNew {
				return false
			}
			return !reflect.DeepEqual(oldPod.Labels, newPod.Labels)
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&cilionv1alpha1.ScionPathPolicy{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Pod{},
			&handler.EnqueueRequestForObject{},
			builder.WithPredicates(podLabelChangedPredicate)).
		Named("scionpathpolicy").
		Complete(r)
}
