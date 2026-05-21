/*
Copyright 2026.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cilionv1alpha1 "github.com/martenwallewein/cilion/api/v1alpha1"
)

const (
	cilionFinalizer   = "cilion.io/policy-finalizer"
	defaultPolicyName = "default-scion-policy"
)

// ScionClient communicates with the global SCION Control Service.
type ScionClient interface {
	// FetchPath now takes a destination AS and preference, returning the raw eBPF bytes and NextHop.
	FetchPath(destinationAS string, preference string) (isReady bool, rawHopFields []byte, nextHopIP string, err error)
}

// ScionPathPolicyReconciler reconciles a ScionPathPolicy object into ScionComputedPaths.
// Notice: There is NO EBPFManager here. This is purely Control Plane logic.
type ScionPathPolicyReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ScionClient ScionClient
}

// +kubebuilder:rbac:groups=cilion.cilion.io,resources=scionpathpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cilion.cilion.io,resources=scioncomputedpaths,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cilion.cilion.io,resources=scionclusterpeers,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

func (r *ScionPathPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("policy", req.Name)

	// 1. Fetch the User Intent (ScionPathPolicy)
	var policy cilionv1alpha1.ScionPathPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Handle Deletion (Cleanup external SCION reservations if necessary)
	if !policy.ObjectMeta.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&policy, cilionFinalizer) {
			// Note: We don't need to manually delete ScionComputedPaths here
			// because we use Kubernetes OwnerReferences. K8s Garbage Collection will drop them automatically!
			controllerutil.RemoveFinalizer(&policy, cilionFinalizer)
			if err := r.Update(ctx, &policy); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(&policy, cilionFinalizer) {
		controllerutil.AddFinalizer(&policy, cilionFinalizer)
		if err := r.Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// 3. Fetch all known remote clusters (Destinations)
	var peers cilionv1alpha1.ScionClusterPeerList
	if err := r.List(ctx, &peers); err != nil {
		log.Error(err, "Failed to list ScionClusterPeers")
		return ctrl.Result{}, err
	}

	// 4. Compute Paths for EACH destination cluster
	allPathsReady := true

	for _, peer := range peers.Items {
		// Contact the SCION daemon to get the cryptographic path for this specific destination
		isReady, rawHopFields, nextHopIP, err := r.ScionClient.FetchPath(peer.Spec.RemoteAS, *policy.Spec.Preference)
		if err != nil {
			log.Error(err, "Failed to fetch path from SCION Control Service", "destination", peer.Spec.RemoteAS)
			return ctrl.Result{}, err
		}

		if !isReady {
			log.Info("SCION path not ready yet", "destination", peer.Spec.RemoteAS)
			allPathsReady = false
			continue // Check the other peers, but we will requeue at the end
		}

		// 5. INTENT -> STATE: Generate the ScionComputedPath CRD for the Local Agents
		computedPathName := fmt.Sprintf("%s-to-%s", policy.Name, peer.Name)
		computedPath := &cilionv1alpha1.ScionComputedPath{
			ObjectMeta: metav1.ObjectMeta{
				Name:      computedPathName,
				Namespace: policy.Namespace,
			},
		}

		// CreateOrUpdate ensures Idempotency. It creates the CRD if it doesn't exist,
		// or updates it if the SCION path has rotated/changed.
		_, err = controllerutil.CreateOrUpdate(ctx, r.Client, computedPath, func() error {
			// Link the lifecycle to the parent Policy
			if err := controllerutil.SetControllerReference(&policy, computedPath, r.Scheme); err != nil {
				return err
			}
			computedPath.Spec.PolicyRef = policy.Name
			computedPath.Spec.DestinationCIDR = peer.Spec.PodCIDR
			computedPath.Spec.NextHopIP = nextHopIP
			computedPath.Spec.HopFields = rawHopFields
			return nil
		})

		if err != nil {
			log.Error(err, "Failed to create/update ScionComputedPath", "computedPath", computedPathName)
			return ctrl.Result{}, err
		}
		log.Info("Successfully generated ScionComputedPath", "destination", peer.Name)
	}

	// 6. Graceful Requeue if any destination paths were missing
	if !allPathsReady {
		log.Info("Some destination paths were not ready. Requeueing...")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// 7. Update Status on the user's Policy CRD
	apimeta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "PathsComputed",
		Message:            fmt.Sprintf("Computed paths for %d destinations", len(peers.Items)),
		ObservedGeneration: policy.Generation,
	})
	if err := r.Status().Update(ctx, &policy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager wires up the event watches.
func (r *ScionPathPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// Predicate: Only wake up if a Pod is newly assigned an IP by Cilium
	podIPAssignedPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPod, okOld := e.ObjectOld.(*corev1.Pod)
			newPod, okNew := e.ObjectNew.(*corev1.Pod)
			if !okOld || !okNew {
				return false
			}
			// Trigger when the Pod transitions from having no IP to having one
			return oldPod.Status.PodIP == "" && newPod.Status.PodIP != ""
		},
		CreateFunc: func(e event.CreateEvent) bool {
			pod, ok := e.Object.(*corev1.Pod)
			return ok && pod.Status.PodIP != ""
		},
	}

	// MapFunc: When a Pod gets an IP, which Policy should we reconcile?
	// This ensures the Global Controller computes a path for the pod's default or matched policy.
	podToPolicyMapper := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return nil
		}

		// List all ScionPathPolicies in the pod's namespace
		var policies cilionv1alpha1.ScionPathPolicyList
		r.Client.List(ctx, &policies, client.InNamespace(pod.Namespace))

		var requests []reconcile.Request
		hasSpecificPolicy := false

		// Inside your podToPolicyMapper:
		for _, p := range policies.Items {
			// Convert the CRD's LabelSelector to a real K8s Selector
			selector, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
			if err != nil {
				continue
			}

			// Check if the Pod's labels match the Policy's selector
			if selector.Matches(labels.Set(pod.Labels)) {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: p.Name, Namespace: p.Namespace},
				})
				hasSpecificPolicy = true
			}
		}

		// If the Pod doesn't match any specific App-Aware policy, enqueue the Default Policy
		if !hasSpecificPolicy {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: defaultPolicyName, Namespace: "kube-system"},
			})
		}

		return requests
	})

	return ctrl.NewControllerManagedBy(mgr).
		// 1. Watch User Intent Policies
		For(&cilionv1alpha1.ScionPathPolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// 2. Watch Pod IP Assignments to ensure policies are proactively computed
		Watches(
			&corev1.Pod{},
			podToPolicyMapper,
			builder.WithPredicates(podIPAssignedPredicate),
		).
		// 3. Watch Remote Destinations (if a new cluster is added, recalculate all policies!)
		Watches(
			&cilionv1alpha1.ScionClusterPeer{},
			&handler.EnqueueRequestForObject{},
		).
		Named("global-scion-policy-controller").
		Complete(r)

	return nil
}
