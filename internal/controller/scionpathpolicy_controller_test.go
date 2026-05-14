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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cilionv1alpha1 "github.com/martenwallewein/cilion/api/v1alpha1"
)

var _ = Describe("ScionPathPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		scionpathpolicy := &cilionv1alpha1.ScionPathPolicy{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind ScionPathPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, scionpathpolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &cilionv1alpha1.ScionPathPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &cilionv1alpha1.ScionPathPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Removing finalizer to allow deletion")
			patch := client.MergeFrom(resource.DeepCopy())
			resource.Finalizers = nil
			Expect(k8sClient.Patch(ctx, resource, patch)).To(Succeed())

			By("Cleanup the specific resource instance ScionPathPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("should add a finalizer on first reconcile", func() {
			controllerReconciler := &ScionPathPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &cilionv1alpha1.ScionPathPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(updated.Finalizers).To(ContainElement(cilionFinalizer))
		})

		It("should set the Active condition after policy injection", func() {
			controllerReconciler := &ScionPathPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// First reconcile adds the finalizer and returns early
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile proceeds to injection and sets status
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &cilionv1alpha1.ScionPathPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(apimeta.IsStatusConditionTrue(updated.Status.Conditions, "Active")).To(BeTrue())
		})

		It("should be idempotent when already active", func() {
			controllerReconciler := &ScionPathPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Run until Active condition is set
			for i := 0; i < 2; i++ {
				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
			}

			// Third reconcile should be a no-op (no EBPFManager, Active condition is True)
			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())
		})
	})
})
