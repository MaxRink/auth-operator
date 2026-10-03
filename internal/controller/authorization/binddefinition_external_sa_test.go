// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/rand"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/helpers"
)

// saWriteCounter counts every mutating client call that targets a ServiceAccount.
type saWriteCounter struct {
	mu     sync.Mutex
	writes []string
}

func (c *saWriteCounter) record(verb string, obj any) {
	key := ""
	switch o := obj.(type) {
	case *corev1.ServiceAccount:
		key = o.Namespace + "/" + o.Name
	case *corev1ac.ServiceAccountApplyConfiguration:
		key = ptr.Deref(o.Namespace, "") + "/" + ptr.Deref(o.Name, "")
	default:
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, verb+" "+key)
}

func (c *saWriteCounter) get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.writes...)
}

// newSAWriteCountingClient wraps k8sClient and records every ServiceAccount write.
func newSAWriteCountingClient(base client.WithWatch) (client.WithWatch, *saWriteCounter) {
	counter := &saWriteCounter{}
	wrapped := interceptor.NewClient(base, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			counter.record("create", obj)
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			counter.record("update", obj)
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			counter.record("patch", obj)
			return c.Patch(ctx, obj, patch, opts...)
		},
		Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			counter.record("apply", obj)
			return c.Apply(ctx, obj, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			counter.record("delete", obj)
			return c.Delete(ctx, obj, opts...)
		},
	})
	return wrapped, counter
}

var _ = Describe("BindDefinition explicitly external ServiceAccounts with competing managers", func() {
	const (
		providerManager = "provider-controller"
		labelManager    = "label-bot"
		providerSAName  = "provider-sa"
	)

	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	newReconciler := func(c client.Client) (*BindDefinitionReconciler, *events.FakeRecorder) {
		rec := events.NewFakeRecorder(200)
		return &BindDefinitionReconciler{client: c, scheme: k8sClient.Scheme(), recorder: rec}, rec
	}

	reconcileBD := func(r *BindDefinitionReconciler, name string) *authorizationv1alpha1.BindDefinition {
		GinkgoHelper()
		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))
		bd := &authorizationv1alpha1.BindDefinition{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, bd)).To(Succeed())
		return bd
	}

	drainEvents := func(rec *events.FakeRecorder) []string {
		var out []string
		for {
			select {
			case e := <-rec.Events:
				out = append(out, e)
			default:
				return out
			}
		}
	}

	expectReady := func(bd *authorizationv1alpha1.BindDefinition) {
		GinkgoHelper()
		Expect(conditions.IsReady(bd)).To(BeTrue(), "conditions: %+v", bd.Status.Conditions)
		Expect(bd.Status.BindReconciled).To(BeTrue())
		Expect(bd.Status.ObservedGeneration).To(Equal(bd.Generation))
		Expect(conditions.IsStalled(bd)).To(BeFalse())
		Expect(conditions.IsReconciling(bd)).To(BeFalse())
	}

	expectSARefs := func(bd *authorizationv1alpha1.BindDefinition, ready bool, skipped ...string) {
		GinkgoHelper()
		cond := conditions.Get(bd, authorizationv1alpha1.ServiceAccountRefsReadyCondition)
		Expect(cond).NotTo(BeNil())
		Expect(cond.ObservedGeneration).To(Equal(bd.Generation))
		if ready {
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal(string(authorizationv1alpha1.ServiceAccountRefsReadyReason)))
			Expect(bd.Status.SkippedServiceAccounts).To(BeEmpty())
			return
		}
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal(string(authorizationv1alpha1.ServiceAccountRefsSkippedReason)))
		Expect(bd.Status.SkippedServiceAccounts).To(ConsistOf(skipped))
		for _, s := range skipped {
			Expect(cond.Message).To(ContainSubstring(s))
		}
	}

	expectBindingsContain := func(crbName, rbNamespace, rbName string, subject rbacv1.Subject) (string, string) {
		GinkgoHelper()
		crb := &rbacv1.ClusterRoleBinding{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: crbName}, crb)).To(Succeed())
		Expect(crb.Subjects).To(ContainElement(subject))
		rb := &rbacv1.RoleBinding{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: rbNamespace, Name: rbName}, rb)).To(Succeed())
		Expect(rb.Subjects).To(ContainElement(subject))
		return crb.ResourceVersion, rb.ResourceVersion
	}

	providerApply := func(namespace string, labels map[string]string, owner *corev1.ConfigMap) {
		GinkgoHelper()
		ac := corev1ac.ServiceAccount(providerSAName, namespace).WithLabels(labels)
		if owner != nil {
			ac.WithOwnerReferences(metav1ac.OwnerReference().
				WithAPIVersion("v1").WithKind("ConfigMap").WithName(owner.Name).WithUID(owner.UID))
		}
		Expect(k8sClient.Apply(ctx, ac, client.FieldOwner(providerManager), client.ForceOwnership)).To(Succeed())
	}

	managersOf := func(sa *corev1.ServiceAccount) []string {
		managers := make([]string, 0, len(sa.ManagedFields))
		for _, mf := range sa.ManagedFields {
			managers = append(managers, mf.Manager)
		}
		return managers
	}

	createClusterRole := func(name string) {
		GinkgoHelper()
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}}))).To(Succeed())
	}

	createNamespace := func(name string) {
		GinkgoHelper()
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})).To(Succeed())
	}

	newBD := func(name, targetName, roleName, targetNS string, subject rbacv1.Subject, external bool) *authorizationv1alpha1.BindDefinition {
		bd := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName:          targetName,
				Subjects:            []rbacv1.Subject{subject},
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{roleName}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{{
					Namespace: targetNS, ClusterRoleRefs: []string{roleName},
				}},
			},
		}
		if external {
			bd.Spec.ExternalServiceAccountRefs = []authorizationv1alpha1.SARef{{Name: subject.Name, Namespace: subject.Namespace}}
		}
		Expect(k8sClient.Create(ctx, bd)).To(Succeed())
		DeferCleanup(func() {
			current := &authorizationv1alpha1.BindDefinition{}
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, current); err != nil {
				return
			}
			current.Finalizers = nil
			_ = k8sClient.Update(ctx, current)
			_ = client.IgnoreNotFound(k8sClient.Delete(ctx, current))
		})
		return bd
	}

	It("stays Ready while a provider creates, relabels, deletes and recreates the ServiceAccount, without writing to it", func() {
		suffix := rand.String(6)
		providerNS := "ext-provider-" + suffix
		targetNS := "ext-target-" + suffix
		roleName := "ext-view-" + suffix
		targetName := "ext-" + suffix
		subject := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: providerSAName, Namespace: providerNS}
		saKey := client.ObjectKey{Namespace: providerNS, Name: providerSAName}
		crbName := targetName + "-" + roleName + "-binding"
		rbName := targetName + "-" + roleName + "-binding"
		createClusterRole(roleName)
		createNamespace(targetNS)
		bd := newBD("ext-lifecycle-"+suffix, targetName, roleName, targetNS, subject, true)

		c, counter := newSAWriteCountingClient(k8sClient)
		r, rec := newReconciler(c)

		By("binding the subject before its namespace exists")
		updated := reconcileBD(r, bd.Name)
		expectReady(updated)
		expectSARefs(updated, false, fmt.Sprintf("%s/%s: namespace unavailable (creation opted out)", providerNS, providerSAName))
		Expect(updated.Status.ExternalServiceAccounts).To(BeEmpty())
		expectBindingsContain(crbName, targetNS, rbName, subject)
		Expect(drainEvents(rec)).To(ContainElement(ContainSubstring(authorizationv1alpha1.EventReasonServiceAccountSkipped)))

		By("observing the namespace created concurrently by the provider, still without the ServiceAccount")
		createNamespace(providerNS)
		updated = reconcileBD(r, bd.Name)
		expectReady(updated)
		expectSARefs(updated, false, fmt.Sprintf("%s/%s: not found (creation opted out)", providerNS, providerSAName))
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, saKey, &corev1.ServiceAccount{}))).To(BeTrue(),
			"the operator must never create an explicitly external ServiceAccount")

		By("the provider creating the ServiceAccount with its own labels and ownerReferences")
		owner := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "provider-owner", Namespace: providerNS}}
		Expect(k8sClient.Create(ctx, owner)).To(Succeed())
		providerLabels := map[string]string{"app.kubernetes.io/managed-by": "provider", "tier": "system"}
		providerApply(providerNS, providerLabels, owner)
		updated = reconcileBD(r, bd.Name)
		expectReady(updated)
		expectSARefs(updated, true)
		Expect(updated.Status.ExternalServiceAccounts).To(ConsistOf(providerNS + "/" + providerSAName))
		Expect(updated.Status.GeneratedServiceAccounts).To(BeEmpty())

		sa := &corev1.ServiceAccount{}
		Expect(k8sClient.Get(ctx, saKey, sa)).To(Succeed())
		Expect(sa.Labels).To(Equal(providerLabels))
		Expect(sa.OwnerReferences).To(HaveLen(1))
		Expect(sa.OwnerReferences[0].UID).To(Equal(owner.UID))
		Expect(sa.Annotations).NotTo(HaveKey(helpers.SourceNamesAnnotation))
		Expect(sa.Annotations).NotTo(HaveKey(authorizationv1alpha1.AnnotationKeyReferencedBy))
		Expect(managersOf(sa)).To(ConsistOf(providerManager))

		By("repeated reconciles converging without writing anything")
		crbRV, rbRV := expectBindingsContain(crbName, targetNS, rbName, subject)
		saRV := sa.ResourceVersion
		bdRV := updated.ResourceVersion
		for range 3 {
			updated = reconcileBD(r, bd.Name)
			expectReady(updated)
			expectSARefs(updated, true)
		}
		Expect(updated.ResourceVersion).To(Equal(bdRV), "steady-state status must not be rewritten")
		Expect(k8sClient.Get(ctx, saKey, sa)).To(Succeed())
		Expect(sa.ResourceVersion).To(Equal(saRV))
		newCRBRV, newRBRV := expectBindingsContain(crbName, targetNS, rbName, subject)
		Expect(newCRBRV).To(Equal(crbRV))
		Expect(newRBRV).To(Equal(rbRV))

		By("the provider relabeling and a second manager adding labels")
		Expect(k8sClient.Apply(ctx, corev1ac.ServiceAccount(providerSAName, providerNS).WithLabels(map[string]string{"team": "platform"}),
			client.FieldOwner(labelManager))).To(Succeed())
		providerApply(providerNS, map[string]string{"app.kubernetes.io/managed-by": "provider", "version": "v2"}, owner)
		updated = reconcileBD(r, bd.Name)
		expectReady(updated)
		expectSARefs(updated, true)
		Expect(k8sClient.Get(ctx, saKey, sa)).To(Succeed())
		Expect(sa.Labels).To(Equal(map[string]string{
			"app.kubernetes.io/managed-by": "provider", "version": "v2", "team": "platform",
		}))
		Expect(sa.OwnerReferences).To(HaveLen(1))
		Expect(managersOf(sa)).To(ConsistOf(providerManager, labelManager))

		By("the provider deleting the ServiceAccount")
		Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
		drainEvents(rec)
		updated = reconcileBD(r, bd.Name)
		expectReady(updated)
		expectSARefs(updated, false, fmt.Sprintf("%s/%s: not found (creation opted out)", providerNS, providerSAName))
		Expect(updated.Status.ExternalServiceAccounts).To(BeEmpty())
		Expect(drainEvents(rec)).To(ContainElement(SatisfyAll(
			ContainSubstring(corev1.EventTypeWarning),
			ContainSubstring(authorizationv1alpha1.EventReasonServiceAccountSkipped))))
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, saKey, &corev1.ServiceAccount{}))).To(BeTrue())
		newCRBRV, newRBRV = expectBindingsContain(crbName, targetNS, rbName, subject)
		Expect(newCRBRV).To(Equal(crbRV), "bindings must survive deletion of the external subject untouched")
		Expect(newRBRV).To(Equal(rbRV))

		By("the provider recreating the ServiceAccount")
		providerApply(providerNS, providerLabels, owner)
		updated = reconcileBD(r, bd.Name)
		expectReady(updated)
		expectSARefs(updated, true)
		Expect(updated.Status.ExternalServiceAccounts).To(ConsistOf(providerNS + "/" + providerSAName))

		Expect(counter.get()).To(BeEmpty(), "the operator must never write an explicitly external ServiceAccount")
	})

	It("reports a terminating ServiceAccount namespace without blocking readiness", func() {
		suffix := rand.String(6)
		providerNS := "ext-term-" + suffix
		targetNS := "ext-term-target-" + suffix
		roleName := "ext-term-view-" + suffix
		targetName := "ext-term-" + suffix
		subject := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: providerSAName, Namespace: providerNS}
		createClusterRole(roleName)
		createNamespace(targetNS)
		createNamespace(providerNS)
		providerApply(providerNS, map[string]string{"app": "provider"}, nil)
		bd := newBD("ext-term-"+suffix, targetName, roleName, targetNS, subject, true)

		c, counter := newSAWriteCountingClient(k8sClient)
		r, _ := newReconciler(c)
		updated := reconcileBD(r, bd.Name)
		expectReady(updated)
		expectSARefs(updated, true)

		By("deleting the provider namespace (envtest keeps it Terminating)")
		Expect(k8sClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: providerNS}})).To(Succeed())
		Eventually(func(g Gomega) {
			ns := &corev1.Namespace{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: providerNS}, ns)).To(Succeed())
			g.Expect(conditions.IsNamespaceTerminating(ns)).To(BeTrue())
		}).Should(Succeed())

		updated = reconcileBD(r, bd.Name)
		expectReady(updated)
		expectSARefs(updated, false, fmt.Sprintf("%s/%s: namespace unavailable (creation opted out)", providerNS, providerSAName))
		Expect(updated.Status.ExternalServiceAccounts).To(BeEmpty())
		expectBindingsContain(targetName+"-"+roleName+"-binding", targetNS, targetName+"-"+roleName+"-binding", subject)
		Expect(counter.get()).To(BeEmpty())
	})

	It("lets two BindDefinitions delegate the same missing ServiceAccount and converge when it appears", func() {
		suffix := rand.String(6)
		providerNS := "ext-two-" + suffix
		targetNS := "ext-two-target-" + suffix
		roleName := "ext-two-view-" + suffix
		subject := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: providerSAName, Namespace: providerNS}
		createClusterRole(roleName)
		createNamespace(targetNS)
		createNamespace(providerNS)
		bdA := newBD("ext-two-a-"+suffix, "ext-two-a-"+suffix, roleName, targetNS, subject, true)
		bdB := newBD("ext-two-b-"+suffix, "ext-two-b-"+suffix, roleName, targetNS, subject, true)

		c, counter := newSAWriteCountingClient(k8sClient)
		r, _ := newReconciler(c)
		missing := fmt.Sprintf("%s/%s: not found (creation opted out)", providerNS, providerSAName)
		for _, name := range []string{bdA.Name, bdB.Name} {
			updated := reconcileBD(r, name)
			expectReady(updated)
			expectSARefs(updated, false, missing)
		}

		providerLabels := map[string]string{"app": "provider"}
		providerApply(providerNS, providerLabels, nil)
		for range 2 {
			for _, name := range []string{bdA.Name, bdB.Name, bdA.Name} {
				updated := reconcileBD(r, name)
				expectReady(updated)
				expectSARefs(updated, true)
				Expect(updated.Status.ExternalServiceAccounts).To(ConsistOf(providerNS + "/" + providerSAName))
			}
		}
		sa := &corev1.ServiceAccount{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: providerNS, Name: providerSAName}, sa)).To(Succeed())
		Expect(sa.Labels).To(Equal(providerLabels))
		Expect(sa.OwnerReferences).To(BeEmpty())
		Expect(managersOf(sa)).To(ConsistOf(providerManager))
		Expect(counter.get()).To(BeEmpty())
	})

	It("does not fight a BindDefinition that manages the ServiceAccount another BindDefinition marks external", func() {
		suffix := rand.String(6)
		saNS := "ext-mixed-" + suffix
		targetNS := "ext-mixed-target-" + suffix
		roleName := "ext-mixed-view-" + suffix
		subject := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: providerSAName, Namespace: saNS}
		saKey := client.ObjectKey{Namespace: saNS, Name: providerSAName}
		createClusterRole(roleName)
		createNamespace(targetNS)
		createNamespace(saNS)
		managed := newBD("ext-mixed-managed-"+suffix, "ext-mixed-m-"+suffix, roleName, targetNS, subject, false)
		external := newBD("ext-mixed-external-"+suffix, "ext-mixed-e-"+suffix, roleName, targetNS, subject, true)

		managedReconciler, _ := newReconciler(k8sClient)
		externalClient, externalCounter := newSAWriteCountingClient(k8sClient)
		externalReconciler, _ := newReconciler(externalClient)

		By("the managing BindDefinition creating the ServiceAccount")
		updatedManaged := reconcileBD(managedReconciler, managed.Name)
		expectReady(updatedManaged)
		expectSARefs(updatedManaged, true)
		Expect(updatedManaged.Status.GeneratedServiceAccounts).To(ConsistOf(subject))
		Expect(k8sClient.Apply(ctx, corev1ac.ServiceAccount(providerSAName, saNS).WithLabels(map[string]string{"team": "platform"}),
			client.FieldOwner(labelManager))).To(Succeed())

		By("alternating reconciles of both BindDefinitions")
		var saRV string
		for i := range 3 {
			updatedManaged = reconcileBD(managedReconciler, managed.Name)
			expectReady(updatedManaged)
			updatedExternal := reconcileBD(externalReconciler, external.Name)
			expectReady(updatedExternal)
			expectSARefs(updatedExternal, true)
			Expect(updatedExternal.Status.ExternalServiceAccounts).To(ConsistOf(saNS + "/" + providerSAName))
			Expect(updatedExternal.Status.GeneratedServiceAccounts).To(BeEmpty())

			sa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, saKey, sa)).To(Succeed())
			Expect(sa.Labels).To(HaveKeyWithValue("team", "platform"))
			Expect(sa.OwnerReferences).To(HaveLen(1))
			Expect(sa.OwnerReferences[0].UID).To(Equal(updatedManaged.UID))
			Expect(strings.Split(sa.Annotations[helpers.SourceNamesAnnotation], ",")).NotTo(ContainElement(external.Name))
			if i == 0 {
				saRV = sa.ResourceVersion
			} else {
				Expect(sa.ResourceVersion).To(Equal(saRV), "managers must not keep rewriting the shared ServiceAccount")
			}
		}
		Expect(externalCounter.get()).To(BeEmpty(), "the delegating BindDefinition must not write a ServiceAccount it does not own")
	})

	It("preserves labels and ownerReferences contributed by other managers on an operator-owned ServiceAccount", func() {
		suffix := rand.String(6)
		saNS := "owned-sa-" + suffix
		targetNS := "owned-sa-target-" + suffix
		roleName := "owned-sa-view-" + suffix
		subject := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: providerSAName, Namespace: saNS}
		saKey := client.ObjectKey{Namespace: saNS, Name: providerSAName}
		createClusterRole(roleName)
		createNamespace(targetNS)
		createNamespace(saNS)
		bd := newBD("owned-sa-"+suffix, "owned-sa-"+suffix, roleName, targetNS, subject, false)
		r, _ := newReconciler(k8sClient)

		updated := reconcileBD(r, bd.Name)
		expectReady(updated)
		expectSARefs(updated, true)
		Expect(updated.Status.GeneratedServiceAccounts).To(ConsistOf(subject))

		By("other managers adding a label and an additional ownerReference")
		Expect(k8sClient.Apply(ctx, corev1ac.ServiceAccount(providerSAName, saNS).WithLabels(map[string]string{"team": "platform"}),
			client.FieldOwner(labelManager))).To(Succeed())
		owner := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "extra-owner", Namespace: saNS}}
		Expect(k8sClient.Create(ctx, owner)).To(Succeed())
		Expect(k8sClient.Apply(ctx, corev1ac.ServiceAccount(providerSAName, saNS).WithOwnerReferences(
			metav1ac.OwnerReference().WithAPIVersion("v1").WithKind("ConfigMap").WithName(owner.Name).WithUID(owner.UID)),
			client.FieldOwner(providerManager))).To(Succeed())

		var saRV string
		for i := range 3 {
			updated = reconcileBD(r, bd.Name)
			expectReady(updated)
			expectSARefs(updated, true)
			Expect(updated.Status.GeneratedServiceAccounts).To(ConsistOf(subject))
			Expect(conditions.Get(updated, authorizationv1alpha1.ServiceAccountOwnershipTransferredCondition)).To(BeNil())

			sa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, saKey, sa)).To(Succeed())
			Expect(sa.Labels).To(HaveKeyWithValue("team", "platform"))
			ownerUIDs := make([]string, 0, len(sa.OwnerReferences))
			for _, ref := range sa.OwnerReferences {
				ownerUIDs = append(ownerUIDs, string(ref.UID))
			}
			Expect(ownerUIDs).To(ConsistOf(string(updated.UID), string(owner.UID)))
			Expect(managersOf(sa)).To(ContainElements(labelManager, providerManager))
			if i == 0 {
				saRV = sa.ResourceVersion
			} else {
				Expect(sa.ResourceVersion).To(Equal(saRV), "the operator must not fight other field managers")
			}
		}
	})
})
