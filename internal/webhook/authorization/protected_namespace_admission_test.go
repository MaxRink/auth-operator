package webhooks_test

import (
	"context"
	"testing"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	webhooks "github.com/telekom/auth-operator/internal/webhook/authorization"
	"github.com/telekom/auth-operator/pkg/indexer"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	crAdmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// TestProtectedNamespaceAdmissionLifecycle exercises the real namespace
// validator handler for all namespace operations. In particular, CREATE must
// evaluate the protected label submitted in the request, while UPDATE and
// DELETE must authorize against the existing classification and prevent
// ordinary identities from changing it.
func TestProtectedNamespaceAdmissionLifecycle(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))

	ordinary := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ordinary-namespace-access"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "ordinary-namespace-access",
			Subjects: []rbacv1.Subject{{
				APIGroup: rbacv1.GroupName,
				Kind:     rbacv1.GroupKind,
				Name:     "oidc:tenant-powerusers",
			}},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"tenant-poweruser"},
				NamespaceSelector: []metav1.LabelSelector{{
					MatchLabels: map[string]string{
						authorizationv1alpha1.LabelKeyOwner:  "tenant",
						authorizationv1alpha1.LabelKeyTenant: "tenant-a",
					},
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      authorizationv1alpha1.LabelKeyProtected,
						Operator: metav1.LabelSelectorOpDoesNotExist,
					}},
				}},
			}},
		},
	}
	protected := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "protected-namespace-access"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "protected-namespace-access",
			Subjects: []rbacv1.Subject{{
				APIGroup: rbacv1.GroupName,
				Kind:     rbacv1.GroupKind,
				Name:     "oidc:tenant-protected-powerusers",
			}},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"tenant-protected"},
				NamespaceSelector: []metav1.LabelSelector{{
					MatchLabels: map[string]string{
						authorizationv1alpha1.LabelKeyOwner:     "tenant",
						authorizationv1alpha1.LabelKeyTenant:    "tenant-a",
						authorizationv1alpha1.LabelKeyProtected: "tenant-a",
					},
				}},
			}},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&authorizationv1alpha1.BindDefinition{}, indexer.BindDefinitionHasRoleBindingsField, indexer.BindDefinitionHasRoleBindingsFunc).
		WithObjects(ordinary, protected).
		Build()
	validator := &webhooks.NamespaceValidator{
		Client:  c,
		Reader:  c,
		Decoder: crAdmission.NewDecoder(scheme),
	}

	ordinaryNS := func(name string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
			authorizationv1alpha1.LabelKeyOwner:  "tenant",
			authorizationv1alpha1.LabelKeyTenant: "tenant-a",
		}}}
	}
	protectedNS := func(name string) *corev1.Namespace {
		ns := ordinaryNS(name)
		ns.Labels[authorizationv1alpha1.LabelKeyProtected] = "tenant-a"
		return ns
	}

	testRequest := func(operation admissionv1.Operation, username string, groups []string, current, old *corev1.Namespace) crAdmission.Request {
		req := admissionv1.AdmissionRequest{
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"},
			Name:      current.Name,
			Operation: operation,
			UserInfo:  authenticationv1.UserInfo{Username: username, Groups: groups},
			Object:    runtime.RawExtension{Raw: mustMarshalJSON(t, current)},
		}
		if old != nil {
			req.OldObject = runtime.RawExtension{Raw: mustMarshalJSON(t, old)}
		}
		return crAdmission.Request{AdmissionRequest: req}
	}

	assertAllowed := func(name string, req crAdmission.Request, want bool) {
		t.Helper()
		resp := validator.Handle(context.Background(), req)
		if resp.Allowed != want {
			t.Fatalf("%s: allowed=%v, want %v (response=%+v)", name, resp.Allowed, want, resp)
		}
	}

	// CREATE uses the submitted protected label. A protected selector must
	// match its value, and an ordinary DoesNotExist selector must not match it.
	assertAllowed("protected selector creates protected namespace", testRequest(admissionv1.Create, "protected-user", []string{"oidc:tenant-protected-powerusers"}, protectedNS("protected-create"), nil), true)
	assertAllowed("protected selector cannot create ordinary namespace", testRequest(admissionv1.Create, "protected-user", []string{"oidc:tenant-protected-powerusers"}, ordinaryNS("ordinary-create"), nil), false)
	assertAllowed("ordinary selector creates ordinary namespace", testRequest(admissionv1.Create, "ordinary-user", []string{"oidc:tenant-powerusers"}, ordinaryNS("ordinary-create-2"), nil), true)
	assertAllowed("ordinary selector cannot create protected namespace", testRequest(admissionv1.Create, "ordinary-user", []string{"oidc:tenant-powerusers"}, protectedNS("protected-create-2"), nil), false)

	// UPDATE is authorized using the old object and the protected label is
	// immutable for non-bypass identities, so classification cannot be added,
	// removed, or changed by either persona.
	ordinaryOld := ordinaryNS("ordinary-update")
	ordinaryNew := ordinaryOld.DeepCopy()
	ordinaryNew.Labels[authorizationv1alpha1.LabelKeyProtected] = "tenant-a"
	assertAllowed("ordinary identity cannot add protected label", testRequest(admissionv1.Update, "ordinary-user", []string{"oidc:tenant-powerusers"}, ordinaryNew, ordinaryOld), false)

	protectedOld := protectedNS("protected-update")
	protectedNew := protectedOld.DeepCopy()
	delete(protectedNew.Labels, authorizationv1alpha1.LabelKeyProtected)
	assertAllowed("ordinary identity cannot strip protected label", testRequest(admissionv1.Update, "ordinary-user", []string{"oidc:tenant-powerusers"}, protectedNew, protectedOld), false)
	changedProtected := protectedOld.DeepCopy()
	changedProtected.Labels[authorizationv1alpha1.LabelKeyProtected] = "tenant-b"
	assertAllowed("protected identity cannot change protected label", testRequest(admissionv1.Update, "protected-user", []string{"oidc:tenant-protected-powerusers"}, changedProtected, protectedOld), false)
	assertAllowed("protected identity can update protected namespace without classification change", testRequest(admissionv1.Update, "protected-user", []string{"oidc:tenant-protected-powerusers"}, protectedOld.DeepCopy(), protectedOld), true)

	// DELETE also evaluates the existing object. Ordinary access must not
	// delete a protected namespace, while the protected persona may do so.
	assertAllowed("ordinary identity cannot delete protected namespace", testRequest(admissionv1.Delete, "ordinary-user", []string{"oidc:tenant-powerusers"}, protectedNS("protected-delete"), protectedNS("protected-delete")), false)
	assertAllowed("protected identity can delete protected namespace", testRequest(admissionv1.Delete, "protected-user", []string{"oidc:tenant-protected-powerusers"}, protectedNS("protected-delete-2"), protectedNS("protected-delete-2")), true)
	assertAllowed("ordinary identity can delete ordinary namespace", testRequest(admissionv1.Delete, "ordinary-user", []string{"oidc:tenant-powerusers"}, ordinaryNS("ordinary-delete"), ordinaryNS("ordinary-delete")), true)
}
