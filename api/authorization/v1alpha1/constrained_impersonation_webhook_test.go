/*
Copyright © 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
*/
package v1alpha1

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// testResourceRules is a minimal, always-valid rule set so specs can focus on the
// principal and impersonation-policy fields under test.
func testResourceRules() []authzv1.ResourceRule {
	return []authzv1.ResourceRule{{
		Verbs:     []string{"get"},
		APIGroups: []string{""},
		Resources: []string{"pods"},
	}}
}

func clientObjectKey(name string) client.ObjectKey {
	return client.ObjectKey{Name: name}
}

// These specs run against a live envtest API server, so they exercise the
// generated CRD schema (OpenAPI validation and CEL XValidation rules) in addition
// to the admission webhook. That distinction matters: several
// constrained-impersonation guardrails are expressed as CEL and would otherwise
// only be covered by unit tests of the Go validators.
var _ = Describe("Constrained impersonation CRD schema and admission", func() {
	var nameCounter int

	uniqueName := func(prefix string) string {
		nameCounter++
		return fmt.Sprintf("%s-%d", prefix, nameCounter)
	}

	newRoleDefinition := func(name string, grant *ConstrainedImpersonationSpec) *RoleDefinition {
		return &RoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: RoleDefinitionSpec{
				TargetRole:               DefinitionClusterRole,
				TargetName:               name,
				ScopeNamespaced:          false,
				ConstrainedImpersonation: grant,
			},
		}
	}

	Context("RoleDefinition spec.constrainedImpersonation", func() {
		It("accepts a user-info grant with identity and action rules", func() {
			name := uniqueName("ci-user-info")
			rd := newRoleDefinition(name, &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUsers, Names: []string{"jane.doe@example.com"}},
					{Resource: ImpersonationResourceGroups, Names: []string{"tenant-a"}},
					{Resource: ImpersonationResourceUIDs, Names: []string{"uid-1234"}},
					{Resource: ImpersonationResourceUserExtras, ExtraKey: "example.com/scopes", Names: []string{"read"}},
				},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list", "watch"}},
				},
			})
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("accepts an associated-node grant with no names", func() {
			name := uniqueName("ci-assoc-node")
			rd := newRoleDefinition(name, &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeAssociatedNode,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceNodes}},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"nodes/status"}, Verbs: []string{"patch"}},
				},
			})
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("accepts a serviceaccount grant", func() {
			name := uniqueName("ci-sa")
			rd := newRoleDefinition(name, &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeServiceAccount,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceServiceAccounts, Names: []string{"applier"}}},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
				},
			})
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("rejects an unknown mode via the enum in the CRD schema", func() {
			rd := newRoleDefinition(uniqueName("ci-bad-mode"), &ConstrainedImpersonationSpec{
				Mode:       "definitely-not-a-mode",
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
			})
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.constrainedImpersonation.mode"))
		})

		It("rejects an unknown identity resource via the enum in the CRD schema", func() {
			rd := newRoleDefinition(uniqueName("ci-bad-resource"), &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: "secrets", Names: []string{"jane"}}},
			})
			Expect(k8sClient.Create(ctx, rd)).NotTo(Succeed())
		})

		It("rejects an empty identities list via MinItems", func() {
			rd := newRoleDefinition(uniqueName("ci-no-identities"), &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
			})
			Expect(k8sClient.Create(ctx, rd)).NotTo(Succeed())
		})

		It("rejects a system:masters group grant", func() {
			rd := newRoleDefinition(uniqueName("ci-masters"), &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceGroups, Names: []string{SystemMastersGroup}}},
			})
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("system:masters"))
		})

		It("rejects names on an associated-node grant", func() {
			rd := newRoleDefinition(uniqueName("ci-assoc-names"), &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeAssociatedNode,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceNodes, Names: []string{"worker-1"}}},
			})
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("names"))
		})

		It("rejects the nodes identity resource in user-info mode", func() {
			rd := newRoleDefinition(uniqueName("ci-userinfo-nodes"), &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceNodes, Names: []string{"worker-1"}}},
			})
			Expect(k8sClient.Create(ctx, rd)).NotTo(Succeed())
		})

		It("rejects the serviceaccounts identity resource in user-info mode", func() {
			rd := newRoleDefinition(uniqueName("ci-userinfo-sa"), &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceServiceAccounts, Names: []string{"applier"}}},
			})
			Expect(k8sClient.Create(ctx, rd)).NotTo(Succeed())
		})

		It("rejects a userextras rule with no extraKey", func() {
			rd := newRoleDefinition(uniqueName("ci-no-extrakey"), &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUserExtras, Names: []string{"read"}}},
			})
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("extraKey"))
		})

		It("rejects an extraKey on a non-userextras rule", func() {
			rd := newRoleDefinition(uniqueName("ci-stray-extrakey"), &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUsers, ExtraKey: "example.com/x", Names: []string{"jane"}},
				},
			})
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("extraKey"))
		})

		It("rejects a pre-encoded action verb", func() {
			rd := newRoleDefinition(uniqueName("ci-preencoded"), &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"impersonate-on:user-info:list"}},
				},
			})
			// Rejected by the items:Pattern on verbs before admission even runs.
			Expect(k8sClient.Create(ctx, rd)).NotTo(Succeed())
		})

		It("rejects a wildcard action verb", func() {
			rd := newRoleDefinition(uniqueName("ci-wildcard-verb"), &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}},
				},
			})
			Expect(k8sClient.Create(ctx, rd)).NotTo(Succeed())
		})

		It("rejects a cluster-scoped identity resource on a namespaced Role", func() {
			name := uniqueName("ci-namespaced")
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      name,
					TargetNamespace: "default",
					ScopeNamespaced: true,
					ConstrainedImpersonation: &ConstrainedImpersonationSpec{
						Mode:       ImpersonationModeUserInfo,
						Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ClusterRole"))
		})

		It("accepts a serviceaccounts identity resource on a namespaced Role", func() {
			name := uniqueName("ci-namespaced-sa")
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      name,
					TargetNamespace: "default",
					ScopeNamespaced: true,
					ConstrainedImpersonation: &ConstrainedImpersonationSpec{
						Mode:       ImpersonationModeServiceAccount,
						Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceServiceAccounts, Names: []string{"applier"}}},
						Actions: []ImpersonationActionRule{
							{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("is optional: a RoleDefinition without the field is admitted unchanged", func() {
			// Backwards compatibility: no new required fields, and an unset grant must
			// round-trip as nil rather than being defaulted to an empty struct.
			name := uniqueName("ci-absent")
			rd := newRoleDefinition(name, nil)
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			fetched := &RoleDefinition{}
			Expect(k8sClient.Get(ctx, clientObjectKey(name), fetched)).To(Succeed())
			Expect(fetched.Spec.ConstrainedImpersonation).To(BeNil())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})
	})

	Context("RoleDefinition spec.restrictedVerbs with impersonation verbs", func() {
		It("accepts constrained impersonation verbs in restrictedVerbs", func() {
			// Blocker #1: the historical pattern ^([a-z]+|\\*)$ rejected colon-bearing
			// verbs. Restricting them must now be expressible.
			name := uniqueName("ci-restricted-verbs")
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      name,
					ScopeNamespaced: false,
					RestrictedVerbs: []string{
						"impersonate",
						"impersonate:user-info",
						"impersonate:serviceaccount",
						"impersonate:arbitrary-node",
						"impersonate:associated-node",
						"impersonate-on:user-info:list",
						"impersonate-on:serviceaccount:get",
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("still rejects arbitrary colon-bearing verbs", func() {
			// The pattern was widened precisely, not opened up: an unknown mode or a
			// non-impersonation colon verb must still be rejected.
			name := uniqueName("ci-bad-verb")
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      name,
					ScopeNamespaced: false,
					RestrictedVerbs: []string{"escalate:everything"},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).NotTo(Succeed())
		})

		It("still rejects an unknown impersonation mode in restrictedVerbs", func() {
			name := uniqueName("ci-bad-mode-verb")
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      name,
					ScopeNamespaced: false,
					RestrictedVerbs: []string{"impersonate:god-mode"},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).NotTo(Succeed())
		})
	})

	Context("RBACPolicy spec.impersonation", func() {
		newPolicy := func(name string, ic *ImpersonationConfig) *RBACPolicy {
			return &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: RBACPolicySpec{
					AppliesTo:     PolicyScope{Namespaces: []string{"*"}},
					Impersonation: ic,
				},
			}
		}

		It("accepts a ServiceAccount apply identity (existing behaviour)", func() {
			name := uniqueName("pol-sa")
			policy := newPolicy(name, &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
			})
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
		})

		It("accepts a full user-info apply identity", func() {
			name := uniqueName("pol-userinfo")
			policy := newPolicy(name, &ImpersonationConfig{
				Enabled:  true,
				UserName: "jane@example.com",
				UID:      "uid-1",
				Groups:   []string{"dev"},
				Extra:    []ImpersonationExtra{{Key: "example.com/scopes", Values: []string{"write"}}},
				Mode:     ImpersonationModeUserInfo,
			})
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
		})

		It("rejects mixing serviceAccountRef with uid (the header-mixing trap)", func() {
			policy := newPolicy(uniqueName("pol-trap-uid"), &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				UID:               "uid-1",
			})
			err := k8sClient.Create(ctx, policy)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("legacy impersonation"))
		})

		// Regression guard for the header-mixing CEL rule itself.
		//
		// The three specs around this one are satisfied by EITHER the CEL
		// XValidation rule or the Go admission webhook, so they still pass when the
		// CEL rule is broken or absent. A malformed CEL rule makes the whole CRD
		// uninstallable, and that failure mode previously reached main because no
		// test asserted on the CEL layer specifically.
		//
		// Distinguishing the two layers by message text alone does NOT work: the Go
		// validator's trapDetail happens to contain the same "silently fall back to
		// legacy impersonation" wording, so asserting on that substring passes even
		// with the CEL rule deleted (verified by deleting it and re-running).
		//
		// The reliable discriminator is the error's field path and cause. CEL rules on
		// the ImpersonationConfig struct report Invalid on the struct path
		// (spec.impersonation), whereas the Go webhook reports Forbidden on the
		// offending child path (spec.impersonation.uid / .groups / .extra).
		DescribeTable("enforces the header-mixing trap via the CEL rule on the generated CRD schema",
			func(childField string, mutate func(*ImpersonationConfig)) {
				ic := &ImpersonationConfig{
					Enabled:           true,
					ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				}
				mutate(ic)
				err := k8sClient.Create(ctx, newPolicy(uniqueName("pol-cel-trap"), ic))
				Expect(err).To(HaveOccurred())
				// Emitted only by the CEL rule on the struct: an Invalid value on the
				// struct path itself, not a Forbidden on the child field.
				Expect(err.Error()).To(ContainSubstring("spec.impersonation: Invalid value"),
					"the header-mixing CEL rule must be present in the generated CRD schema; "+
						"a Forbidden error on spec.impersonation.%s means only the Go webhook rejected it",
					childField)
			},
			Entry("uid", "uid", func(ic *ImpersonationConfig) { ic.UID = "uid-1" }),
			Entry("groups", "groups", func(ic *ImpersonationConfig) { ic.Groups = []string{"dev"} }),
			Entry("extra", "extra", func(ic *ImpersonationConfig) {
				ic.Extra = []ImpersonationExtra{{Key: "example.com/a", Values: []string{"1"}}}
			}),
		)

		// The positive half of the same rule: a serviceAccountRef with none of the
		// conflicting fields must be accepted, so the CEL rule cannot regress into
		// rejecting everything.
		It("admits a serviceAccountRef with no uid, groups or extra (CEL positive case)", func() {
			policy := newPolicy(uniqueName("pol-cel-ok"), &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
			})
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
		})

		It("rejects mixing serviceAccountRef with groups", func() {
			policy := newPolicy(uniqueName("pol-trap-groups"), &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				Groups:            []string{"dev"},
			})
			Expect(k8sClient.Create(ctx, policy)).NotTo(Succeed())
		})

		It("rejects mixing serviceAccountRef with extra", func() {
			policy := newPolicy(uniqueName("pol-trap-extra"), &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				Extra:             []ImpersonationExtra{{Key: "example.com/a", Values: []string{"1"}}},
			})
			Expect(k8sClient.Create(ctx, policy)).NotTo(Succeed())
		})

		It("rejects a system:masters group", func() {
			policy := newPolicy(uniqueName("pol-masters"), &ImpersonationConfig{
				Enabled:  true,
				UserName: "jane",
				Groups:   []string{SystemMastersGroup},
			})
			err := k8sClient.Create(ctx, policy)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("system:masters"))
		})

		It("rejects a declared mode that the identity does not select", func() {
			policy := newPolicy(uniqueName("pol-mode-mismatch"), &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				Mode:              ImpersonationModeUserInfo,
			})
			err := k8sClient.Create(ctx, policy)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("mode"))
		})
	})

	Context("RBACPolicy spec.roleLimits.constrainedImpersonation", func() {
		It("accepts a full limits block", func() {
			name := uniqueName("pol-ci-limits")
			policy := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{Namespaces: []string{"*"}},
					RoleLimits: &RoleLimits{
						AllowClusterRoles: true,
						ForbiddenVerbs:    []string{"impersonate:arbitrary-node"},
						ConstrainedImpersonation: &ConstrainedImpersonationLimits{
							Allowed:                  true,
							AllowedModes:             []ImpersonationMode{ImpersonationModeUserInfo},
							AllowedIdentityResources: []ImpersonationIdentityResource{ImpersonationResourceUsers},
							ForbiddenActionVerbs:     []string{"delete"},
							ForbidLegacyFallback:     true,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
		})

		It("rejects an unknown allowed mode", func() {
			policy := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("pol-ci-bad-mode")},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{Namespaces: []string{"*"}},
					RoleLimits: &RoleLimits{
						ConstrainedImpersonation: &ConstrainedImpersonationLimits{
							Allowed:      true,
							AllowedModes: []ImpersonationMode{"bogus"},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).NotTo(Succeed())
		})
	})

	Context("WebhookAuthorizer principal uid and extra matchers", func() {
		It("accepts uid and extra matchers and the impersonation verb policy", func() {
			name := uniqueName("wa-ci")
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: WebhookAuthorizerSpec{
					ImpersonationVerbPolicy: ImpersonationVerbPolicyRequireExplicitVerb,
					AllowedPrincipals: []Principal{{
						User: "system:serviceaccount:kube-system:node-agent",
						UID:  "uid-1",
						Extra: []PrincipalExtraMatch{
							{Key: "authentication.kubernetes.io/node-name", Values: []string{"worker-1"}},
						},
					}},
					ResourceRules: testResourceRules(),
				},
			}
			Expect(k8sClient.Create(ctx, wa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, wa)).To(Succeed())
		})

		It("accepts a uid-only principal", func() {
			name := uniqueName("wa-uid-only")
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: WebhookAuthorizerSpec{
					AllowedPrincipals: []Principal{{UID: "uid-42"}},
					ResourceRules:     testResourceRules(),
				},
			}
			Expect(k8sClient.Create(ctx, wa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, wa)).To(Succeed())
		})

		It("accepts an extra-only principal", func() {
			name := uniqueName("wa-extra-only")
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: WebhookAuthorizerSpec{
					AllowedPrincipals: []Principal{{
						Extra: []PrincipalExtraMatch{{Key: "example.com/tier", Values: []string{"platform"}}},
					}},
					ResourceRules: testResourceRules(),
				},
			}
			Expect(k8sClient.Create(ctx, wa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, wa)).To(Succeed())
		})

		It("rejects a principal with no matchers at all", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("wa-empty-principal")},
				Spec: WebhookAuthorizerSpec{
					AllowedPrincipals: []Principal{{}},
					ResourceRules:     testResourceRules(),
				},
			}
			Expect(k8sClient.Create(ctx, wa)).NotTo(Succeed())
		})

		It("rejects an unknown impersonationVerbPolicy", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("wa-bad-policy")},
				Spec: WebhookAuthorizerSpec{
					ImpersonationVerbPolicy: "Maybe",
					AllowedPrincipals:       []Principal{{User: "jane"}},
					ResourceRules:           testResourceRules(),
				},
			}
			Expect(k8sClient.Create(ctx, wa)).NotTo(Succeed())
		})

		It("defaults impersonationVerbPolicy to RequireExplicitVerb", func() {
			// The fail-safe default must come from the CRD so operators do not have to
			// opt into the hardening explicitly.
			name := uniqueName("wa-default-policy")
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: WebhookAuthorizerSpec{
					AllowedPrincipals: []Principal{{User: "jane"}},
					ResourceRules:     testResourceRules(),
				},
			}
			Expect(k8sClient.Create(ctx, wa)).To(Succeed())

			fetched := &WebhookAuthorizer{}
			Expect(k8sClient.Get(ctx, clientObjectKey(name), fetched)).To(Succeed())
			Expect(fetched.Spec.ImpersonationVerbPolicy).To(Equal(ImpersonationVerbPolicyRequireExplicitVerb))
			Expect(k8sClient.Delete(ctx, wa)).To(Succeed())
		})
	})
})
