// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/utils/ptr"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

func userInfoGrant() *authorizationv1alpha1.ConstrainedImpersonationSpec {
	return &authorizationv1alpha1.ConstrainedImpersonationSpec{
		Mode: authorizationv1alpha1.ImpersonationModeUserInfo,
		Identities: []authorizationv1alpha1.ImpersonationIdentityRule{
			{Resource: authorizationv1alpha1.ImpersonationResourceUsers, Names: []string{"jane@example.com"}},
		},
		Actions: []authorizationv1alpha1.ImpersonationActionRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list", "watch"}},
		},
	}
}

func rrdWithGrant(
	grant *authorizationv1alpha1.ConstrainedImpersonationSpec,
	restrictedVerbs ...string,
) *authorizationv1alpha1.RestrictedRoleDefinition {
	return &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:               authorizationv1alpha1.DefinitionClusterRole,
			TargetName:               "tenant-impersonator",
			ConstrainedImpersonation: grant,
			RestrictedVerbs:          restrictedVerbs,
		},
	}
}

func joinViolations(violations []Violation) string {
	parts := make([]string, 0, len(violations))
	for _, v := range violations {
		parts = append(parts, v.Field+": "+v.Message)
	}
	return strings.Join(parts, " | ")
}

func TestEvaluateConstrainedImpersonation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		limits       *authorizationv1alpha1.RoleLimits
		rrd          *authorizationv1alpha1.RestrictedRoleDefinition
		wantCount    int
		wantContains string
	}{
		{
			name:      "no grant means nothing to evaluate",
			limits:    &authorizationv1alpha1.RoleLimits{},
			rrd:       rrdWithGrant(nil),
			wantCount: 0,
		},
		{
			name: "deny by default when the policy has no constrainedImpersonation block",
			// This is the important default: constrained impersonation lets a tenant act
			// as another identity, so it must be opt-in per policy.
			limits:       &authorizationv1alpha1.RoleLimits{},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: "not allowed by policy",
		},
		{
			name: "deny when allowed is explicitly false",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{Allowed: false},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: "not allowed by policy",
		},
		{
			name: "allowed with no further limits is compliant",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{Allowed: true},
			},
			rrd:       rrdWithGrant(userInfoGrant()),
			wantCount: 0,
		},
		{
			name: "forbiddenVerbs can forbid a fully spelled out identity verb",
			limits: &authorizationv1alpha1.RoleLimits{
				ForbiddenVerbs:           []string{"impersonate:user-info"},
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{Allowed: true},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: `generated verb "impersonate:user-info" is forbidden`,
		},
		{
			name: "forbiddenVerbs wildcard impersonate:* forbids every identity verb",
			limits: &authorizationv1alpha1.RoleLimits{
				ForbiddenVerbs:           []string{"impersonate:*"},
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{Allowed: true},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: "impersonate:user-info",
		},
		{
			name: "forbiddenVerbs wildcard impersonate-on:* forbids every action verb",
			limits: &authorizationv1alpha1.RoleLimits{
				ForbiddenVerbs:           []string{"impersonate-on:*"},
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{Allowed: true},
			},
			rrd: rrdWithGrant(userInfoGrant()),
			// One violation per generated action verb (list and watch).
			wantCount:    2,
			wantContains: "impersonate-on:user-info:list",
		},
		{
			name: "forbiddenResourceVerbs can forbid an action verb on a specific resource",
			limits: &authorizationv1alpha1.RoleLimits{
				ForbiddenResourceVerbs: []authorizationv1alpha1.ResourceVerbRule{
					{Resource: "pods", APIGroup: "", Verbs: []string{"impersonate-on:user-info:watch"}},
				},
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{Allowed: true},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: "forbidden by roleLimits.forbiddenResourceVerbs",
		},
		{
			name: "allowedModes restricts the mode",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed:      true,
					AllowedModes: []authorizationv1alpha1.ImpersonationMode{authorizationv1alpha1.ImpersonationModeServiceAccount},
				},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: `mode "user-info" is not allowed by policy`,
		},
		{
			name: "allowedModes permits a listed mode",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed:      true,
					AllowedModes: []authorizationv1alpha1.ImpersonationMode{authorizationv1alpha1.ImpersonationModeUserInfo},
				},
			},
			rrd:       rrdWithGrant(userInfoGrant()),
			wantCount: 0,
		},
		{
			name: "allowedIdentityResources restricts the identity resource",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed: true,
					AllowedIdentityResources: []authorizationv1alpha1.ImpersonationIdentityResource{
						authorizationv1alpha1.ImpersonationResourceGroups,
					},
				},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: `identity resource "users" is not allowed by policy`,
		},
		{
			name: "identityNameLimits forbidden name",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed: true,
					IdentityNameLimits: &authorizationv1alpha1.NameMatchLimits{
						ForbiddenNames: []string{"jane@example.com"},
					},
				},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: "is explicitly forbidden by policy",
		},
		{
			name: "identityNameLimits forbidden prefix",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed: true,
					IdentityNameLimits: &authorizationv1alpha1.NameMatchLimits{
						ForbiddenPrefixes: []string{"jane"},
					},
				},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: "matches the forbidden prefix",
		},
		{
			name: "identityNameLimits forbidden suffix",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed: true,
					IdentityNameLimits: &authorizationv1alpha1.NameMatchLimits{
						ForbiddenSuffixes: []string{"@example.com"},
					},
				},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: "matches the forbidden suffix",
		},
		{
			name: "identityNameLimits allowlist is default-deny",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed: true,
					IdentityNameLimits: &authorizationv1alpha1.NameMatchLimits{
						AllowedNames: []string{"someone-else"},
					},
				},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: "does not match any allowed name",
		},
		{
			name: "identityNameLimits allowed suffix permits the name",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed: true,
					IdentityNameLimits: &authorizationv1alpha1.NameMatchLimits{
						AllowedSuffixes: []string{"@example.com"},
					},
				},
			},
			rrd:       rrdWithGrant(userInfoGrant()),
			wantCount: 0,
		},
		{
			name: "denials win over allowances",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed: true,
					IdentityNameLimits: &authorizationv1alpha1.NameMatchLimits{
						AllowedNames:   []string{"jane@example.com"},
						ForbiddenNames: []string{"jane@example.com"},
					},
				},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: "is explicitly forbidden by policy",
		},
		{
			name: "maxIdentityNames is enforced across all identity rules",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed:          true,
					MaxIdentityNames: ptr.To(int32(2)),
				},
			},
			rrd: rrdWithGrant(&authorizationv1alpha1.ConstrainedImpersonationSpec{
				Mode: authorizationv1alpha1.ImpersonationModeUserInfo,
				Identities: []authorizationv1alpha1.ImpersonationIdentityRule{
					{Resource: authorizationv1alpha1.ImpersonationResourceUsers, Names: []string{"a", "b"}},
					{Resource: authorizationv1alpha1.ImpersonationResourceGroups, Names: []string{"g"}},
				},
			}),
			wantCount:    1,
			wantContains: "exceeding the policy maximum of 2",
		},
		{
			name: "maxIdentityNames within the limit is compliant",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed:          true,
					MaxIdentityNames: ptr.To(int32(4)),
				},
			},
			rrd:       rrdWithGrant(userInfoGrant()),
			wantCount: 0,
		},
		{
			name: "forbiddenActionVerbs rejects a listed underlying verb",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed:              true,
					ForbiddenActionVerbs: []string{"watch"},
				},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: `action verb "watch" is forbidden`,
		},
		{
			name: "forbiddenActionVerbs supports wildcards",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed:              true,
					ForbiddenActionVerbs: []string{rbacv1.VerbAll},
				},
			},
			rrd:       rrdWithGrant(userInfoGrant()),
			wantCount: 2,
		},
		{
			name: "forbidLegacyFallback requires the legacy verb to be restricted",
			// Knob #8: a blanket legacy grant wins by fallback and silently defeats the
			// constraint, so a policy must be able to demand it is closed.
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed:              true,
					ForbidLegacyFallback: true,
				},
			},
			rrd:          rrdWithGrant(userInfoGrant()),
			wantCount:    1,
			wantContains: "policy requires the legacy fallback to be closed",
		},
		{
			name: "forbidLegacyFallback satisfied by an explicit restrictedVerbs entry",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed:              true,
					ForbidLegacyFallback: true,
				},
			},
			rrd:       rrdWithGrant(userInfoGrant(), authorizationv1alpha1.LegacyImpersonateVerb),
			wantCount: 0,
		},
		{
			name: "forbidLegacyFallback satisfied by a restrictedVerbs wildcard",
			limits: &authorizationv1alpha1.RoleLimits{
				ConstrainedImpersonation: &authorizationv1alpha1.ConstrainedImpersonationLimits{
					Allowed:              true,
					ForbidLegacyFallback: true,
				},
			},
			rrd:       rrdWithGrant(userInfoGrant(), rbacv1.VerbAll),
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := evaluateConstrainedImpersonation(tt.limits, tt.rrd)
			if len(got) != tt.wantCount {
				t.Fatalf("got %d violations, want %d: %s", len(got), tt.wantCount, joinViolations(got))
			}
			if tt.wantContains == "" {
				return
			}
			if !strings.Contains(joinViolations(got), tt.wantContains) {
				t.Errorf("violations %q do not contain %q", joinViolations(got), tt.wantContains)
			}
		})
	}
}

func TestEvaluateRoleDefinitionIncludesConstrainedImpersonation(t *testing.T) {
	t.Parallel()

	// End-to-end through the public evaluator: an RRD with a grant under a policy
	// that does not permit it must be reported as non-compliant.
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo:  authorizationv1alpha1.PolicyScope{Namespaces: []string{"*"}},
			RoleLimits: &authorizationv1alpha1.RoleLimits{AllowClusterRoles: true},
		},
	}
	violations := EvaluateRoleDefinition(policy, rrdWithGrant(userInfoGrant()))
	if !strings.Contains(joinViolations(violations), "not allowed by policy") {
		t.Errorf("expected a constrained impersonation violation, got: %s", joinViolations(violations))
	}

	// And with it permitted, the same RRD is compliant.
	policy.Spec.RoleLimits.ConstrainedImpersonation = &authorizationv1alpha1.ConstrainedImpersonationLimits{Allowed: true}
	violations = EvaluateRoleDefinition(policy, rrdWithGrant(userInfoGrant()))
	if len(violations) != 0 {
		t.Errorf("expected no violations, got: %s", joinViolations(violations))
	}
}

func TestEvaluateRoleDefinitionUnaffectedWhenGrantIsUnset(t *testing.T) {
	t.Parallel()

	// Backwards compatibility: an RRD without the new field must evaluate exactly as
	// it did before, with no new violations introduced by the added evaluation pass.
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo:  authorizationv1alpha1.PolicyScope{Namespaces: []string{"*"}},
			RoleLimits: &authorizationv1alpha1.RoleLimits{AllowClusterRoles: true},
		},
	}
	if violations := EvaluateRoleDefinition(policy, rrdWithGrant(nil)); len(violations) != 0 {
		t.Errorf("expected no violations for an RRD without a grant, got: %s", joinViolations(violations))
	}
}

func TestNameMatchViolation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		limits     *authorizationv1alpha1.NameMatchLimits
		value      string
		wantReason bool
	}{
		{name: "empty limits accept everything", limits: &authorizationv1alpha1.NameMatchLimits{}, value: "anything"},
		{
			name:       "forbidden name",
			limits:     &authorizationv1alpha1.NameMatchLimits{ForbiddenNames: []string{"x"}},
			value:      "x",
			wantReason: true,
		},
		{
			name:   "allowed prefix",
			limits: &authorizationv1alpha1.NameMatchLimits{AllowedPrefixes: []string{"team-"}},
			value:  "team-a",
		},
		{
			name:       "allowlist default-deny",
			limits:     &authorizationv1alpha1.NameMatchLimits{AllowedPrefixes: []string{"team-"}},
			value:      "other",
			wantReason: true,
		},
		{
			name:   "allowed name",
			limits: &authorizationv1alpha1.NameMatchLimits{AllowedNames: []string{"exact"}},
			value:  "exact",
		},
		{
			name:   "allowed suffix",
			limits: &authorizationv1alpha1.NameMatchLimits{AllowedSuffixes: []string{"-prod"}},
			value:  "svc-prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reason := nameMatchViolation(tt.limits, tt.value)
			if (reason != "") != tt.wantReason {
				t.Errorf("nameMatchViolation(%q) = %q, wantReason = %t", tt.value, reason, tt.wantReason)
			}
		})
	}
}
