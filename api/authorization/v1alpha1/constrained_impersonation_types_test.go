// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestIdentityVerb(t *testing.T) {
	t.Parallel()

	// The verb spellings are load-bearing: they must byte-match what the
	// kube-apiserver builds inline in mode.go. There are no upstream constants to
	// compare against, so they are asserted literally here.
	want := map[ImpersonationMode]string{
		ImpersonationModeUserInfo:       "impersonate:user-info",
		ImpersonationModeServiceAccount: "impersonate:serviceaccount",
		ImpersonationModeArbitraryNode:  "impersonate:arbitrary-node",
		ImpersonationModeAssociatedNode: "impersonate:associated-node",
	}
	for mode, expected := range want {
		if got := IdentityVerb(mode); got != expected {
			t.Errorf("IdentityVerb(%q) = %q, want %q", mode, got, expected)
		}
	}
	if len(want) != len(AllImpersonationModes()) {
		t.Fatalf("test covers %d modes but AllImpersonationModes() has %d", len(want), len(AllImpersonationModes()))
	}
}

func TestActionVerb(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode ImpersonationMode
		verb string
		want string
	}{
		{ImpersonationModeUserInfo, "list", "impersonate-on:user-info:list"},
		{ImpersonationModeUserInfo, "watch", "impersonate-on:user-info:watch"},
		{ImpersonationModeServiceAccount, "get", "impersonate-on:serviceaccount:get"},
		{ImpersonationModeArbitraryNode, "patch", "impersonate-on:arbitrary-node:patch"},
		{ImpersonationModeAssociatedNode, "create", "impersonate-on:associated-node:create"},
	}
	for _, tt := range tests {
		if got := ActionVerb(tt.mode, tt.verb); got != tt.want {
			t.Errorf("ActionVerb(%q, %q) = %q, want %q", tt.mode, tt.verb, got, tt.want)
		}
	}
}

func TestIsImpersonationVerb(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"impersonate:user-info":           true,
		"impersonate-on:user-info:list":   true,
		"impersonate:arbitrary-node":      true,
		"impersonate-on:serviceaccount:*": true,
		// The legacy verb is deliberately NOT an impersonation verb for this helper:
		// it must keep flowing through the plain RBAC matching path unchanged.
		"impersonate": false,
		"get":         false,
		"list":        false,
		"*":           false,
		"":            false,
	}
	for verb, want := range tests {
		if got := IsImpersonationVerb(verb); got != want {
			t.Errorf("IsImpersonationVerb(%q) = %t, want %t", verb, got, want)
		}
	}
}

func TestParseImpersonationVerb(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		verb   string
		want   ParsedImpersonationVerb
		wantOK bool
	}{
		{
			name:   "identity verb user-info",
			verb:   "impersonate:user-info",
			want:   ParsedImpersonationVerb{Mode: ImpersonationModeUserInfo},
			wantOK: true,
		},
		{
			name:   "identity verb associated-node",
			verb:   "impersonate:associated-node",
			want:   ParsedImpersonationVerb{Mode: ImpersonationModeAssociatedNode},
			wantOK: true,
		},
		{
			name:   "action verb",
			verb:   "impersonate-on:user-info:list",
			want:   ParsedImpersonationVerb{Mode: ImpersonationModeUserInfo, Action: "list", IsAction: true},
			wantOK: true,
		},
		{
			name:   "action verb with colon in underlying verb keeps the remainder",
			verb:   "impersonate-on:serviceaccount:weird:verb",
			want:   ParsedImpersonationVerb{Mode: ImpersonationModeServiceAccount, Action: "weird:verb", IsAction: true},
			wantOK: true,
		},
		{name: "legacy verb is not parseable", verb: "impersonate"},
		{name: "plain verb", verb: "list"},
		{name: "unknown mode in identity verb", verb: "impersonate:bogus-mode"},
		{name: "unknown mode in action verb", verb: "impersonate-on:bogus-mode:list"},
		{name: "action verb missing underlying verb", verb: "impersonate-on:user-info:"},
		{name: "action verb missing separator", verb: "impersonate-on:user-info"},
		{name: "empty", verb: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := ParseImpersonationVerb(tt.verb)
			if ok != tt.wantOK {
				t.Fatalf("ParseImpersonationVerb(%q) ok = %t, want %t", tt.verb, ok, tt.wantOK)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseImpersonationVerb(%q) mismatch (-want +got):\n%s", tt.verb, diff)
			}
		})
	}
}

func TestParseImpersonationVerbRoundTrip(t *testing.T) {
	t.Parallel()

	// Every verb the operator can generate must parse back to what generated it.
	for _, mode := range AllImpersonationModes() {
		parsed, ok := ParseImpersonationVerb(IdentityVerb(mode))
		if !ok || parsed.Mode != mode || parsed.IsAction {
			t.Errorf("identity verb round trip failed for mode %q: %+v ok=%t", mode, parsed, ok)
		}
		for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete"} {
			parsed, ok := ParseImpersonationVerb(ActionVerb(mode, verb))
			if !ok || parsed.Mode != mode || parsed.Action != verb || !parsed.IsAction {
				t.Errorf("action verb round trip failed for %q/%q: %+v ok=%t", mode, verb, parsed, ok)
			}
		}
	}
}

func TestRequiresClusterScope(t *testing.T) {
	t.Parallel()

	// Only serviceaccounts identity rules can live in a namespaced Role.
	for _, resource := range AllImpersonationIdentityResources() {
		want := resource != ImpersonationResourceServiceAccounts
		if got := resource.RequiresClusterScope(); got != want {
			t.Errorf("%q.RequiresClusterScope() = %t, want %t", resource, got, want)
		}
	}
}

func TestBuildConstrainedImpersonationRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spec    *ConstrainedImpersonationSpec
		want    []rbacv1.PolicyRule
		wantErr bool
	}{
		{
			name: "nil spec produces no rules",
			spec: nil,
			want: nil,
		},
		{
			name: "user-info identity plus action rule matches the KEP example",
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUsers, Names: []string{"jane.doe@example.com"}},
				},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list", "watch"}},
				},
			},
			want: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{authenticationv1.GroupName},
					Resources:     []string{"users"},
					ResourceNames: []string{"jane.doe@example.com"},
					Verbs:         []string{"impersonate:user-info"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"impersonate-on:user-info:list", "impersonate-on:user-info:watch"},
				},
			},
		},
		{
			name: "userextras renders the extra key as a subresource",
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUserExtras, ExtraKey: "example.com/scopes", Names: []string{"read"}},
				},
			},
			want: []rbacv1.PolicyRule{{
				APIGroups:     []string{authenticationv1.GroupName},
				Resources:     []string{"userextras/example.com/scopes"},
				ResourceNames: []string{"read"},
				Verbs:         []string{"impersonate:user-info"},
			}},
		},
		{
			name: "associated-node emits no resourceNames",
			spec: &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeAssociatedNode,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceNodes}},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"nodes/status"}, Verbs: []string{"patch"}},
				},
			},
			want: []rbacv1.PolicyRule{
				{
					APIGroups: []string{authenticationv1.GroupName},
					Resources: []string{"nodes"},
					Verbs:     []string{"impersonate:associated-node"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"nodes/status"},
					Verbs:     []string{"impersonate-on:associated-node:patch"},
				},
			},
		},
		{
			name: "identity rules for the same resource are merged, sorted and de-duplicated",
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUsers, Names: []string{"zoe", "amy"}},
					{Resource: ImpersonationResourceGroups, Names: []string{"dev"}},
					{Resource: ImpersonationResourceUsers, Names: []string{"amy", "bob"}},
				},
			},
			want: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{authenticationv1.GroupName},
					Resources:     []string{"groups"},
					ResourceNames: []string{"dev"},
					Verbs:         []string{"impersonate:user-info"},
				},
				{
					APIGroups:     []string{authenticationv1.GroupName},
					Resources:     []string{"users"},
					ResourceNames: []string{"amy", "bob", "zoe"},
					Verbs:         []string{"impersonate:user-info"},
				},
			},
		},
		{
			name: "serviceaccount mode with resourceNames",
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeServiceAccount,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceServiceAccounts, Names: []string{"applier"}},
				},
				Actions: []ImpersonationActionRule{{
					APIGroups:     []string{rbacv1.GroupName},
					Resources:     []string{"roles"},
					ResourceNames: []string{"tenant-role"},
					Verbs:         []string{"patch"},
				}},
			},
			want: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{authenticationv1.GroupName},
					Resources:     []string{"serviceaccounts"},
					ResourceNames: []string{"applier"},
					Verbs:         []string{"impersonate:serviceaccount"},
				},
				{
					APIGroups:     []string{rbacv1.GroupName},
					Resources:     []string{"roles"},
					ResourceNames: []string{"tenant-role"},
					Verbs:         []string{"impersonate-on:serviceaccount:patch"},
				},
			},
		},
		{
			name:    "unknown mode is an error",
			spec:    &ConstrainedImpersonationSpec{Mode: "bogus"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := BuildConstrainedImpersonationRules(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("BuildConstrainedImpersonationRules() expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildConstrainedImpersonationRules() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("rules mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuildConstrainedImpersonationRulesIsDeterministic(t *testing.T) {
	t.Parallel()

	// SSA diffs against the generated rules, so authoring order must not change the
	// output. Building twice from differently ordered but equivalent specs must
	// produce identical rules.
	a := &ConstrainedImpersonationSpec{
		Mode: ImpersonationModeUserInfo,
		Identities: []ImpersonationIdentityRule{
			{Resource: ImpersonationResourceUsers, Names: []string{"b", "a"}},
			{Resource: ImpersonationResourceGroups, Names: []string{"g2", "g1"}},
			{Resource: ImpersonationResourceUIDs, Names: []string{"uid-1"}},
		},
	}
	b := &ConstrainedImpersonationSpec{
		Mode: ImpersonationModeUserInfo,
		Identities: []ImpersonationIdentityRule{
			{Resource: ImpersonationResourceUIDs, Names: []string{"uid-1"}},
			{Resource: ImpersonationResourceGroups, Names: []string{"g1", "g2"}},
			{Resource: ImpersonationResourceUsers, Names: []string{"a", "b"}},
		},
	}

	rulesA, err := BuildConstrainedImpersonationRules(a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rulesB, err := BuildConstrainedImpersonationRules(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff(rulesA, rulesB); diff != "" {
		t.Errorf("generated rules depend on authoring order (-a +b):\n%s", diff)
	}
}

func TestBuildConstrainedImpersonationRulesPreservesCoreGroup(t *testing.T) {
	t.Parallel()

	// The core API group is the empty string. It must survive de-duplication, or
	// action rules against core resources would lose their apiGroups entry entirely.
	rules, err := BuildConstrainedImpersonationRules(&ConstrainedImpersonationSpec{
		Mode:       ImpersonationModeUserInfo,
		Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
		Actions: []ImpersonationActionRule{
			{APIGroups: []string{"", "apps"}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	action := rules[len(rules)-1]
	if diff := cmp.Diff([]string{"", "apps"}, action.APIGroups); diff != "" {
		t.Errorf("core API group not preserved (-want +got):\n%s", diff)
	}
}

func TestValidateConstrainedImpersonationSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		spec            *ConstrainedImpersonationSpec
		clusterRole     bool
		wantErrCount    int
		wantErrContains string
	}{
		{name: "nil spec is valid", spec: nil, clusterRole: true},
		{
			name:        "minimal valid user-info grant",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
				},
			},
		},
		{
			name:            "unknown mode",
			clusterRole:     true,
			spec:            &ConstrainedImpersonationSpec{Mode: "bogus"},
			wantErrCount:    1,
			wantErrContains: "Unsupported value",
		},
		{
			name:            "no identities",
			clusterRole:     true,
			spec:            &ConstrainedImpersonationSpec{Mode: ImpersonationModeUserInfo},
			wantErrCount:    1,
			wantErrContains: "at least one identity rule is required",
		},
		{
			name:        "system:masters group grant is rejected",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceGroups, Names: []string{SystemMastersGroup}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "system:masters",
		},
		{
			name:        "empty group name is rejected",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceGroups, Names: []string{""}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "must not be empty",
		},
		{
			name:        "empty names allowlist is rejected outside associated-node",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers}},
			},
			wantErrCount:    1,
			wantErrContains: "empty allowlist would grant unrestricted impersonation",
		},
		{
			name:        "associated-node with names is rejected",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeAssociatedNode,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceNodes, Names: []string{"node-1"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "must not set names",
		},
		{
			name:        "associated-node without names is valid",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeAssociatedNode,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceNodes}},
			},
		},
		{
			name:        "associated-node with a non-node resource is rejected",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeAssociatedNode,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUsers, Names: []string{"jane"}},
				},
			},
			// Mode incompatibility plus the associated-node names restriction.
			wantErrCount:    2,
			wantErrContains: "forces the impersonated groups",
		},
		{
			name:        "arbitrary-node forces the nodes resource",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeArbitraryNode,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceGroups, Names: []string{"dev"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "only supports the \"nodes\" identity resource",
		},
		{
			name:        "serviceaccount mode forces the serviceaccounts resource",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeServiceAccount,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceGroups, Names: []string{"dev"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "computes the impersonated groups from the ServiceAccount namespace",
		},
		{
			name:        "user-info mode rejects the nodes resource",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceNodes, Names: []string{"node-1"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "reserved for the",
		},
		{
			name:        "user-info mode rejects the serviceaccounts resource",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceServiceAccounts, Names: []string{"applier"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "reserved for the",
		},
		{
			name:        "user-info users rule rejects a node username",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUsers, Names: []string{"system:node:worker-1"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "are reserved",
		},
		{
			name:        "user-info users rule rejects a ServiceAccount username",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUsers, Names: []string{"system:serviceaccount:ns:sa"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "are reserved",
		},
		{
			name:        "users rule accepts the wildcard",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUsers, Names: []string{rbacv1.ResourceAll}},
				},
			},
		},
		{
			name:        "serviceaccounts rule rejects the full username form",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeServiceAccount,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceServiceAccounts, Names: []string{"system:serviceaccount:ns:sa"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "must be the bare serviceaccounts name",
		},
		{
			name:        "nodes rule rejects the full username form",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeArbitraryNode,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceNodes, Names: []string{"system:node:worker-1"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "must be the bare nodes name",
		},
		{
			name:        "userextras requires an extraKey",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUserExtras, Names: []string{"read"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "extraKey is required",
		},
		{
			name:        "extraKey is forbidden on non-userextras resources",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUsers, ExtraKey: "example.com/x", Names: []string{"jane"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "extraKey may only be set",
		},
		{
			name:        "non-lowercase extraKey is rejected",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUserExtras, ExtraKey: "Example.com/scopes", Names: []string{"read"}},
				},
			},
			// Two errors: the lowercase check and the domain-prefixed-path check both fire.
			wantErrCount:    2,
			wantErrContains: "must be lowercase",
		},
		{
			name:        "extraKey that is not a domain-prefixed path is rejected",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceUserExtras, ExtraKey: "notadomain", Names: []string{"read"}},
				},
			},
			wantErrCount: 1,
		},
		{
			name:        "cluster-scoped identity resource on a namespaced Role is rejected",
			clusterRole: false,
			spec: &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
			},
			wantErrCount:    1,
			wantErrContains: "requires targetRole 'ClusterRole'",
		},
		{
			name:        "serviceaccounts identity resource is allowed on a namespaced Role",
			clusterRole: false,
			spec: &ConstrainedImpersonationSpec{
				Mode: ImpersonationModeServiceAccount,
				Identities: []ImpersonationIdentityRule{
					{Resource: ImpersonationResourceServiceAccounts, Names: []string{"applier"}},
				},
			},
		},
		{
			name:        "wildcard action verb is rejected because there is no prefix wildcard",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{rbacv1.VerbAll}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "no action verb wildcard",
		},
		{
			name:        "pre-encoded action verb is rejected",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"impersonate-on:user-info:list"}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "prefix is added automatically",
		},
		{
			name:        "legacy impersonate as an action verb is rejected",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
				Actions: []ImpersonationActionRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{LegacyImpersonateVerb}},
				},
			},
			wantErrCount:    1,
			wantErrContains: "prefix is added automatically",
		},
		{
			name:        "action rule with no verbs is rejected",
			clusterRole: true,
			spec: &ConstrainedImpersonationSpec{
				Mode:       ImpersonationModeUserInfo,
				Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
				Actions:    []ImpersonationActionRule{{APIGroups: []string{""}, Resources: []string{"pods"}}},
			},
			wantErrCount:    1,
			wantErrContains: "at least one verb is required",
		},
		{
			name:            "unknown identity resource",
			clusterRole:     true,
			spec:            &ConstrainedImpersonationSpec{Mode: ImpersonationModeUserInfo, Identities: []ImpersonationIdentityRule{{Resource: "bogus"}}},
			wantErrCount:    1,
			wantErrContains: "Unsupported value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			errs := ValidateConstrainedImpersonationSpec(tt.spec, tt.clusterRole, field.NewPath("spec", "constrainedImpersonation"))
			if len(errs) != tt.wantErrCount {
				t.Fatalf("got %d errors, want %d: %v", len(errs), tt.wantErrCount, errs)
			}
			if tt.wantErrContains == "" {
				return
			}
			if !strings.Contains(errs.ToAggregate().Error(), tt.wantErrContains) {
				t.Errorf("errors %q do not contain %q", errs.ToAggregate().Error(), tt.wantErrContains)
			}
		})
	}
}

func TestConstrainedImpersonationWarnings(t *testing.T) {
	t.Parallel()

	t.Run("nil spec yields no warnings", func(t *testing.T) {
		t.Parallel()
		if got := ConstrainedImpersonationWarnings(nil, "spec.constrainedImpersonation"); got != nil {
			t.Errorf("expected no warnings, got %v", got)
		}
	})

	t.Run("identity-only grant warns about the action check ordering", func(t *testing.T) {
		t.Parallel()
		warnings := ConstrainedImpersonationWarnings(&ConstrainedImpersonationSpec{
			Mode:       ImpersonationModeUserInfo,
			Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
		}, "spec.constrainedImpersonation")
		if len(warnings) != 1 || !strings.Contains(warnings[0], "action check FIRST") {
			t.Errorf("expected an action-ordering warning, got %v", warnings)
		}
	})

	t.Run("multiple identities warn about union rather than correlation", func(t *testing.T) {
		t.Parallel()
		warnings := ConstrainedImpersonationWarnings(&ConstrainedImpersonationSpec{
			Mode: ImpersonationModeUserInfo,
			Identities: []ImpersonationIdentityRule{
				{Resource: ImpersonationResourceUsers, Names: []string{"jane"}},
				{Resource: ImpersonationResourceGroups, Names: []string{"dev"}},
			},
			Actions: []ImpersonationActionRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
			},
		}, "spec.constrainedImpersonation")
		if len(warnings) != 1 || !strings.Contains(warnings[0], "UNION rather than correlate") {
			t.Errorf("expected a union warning, got %v", warnings)
		}
	})

	t.Run("wildcard action rule warns", func(t *testing.T) {
		t.Parallel()
		warnings := ConstrainedImpersonationWarnings(&ConstrainedImpersonationSpec{
			Mode:       ImpersonationModeUserInfo,
			Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
			Actions: []ImpersonationActionRule{{
				APIGroups: []string{rbacv1.APIGroupAll},
				Resources: []string{rbacv1.ResourceAll},
				Verbs:     []string{"get"},
			}},
		}, "spec.constrainedImpersonation")
		if len(warnings) != 1 || !strings.Contains(warnings[0], "all resources in all API groups") {
			t.Errorf("expected a wildcard warning, got %v", warnings)
		}
	})

	t.Run("narrow single-identity grant yields no warnings", func(t *testing.T) {
		t.Parallel()
		warnings := ConstrainedImpersonationWarnings(&ConstrainedImpersonationSpec{
			Mode:       ImpersonationModeUserInfo,
			Identities: []ImpersonationIdentityRule{{Resource: ImpersonationResourceUsers, Names: []string{"jane"}}},
			Actions: []ImpersonationActionRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
			},
		}, "spec.constrainedImpersonation")
		if len(warnings) != 0 {
			t.Errorf("expected no warnings, got %v", warnings)
		}
	})
}
