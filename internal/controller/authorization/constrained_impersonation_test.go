// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/capabilities"
	"github.com/telekom/auth-operator/pkg/conditions"
)

// stubDetector returns a fixed capability result.
type stubDetector struct {
	result capabilities.Result
}

func (s stubDetector) ConstrainedImpersonation(context.Context) capabilities.Result {
	return s.result
}

func testGrant() *authorizationv1alpha1.ConstrainedImpersonationSpec {
	return &authorizationv1alpha1.ConstrainedImpersonationSpec{
		Mode: authorizationv1alpha1.ImpersonationModeUserInfo,
		Identities: []authorizationv1alpha1.ImpersonationIdentityRule{
			{Resource: authorizationv1alpha1.ImpersonationResourceUsers, Names: []string{"jane"}},
		},
		Actions: []authorizationv1alpha1.ImpersonationActionRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
		},
	}
}

func TestAppendConstrainedImpersonationRules(t *testing.T) {
	t.Parallel()

	discovered := []rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"configmaps"},
		Verbs:     []string{"get", "list"},
	}}

	t.Run("nil spec leaves the discovered rules byte-identical", func(t *testing.T) {
		t.Parallel()
		// This is the backwards-compatibility guarantee: an existing definition with
		// the new field unset must produce exactly the rules it produced before.
		want := append([]rbacv1.PolicyRule(nil), discovered...)
		got, err := appendConstrainedImpersonationRules(nil, append([]rbacv1.PolicyRule(nil), discovered...))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("rules changed when no grant is configured (-want +got):\n%s", diff)
		}
	})

	t.Run("grant is appended after the discovered rules", func(t *testing.T) {
		t.Parallel()
		got, err := appendConstrainedImpersonationRules(testGrant(), append([]rbacv1.PolicyRule(nil), discovered...))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("expected 3 rules (1 discovered + 1 identity + 1 action), got %d: %+v", len(got), got)
		}
		if diff := cmp.Diff(discovered[0], got[0]); diff != "" {
			t.Errorf("discovered rule was modified (-want +got):\n%s", diff)
		}
		if got[1].APIGroups[0] != authenticationv1.GroupName {
			t.Errorf("identity rule apiGroup = %q, want %q", got[1].APIGroups[0], authenticationv1.GroupName)
		}
		if got[1].Verbs[0] != "impersonate:user-info" {
			t.Errorf("identity verb = %q, want impersonate:user-info", got[1].Verbs[0])
		}
		if got[2].Verbs[0] != "impersonate-on:user-info:list" {
			t.Errorf("action verb = %q, want impersonate-on:user-info:list", got[2].Verbs[0])
		}
	})

	t.Run("invalid mode is wrapped", func(t *testing.T) {
		t.Parallel()
		_, err := appendConstrainedImpersonationRules(
			&authorizationv1alpha1.ConstrainedImpersonationSpec{Mode: "bogus"}, nil)
		if err == nil {
			t.Fatal("expected an error for an unknown mode")
		}
		if !strings.Contains(err.Error(), "build constrained impersonation rules") {
			t.Errorf("error is not wrapped with context: %v", err)
		}
	})

	t.Run("appending to a nil rule slice works", func(t *testing.T) {
		t.Parallel()
		got, err := appendConstrainedImpersonationRules(testGrant(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("expected 2 generated rules, got %d", len(got))
		}
	})
}

func TestLegacyImpersonateRestricted(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		verbs []string
		want  bool
	}{
		"nil":                    {nil, false},
		"unrelated verbs":        {[]string{"delete", "patch"}, false},
		"explicit impersonate":   {[]string{"impersonate"}, true},
		"wildcard":               {[]string{rbacv1.VerbAll}, true},
		"impersonate among many": {[]string{"delete", "impersonate", "escalate"}, true},
		// A constrained verb is NOT the legacy verb: restricting impersonate:user-info
		// does not close the legacy fallback.
		"constrained verb only": {[]string{"impersonate:user-info"}, false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := legacyImpersonateRestricted(tt.verbs); got != tt.want {
				t.Errorf("legacyImpersonateRestricted(%v) = %t, want %t", tt.verbs, got, tt.want)
			}
		})
	}
}

func TestSetConstrainedImpersonationCondition(t *testing.T) {
	t.Parallel()

	// restrictedVerbs closing the legacy fallback, so the capability state is what
	// the condition reflects.
	closed := []string{authorizationv1alpha1.LegacyImpersonateVerb}

	tests := []struct {
		name            string
		grant           *authorizationv1alpha1.ConstrainedImpersonationSpec
		restrictedVerbs []string
		detector        capabilityDetector
		wantCondition   bool
		wantStatus      metav1.ConditionStatus
		wantReason      authorizationv1alpha1.AuthZConditionReason
	}{
		{
			name:     "no grant sets no condition",
			grant:    nil,
			detector: stubDetector{result: capabilities.Result{State: capabilities.StateEnabled}},
		},
		{
			name:            "gate enabled marks the condition True",
			grant:           testGrant(),
			restrictedVerbs: closed,
			detector: stubDetector{result: capabilities.Result{
				State: capabilities.StateEnabled, Reason: "FeatureGateEnabled", Detail: "gate on",
			}},
			wantCondition: true,
			wantStatus:    metav1.ConditionTrue,
			wantReason:    authorizationv1alpha1.ConstrainedImpersonationReasonEffective,
		},
		{
			name:            "gate disabled marks the condition False as inert",
			grant:           testGrant(),
			restrictedVerbs: closed,
			detector: stubDetector{result: capabilities.Result{
				State: capabilities.StateDisabled, Reason: "FeatureGateDisabled", Detail: "gate off",
			}},
			wantCondition: true,
			wantStatus:    metav1.ConditionFalse,
			wantReason:    authorizationv1alpha1.ConstrainedImpersonationReasonInert,
		},
		{
			name:            "pre-1.35 apiserver marks the condition False as inert",
			grant:           testGrant(),
			restrictedVerbs: closed,
			detector: stubDetector{result: capabilities.Result{
				State: capabilities.StateDisabled, Reason: "VersionTooOld", Detail: "1.34",
			}},
			wantCondition: true,
			wantStatus:    metav1.ConditionFalse,
			wantReason:    authorizationv1alpha1.ConstrainedImpersonationReasonInert,
		},
		{
			name:            "undetectable state marks the condition Unknown",
			grant:           testGrant(),
			restrictedVerbs: closed,
			detector: stubDetector{result: capabilities.Result{
				State: capabilities.StateUnknown, Reason: "VersionUnknown", Detail: "cannot tell",
			}},
			wantCondition: true,
			wantStatus:    metav1.ConditionUnknown,
			wantReason:    authorizationv1alpha1.ConstrainedImpersonationReasonUnknown,
		},
		{
			name:            "missing detector marks the condition Unknown rather than assuming support",
			grant:           testGrant(),
			restrictedVerbs: closed,
			detector:        nil,
			wantCondition:   true,
			wantStatus:      metav1.ConditionUnknown,
			wantReason:      authorizationv1alpha1.ConstrainedImpersonationReasonUnknown,
		},
		{
			name:  "reachable legacy fallback wins over an enabled gate",
			grant: testGrant(),
			// restrictedVerbs does not close the legacy fallback, so even with the gate
			// on the grant can be silently defeated.
			restrictedVerbs: nil,
			detector: stubDetector{result: capabilities.Result{
				State: capabilities.StateEnabled, Reason: "FeatureGateEnabled", Detail: "gate on",
			}},
			wantCondition: true,
			wantStatus:    metav1.ConditionFalse,
			wantReason:    authorizationv1alpha1.ConstrainedImpersonationReasonLegacyFallback,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			obj := &authorizationv1alpha1.RoleDefinition{}
			obj.Generation = 7

			setConstrainedImpersonationCondition(
				context.Background(), obj, obj.Generation, tt.grant, tt.restrictedVerbs, tt.detector)

			cond := conditions.Get(obj, authorizationv1alpha1.ConstrainedImpersonationCondition)
			if !tt.wantCondition {
				if cond != nil {
					t.Fatalf("expected no condition, got %+v", cond)
				}
				return
			}
			if cond == nil {
				t.Fatal("expected the ConstrainedImpersonationEffective condition to be set")
			}
			if cond.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q (message: %s)", cond.Status, tt.wantStatus, cond.Message)
			}
			if cond.Reason != string(tt.wantReason) {
				t.Errorf("reason = %q, want %q", cond.Reason, tt.wantReason)
			}
			if cond.ObservedGeneration != obj.Generation {
				t.Errorf("observedGeneration = %d, want %d", cond.ObservedGeneration, obj.Generation)
			}
		})
	}
}

func TestSetConstrainedImpersonationConditionClearsStaleCondition(t *testing.T) {
	t.Parallel()

	// Removing the grant must drop the condition, otherwise the status keeps
	// advertising a grant that no longer exists.
	obj := &authorizationv1alpha1.RoleDefinition{}
	obj.Generation = 1
	detector := stubDetector{result: capabilities.Result{State: capabilities.StateDisabled, Detail: "off"}}

	setConstrainedImpersonationCondition(context.Background(), obj, obj.Generation, testGrant(),
		[]string{authorizationv1alpha1.LegacyImpersonateVerb}, detector)
	if conditions.Get(obj, authorizationv1alpha1.ConstrainedImpersonationCondition) == nil {
		t.Fatal("expected the condition to be set")
	}

	obj.Generation = 2
	setConstrainedImpersonationCondition(context.Background(), obj, obj.Generation, nil, nil, detector)
	if cond := conditions.Get(obj, authorizationv1alpha1.ConstrainedImpersonationCondition); cond != nil {
		t.Errorf("expected the stale condition to be removed, got %+v", cond)
	}
}

func TestSetConstrainedImpersonationConditionOnRestrictedRoleDefinition(t *testing.T) {
	t.Parallel()

	// The helper is shared between RoleDefinition and RestrictedRoleDefinition, so
	// assert it works against the restricted type too.
	obj := &authorizationv1alpha1.RestrictedRoleDefinition{}
	obj.Generation = 3
	result := setConstrainedImpersonationCondition(
		context.Background(), obj, obj.Generation, testGrant(),
		[]string{authorizationv1alpha1.LegacyImpersonateVerb},
		stubDetector{result: capabilities.Result{State: capabilities.StateEnabled, Detail: "on"}},
	)
	if result.State != capabilities.StateEnabled {
		t.Errorf("state = %q, want Enabled", result.State)
	}
	cond := conditions.Get(obj, authorizationv1alpha1.ConstrainedImpersonationCondition)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("expected a True condition, got %+v", cond)
	}
}
