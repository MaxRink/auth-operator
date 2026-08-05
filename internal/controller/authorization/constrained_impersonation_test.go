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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"

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

// TestRecordConstrainedImpersonationStateEmitsWarningOnLegacyFallback pins the
// security-relevant case Copilot flagged on PR #513: when the detector reports the
// feature gate as Enabled but the definition leaves the legacy blanket
// "impersonate" verb reachable, the grant is defeated by fallback. The helper must
// therefore return a non-Enabled Result so the reconciler still emits the Warning
// event, and the event note must describe the legacy fallback rather than the
// (irrelevant) feature-gate detail.
func TestRecordConstrainedImpersonationStateEmitsWarningOnLegacyFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		restrictedVerbs []string
		wantEvent       bool
		wantNote        string
	}{
		{
			name: "legacy fallback reachable while the gate is enabled still warns",
			// restrictedVerbs does not strip the legacy verb.
			restrictedVerbs: nil,
			wantEvent:       true,
			wantNote:        "restrictedVerbs",
		},
		{
			name:            "legacy fallback closed and gate enabled emits no warning",
			restrictedVerbs: []string{authorizationv1alpha1.LegacyImpersonateVerb},
			wantEvent:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			recorder := events.NewFakeRecorder(4)
			r := &RoleDefinitionReconciler{
				recorder: recorder,
				capabilityDetector: stubDetector{result: capabilities.Result{
					State:  capabilities.StateEnabled,
					Reason: capabilities.ReasonFeatureGateEnabled,
					Detail: "feature gate ConstrainedImpersonation is enabled",
				}},
			}
			rd := &authorizationv1alpha1.RoleDefinition{}
			rd.Generation = 5
			rd.Spec.ConstrainedImpersonation = testGrant()
			rd.Spec.RestrictedVerbs = tt.restrictedVerbs

			r.recordConstrainedImpersonationState(context.Background(), rd)

			select {
			case ev := <-recorder.Events:
				if !tt.wantEvent {
					t.Fatalf("did not expect a Warning event, got %q", ev)
				}
				if !strings.HasPrefix(ev, corev1.EventTypeWarning+" ") {
					t.Errorf("event is not a Warning: %q", ev)
				}
				if !strings.Contains(ev, tt.wantNote) {
					t.Errorf("event note %q does not mention %q; the detail must describe the "+
						"legacy fallback, not the feature-gate state", ev, tt.wantNote)
				}
				if strings.Contains(ev, "feature gate ConstrainedImpersonation is enabled") {
					t.Errorf("event note carries the unrelated detector detail: %q", ev)
				}
			default:
				if tt.wantEvent {
					t.Fatal("expected a Warning event because the legacy impersonate fallback is " +
						"reachable, but none was emitted")
				}
			}

			cond := conditions.Get(rd, authorizationv1alpha1.ConstrainedImpersonationCondition)
			if cond == nil {
				t.Fatal("expected the ConstrainedImpersonationEffective condition to be set")
			}
			wantStatus := metav1.ConditionTrue
			if tt.wantEvent {
				wantStatus = metav1.ConditionFalse
			}
			if cond.Status != wantStatus {
				t.Errorf("condition status = %q, want %q", cond.Status, wantStatus)
			}
		})
	}
}

// TestSetConstrainedImpersonationConditionLegacyFallbackResult asserts the
// returned Result directly, so the contract callers rely on cannot silently
// regress back to passing the detector's answer through.
func TestSetConstrainedImpersonationConditionLegacyFallbackResult(t *testing.T) {
	t.Parallel()

	obj := &authorizationv1alpha1.RoleDefinition{}
	obj.Generation = 1
	result := setConstrainedImpersonationCondition(
		context.Background(), obj, obj.Generation, testGrant(), nil,
		stubDetector{result: capabilities.Result{
			State:         capabilities.StateEnabled,
			Reason:        capabilities.ReasonFeatureGateEnabled,
			Detail:        "gate on",
			ServerVersion: "v1.36.0",
		}},
	)

	if result.State == capabilities.StateEnabled {
		t.Error("state must not be Enabled while the legacy impersonate fallback is reachable")
	}
	if result.State != capabilities.StateDisabled {
		t.Errorf("state = %q, want %q", result.State, capabilities.StateDisabled)
	}
	if result.Reason != legacyFallbackReachableReason {
		t.Errorf("reason = %q, want %q", result.Reason, legacyFallbackReachableReason)
	}
	if !strings.Contains(result.Detail, authorizationv1alpha1.LegacyImpersonateVerb) {
		t.Errorf("detail %q does not mention the legacy verb", result.Detail)
	}
	if result.Detail == "gate on" {
		t.Error("detail leaked the detector's unrelated feature-gate explanation")
	}
	// The condition message args and the event note must be the same string.
	cond := conditions.Get(obj, authorizationv1alpha1.ConstrainedImpersonationCondition)
	if cond == nil || !strings.Contains(cond.Message, result.Detail) {
		t.Errorf("condition message %+v does not carry the returned detail %q", cond, result.Detail)
	}
	if result.ServerVersion != "v1.36.0" {
		t.Errorf("serverVersion = %q, want the detected version to be preserved", result.ServerVersion)
	}
}

// TestWithCapabilityDetectorAcceptsInterface pins the option signature to the
// local interface so a stub can be injected without building a real Detector.
func TestWithCapabilityDetectorAcceptsInterface(t *testing.T) {
	t.Parallel()

	stub := stubDetector{result: capabilities.Result{State: capabilities.StateDisabled}}
	r := &RoleDefinitionReconciler{}
	WithCapabilityDetector(stub)(r)

	if r.capabilityDetector == nil {
		t.Fatal("expected the stub detector to be wired onto the reconciler")
	}
	if got := r.capabilityDetector.ConstrainedImpersonation(context.Background()); got.State != capabilities.StateDisabled {
		t.Errorf("wired detector returned %q, want Disabled", got.State)
	}

	// A nil detector must be ignored rather than wiring a nil interface.
	fresh := &RoleDefinitionReconciler{}
	WithCapabilityDetector(nil)(fresh)
	if fresh.capabilityDetector != nil {
		t.Error("a nil detector must not be wired")
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
