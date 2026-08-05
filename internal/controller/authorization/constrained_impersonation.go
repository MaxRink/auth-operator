// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/capabilities"
	"github.com/telekom/auth-operator/pkg/conditions"
)

// capabilityDetector is the subset of pkg/capabilities.Detector the reconcilers
// depend on, so tests can inject a stub without a live API server.
type capabilityDetector interface {
	ConstrainedImpersonation(ctx context.Context) capabilities.Result
}

// legacyFallbackReachableReason is the machine-readable reason carried by the
// synthetic capabilities.Result returned when a grant leaves the legacy blanket
// "impersonate" verb reachable. It is not a detector reason: the API server
// capability is irrelevant once the constraint can be bypassed by fallback.
const legacyFallbackReachableReason = "LegacyFallbackReachable"

// appendConstrainedImpersonationRules appends the RBAC rules generated from a
// constrained-impersonation grant to the discovery-derived rules of a role.
//
// The grant is additive on purpose: the impersonation verbs live in the
// authentication.k8s.io API group (identity rules) or reuse the target request's
// own group (action rules), so they never collide with the resource rules produced
// by API discovery.
//
// A nil spec is a no-op and returns the input slice unchanged, which is what keeps
// existing RoleDefinitions reconciling byte-identically after the upgrade.
func appendConstrainedImpersonationRules(
	spec *authorizationv1alpha1.ConstrainedImpersonationSpec,
	rules []rbacv1.PolicyRule,
) ([]rbacv1.PolicyRule, error) {
	if spec == nil {
		return rules, nil
	}
	generated, err := authorizationv1alpha1.BuildConstrainedImpersonationRules(spec)
	if err != nil {
		return nil, fmt.Errorf("build constrained impersonation rules: %w", err)
	}
	return append(rules, generated...), nil
}

// conditionSetter is satisfied by every definition type that carries conditions.
type conditionSetter interface {
	conditions.Setter
}

// setConstrainedImpersonationCondition records whether a generated
// constrained-impersonation grant is actually effective on this cluster.
//
// This is the graceful-degradation surface required for backwards compatibility:
// on an API server without the ConstrainedImpersonation feature gate the generated
// ClusterRole is still accepted (RBAC verbs and resources are free-form strings)
// but grants nothing. Reporting Ready=true with no further signal would be a
// silent-no-privilege failure, so the state is surfaced explicitly:
//
//   - gate enabled          -> condition True,    reason FeatureGateEnabled
//   - gate disabled/too old -> condition False,   reason FeatureGateDisabled / VersionTooOld
//   - undetectable          -> condition Unknown, reason FeatureStateUnknown
//
// A reachable legacy blanket "impersonate" verb takes precedence over all of the
// above and yields condition False, reason LegacyFallbackReachable. The returned
// capabilities.Result is then synthetic (StateDisabled) rather than the detector's
// own answer, so callers that gate the Warning event on result.State still emit it
// and see the legacy-fallback detail.
//
// The condition is deliberately NOT wired into Ready: the operator did apply
// exactly what was asked for, and failing reconciliation would make the operator
// unusable on clusters where /metrics is unreadable. It is a warning surface, not
// an error.
//
// When the grant is not effective, the reconciler additionally emits a Warning
// event so the situation is visible without inspecting conditions.
func setConstrainedImpersonationCondition(
	ctx context.Context,
	obj conditionSetter,
	generation int64,
	spec *authorizationv1alpha1.ConstrainedImpersonationSpec,
	restrictedVerbs []string,
	detector capabilityDetector,
) capabilities.Result {
	if spec == nil {
		// Nothing was requested — drop any stale condition from a previous
		// generation so the status does not keep advertising a removed grant.
		conditions.Delete(obj, authorizationv1alpha1.ConstrainedImpersonationCondition)
		return capabilities.Result{}
	}

	logger := log.FromContext(ctx)

	if detector == nil {
		conditions.MarkUnknown(obj, authorizationv1alpha1.ConstrainedImpersonationCondition, generation,
			authorizationv1alpha1.ConstrainedImpersonationReasonUnknown,
			authorizationv1alpha1.ConstrainedImpersonationMessageUnknown,
			"capability detection is not configured")
		return capabilities.Result{State: capabilities.StateUnknown, Reason: "DetectorUnavailable"}
	}

	result := detector.ConstrainedImpersonation(ctx)

	// The legacy-fallback interaction is the dangerous part: a blanket legacy
	// "impersonate" grant wins by fallback and silently defeats the constraint. Only
	// report it as satisfied when the definition explicitly restricts that verb.
	if !legacyImpersonateRestricted(restrictedVerbs) {
		logger.V(1).Info("constrained impersonation grant leaves the legacy impersonate fallback reachable",
			"mode", spec.Mode)
		detail := fmt.Sprintf("add %q to spec.restrictedVerbs so the generated role cannot carry the blanket verb",
			authorizationv1alpha1.LegacyImpersonateVerb)
		conditions.MarkFalse(obj, authorizationv1alpha1.ConstrainedImpersonationCondition, generation,
			authorizationv1alpha1.ConstrainedImpersonationReasonLegacyFallback,
			authorizationv1alpha1.ConstrainedImpersonationMessageLegacyFallback,
			detail)
		// Deliberately NOT the detector's own result: a reachable legacy fallback
		// defeats the grant no matter what the feature gate says, so returning the
		// detector's StateEnabled here would make callers such as
		// recordConstrainedImpersonationState skip the Warning event and report a
		// detail unrelated to the actual problem. The synthetic result carries the
		// same detail as the condition so event and condition stay consistent.
		return capabilities.Result{
			State:         capabilities.StateDisabled,
			Reason:        legacyFallbackReachableReason,
			Detail:        detail,
			ServerVersion: result.ServerVersion,
		}
	}

	switch result.State {
	case capabilities.StateEnabled:
		conditions.MarkTrue(obj, authorizationv1alpha1.ConstrainedImpersonationCondition, generation,
			authorizationv1alpha1.ConstrainedImpersonationReasonEffective,
			authorizationv1alpha1.ConstrainedImpersonationMessageEffective, result.Detail)
	case capabilities.StateDisabled:
		logger.Info("constrained impersonation grant is inert on this API server",
			"mode", spec.Mode, "reason", result.Reason, "serverVersion", result.ServerVersion)
		conditions.MarkFalse(obj, authorizationv1alpha1.ConstrainedImpersonationCondition, generation,
			authorizationv1alpha1.ConstrainedImpersonationReasonInert,
			authorizationv1alpha1.ConstrainedImpersonationMessageInert, result.Detail)
	default:
		logger.V(1).Info("constrained impersonation support could not be determined",
			"mode", spec.Mode, "reason", result.Reason, "serverVersion", result.ServerVersion)
		conditions.MarkUnknown(obj, authorizationv1alpha1.ConstrainedImpersonationCondition, generation,
			authorizationv1alpha1.ConstrainedImpersonationReasonUnknown,
			authorizationv1alpha1.ConstrainedImpersonationMessageUnknown, result.Detail)
	}

	return result
}

// legacyImpersonateRestricted reports whether the definition's restrictedVerbs
// exclude the legacy bare "impersonate" verb, either explicitly or via "*".
func legacyImpersonateRestricted(restrictedVerbs []string) bool {
	return slices.Contains(restrictedVerbs, authorizationv1alpha1.LegacyImpersonateVerb) ||
		slices.Contains(restrictedVerbs, rbacv1.VerbAll)
}
