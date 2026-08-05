// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

// constrainedImpersonationField is the spec path reported in violations.
const constrainedImpersonationField = "spec.constrainedImpersonation"

// evaluateConstrainedImpersonation checks a RestrictedRoleDefinition's
// constrained-impersonation grant against its governing RBACPolicy.
//
// Deny by default: a policy without roleLimits.constrainedImpersonation, or with
// allowed=false, forbids the grant entirely. This keeps the feature opt-in per
// policy, which matters because constrained impersonation lets a tenant act as
// another identity.
func evaluateConstrainedImpersonation(
	limits *authorizationv1alpha1.RoleLimits,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
) []Violation {
	spec := rrd.Spec.ConstrainedImpersonation
	if spec == nil {
		return nil
	}

	ciLimits := limits.ConstrainedImpersonation
	if ciLimits == nil || !ciLimits.Allowed {
		return []Violation{{
			Field: constrainedImpersonationField,
			Message: "constrained impersonation is not allowed by policy; " +
				"set roleLimits.constrainedImpersonation.allowed=true to permit it",
		}}
	}

	violations := make([]Violation, 0, len(spec.Identities)+len(spec.Actions))
	violations = append(violations, evaluateImpersonationVerbDenylist(limits, spec)...)
	violations = append(violations, evaluateImpersonationModeAndResources(ciLimits, spec)...)
	violations = append(violations, evaluateImpersonationIdentityNames(ciLimits, spec)...)
	violations = append(violations, evaluateImpersonationActions(ciLimits, spec)...)
	violations = append(violations, evaluateImpersonationLegacyFallback(ciLimits, rrd)...)
	if len(violations) == 0 {
		return nil
	}
	return violations
}

// evaluateImpersonationVerbDenylist applies the generic RoleLimits.ForbiddenVerbs
// and RoleLimits.ForbiddenResourceVerbs denylists to the verbs the grant would
// generate.
//
// This is what makes an existing policy able to forbid `impersonate:*`-style
// grants without knowing about the typed API: the generated verb strings are
// matched with the same wildcard semantics as any other forbidden verb, so
// "impersonate:*" and "impersonate-on:*" both work as patterns.
func evaluateImpersonationVerbDenylist(
	limits *authorizationv1alpha1.RoleLimits,
	spec *authorizationv1alpha1.ConstrainedImpersonationSpec,
) []Violation {
	generated, err := authorizationv1alpha1.BuildConstrainedImpersonationRules(spec)
	if err != nil {
		return []Violation{{
			Field:   constrainedImpersonationField,
			Message: fmt.Sprintf("cannot evaluate grant: %v", err),
		}}
	}

	var violations []Violation
	for _, rule := range generated {
		for _, verb := range rule.Verbs {
			if matchesAnyWildcard(limits.ForbiddenVerbs, verb) {
				violations = append(violations, Violation{
					Field:   constrainedImpersonationField,
					Message: fmt.Sprintf("generated verb %q is forbidden by roleLimits.forbiddenVerbs", verb),
				})
				continue
			}
			if v := forbiddenResourceVerbViolation(limits, &rule, verb); v != nil {
				violations = append(violations, *v)
			}
		}
	}
	return violations
}

// forbiddenResourceVerbViolation reports a violation when a generated
// resource+verb combination is listed in RoleLimits.ForbiddenResourceVerbs.
func forbiddenResourceVerbViolation(
	limits *authorizationv1alpha1.RoleLimits,
	rule *rbacv1.PolicyRule,
	verb string,
) *Violation {
	for _, forbidden := range limits.ForbiddenResourceVerbs {
		if !matchesAnyWildcard(forbidden.Verbs, verb) {
			continue
		}
		if !slices.ContainsFunc(rule.APIGroups, func(g string) bool {
			return APIGroupRestrictionCovers(forbidden.APIGroup, g) || g == rbacv1.APIGroupAll
		}) {
			continue
		}
		if !slices.ContainsFunc(rule.Resources, func(r string) bool {
			return MatchesResourceName(forbidden.Resource, r)
		}) {
			continue
		}
		return &Violation{
			Field: constrainedImpersonationField,
			Message: fmt.Sprintf(
				"generated resource+verb combination %q on resource %q (apiGroup %q) is forbidden by roleLimits.forbiddenResourceVerbs",
				verb, forbidden.Resource, forbidden.APIGroup),
		}
	}
	return nil
}

func evaluateImpersonationModeAndResources(
	limits *authorizationv1alpha1.ConstrainedImpersonationLimits,
	spec *authorizationv1alpha1.ConstrainedImpersonationSpec,
) []Violation {
	var violations []Violation

	if len(limits.AllowedModes) > 0 && !slices.Contains(limits.AllowedModes, spec.Mode) {
		allowed := make([]string, 0, len(limits.AllowedModes))
		for _, m := range limits.AllowedModes {
			allowed = append(allowed, string(m))
		}
		violations = append(violations, Violation{
			Field: constrainedImpersonationField + ".mode",
			Message: fmt.Sprintf("mode %q is not allowed by policy; allowed modes: [%s]",
				spec.Mode, strings.Join(allowed, ", ")),
		})
	}

	if len(limits.AllowedIdentityResources) > 0 {
		allowed := make([]string, 0, len(limits.AllowedIdentityResources))
		for _, r := range limits.AllowedIdentityResources {
			allowed = append(allowed, string(r))
		}
		for i := range spec.Identities {
			resource := spec.Identities[i].Resource
			if slices.Contains(limits.AllowedIdentityResources, resource) {
				continue
			}
			violations = append(violations, Violation{
				Field: fmt.Sprintf("%s.identities[%d].resource", constrainedImpersonationField, i),
				Message: fmt.Sprintf("identity resource %q is not allowed by policy; allowed resources: [%s]",
					resource, strings.Join(allowed, ", ")),
			})
		}
	}

	return violations
}

func evaluateImpersonationIdentityNames(
	limits *authorizationv1alpha1.ConstrainedImpersonationLimits,
	spec *authorizationv1alpha1.ConstrainedImpersonationSpec,
) []Violation {
	var violations []Violation

	total := 0
	for i := range spec.Identities {
		total += len(spec.Identities[i].Names)
	}
	if limits.MaxIdentityNames != nil && total > int(*limits.MaxIdentityNames) {
		violations = append(violations, Violation{
			Field: constrainedImpersonationField + ".identities",
			Message: fmt.Sprintf("grant allowlists %d identity names, exceeding the policy maximum of %d",
				total, *limits.MaxIdentityNames),
		})
	}

	if limits.IdentityNameLimits == nil {
		return violations
	}
	for i := range spec.Identities {
		for j, name := range spec.Identities[i].Names {
			if reason := nameMatchViolation(limits.IdentityNameLimits, name); reason != "" {
				violations = append(violations, Violation{
					Field:   fmt.Sprintf("%s.identities[%d].names[%d]", constrainedImpersonationField, i, j),
					Message: fmt.Sprintf("identity name %q %s", name, reason),
				})
			}
		}
	}
	return violations
}

func evaluateImpersonationActions(
	limits *authorizationv1alpha1.ConstrainedImpersonationLimits,
	spec *authorizationv1alpha1.ConstrainedImpersonationSpec,
) []Violation {
	if len(limits.ForbiddenActionVerbs) == 0 {
		return nil
	}
	var violations []Violation
	for i := range spec.Actions {
		for j, verb := range spec.Actions[i].Verbs {
			if matchesAnyWildcard(limits.ForbiddenActionVerbs, verb) {
				violations = append(violations, Violation{
					Field: fmt.Sprintf("%s.actions[%d].verbs[%d]", constrainedImpersonationField, i, j),
					Message: fmt.Sprintf("action verb %q is forbidden by roleLimits.constrainedImpersonation.forbiddenActionVerbs",
						verb),
				})
			}
		}
	}
	return violations
}

// evaluateImpersonationLegacyFallback enforces knob #8: the legacy blanket
// "impersonate" verb wins by fallback and silently defeats every constraint the
// grant expresses, so a policy can require that it is explicitly stripped.
func evaluateImpersonationLegacyFallback(
	limits *authorizationv1alpha1.ConstrainedImpersonationLimits,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
) []Violation {
	if !limits.ForbidLegacyFallback {
		return nil
	}
	if ContainsStringOrWildcard(rrd.Spec.RestrictedVerbs, authorizationv1alpha1.LegacyImpersonateVerb) {
		return nil
	}
	return []Violation{{
		Field: "spec.restrictedVerbs",
		Message: fmt.Sprintf(
			"policy requires the legacy fallback to be closed: %q must be listed in restrictedVerbs, "+
				"otherwise a blanket legacy impersonation grant wins by fallback and silently defeats the constrained impersonation grant",
			authorizationv1alpha1.LegacyImpersonateVerb),
	}}
}

// nameMatchViolation returns a human-readable reason when a name is rejected by
// the allow/deny limits, or an empty string when it is accepted.
//
// Precedence mirrors the rest of the policy engine: explicit denials win over
// allowances, and a non-empty allowlist is default-deny.
func nameMatchViolation(limits *authorizationv1alpha1.NameMatchLimits, name string) string {
	if slices.Contains(limits.ForbiddenNames, name) {
		return "is explicitly forbidden by policy"
	}
	for _, prefix := range limits.ForbiddenPrefixes {
		if strings.HasPrefix(name, prefix) {
			return fmt.Sprintf("matches the forbidden prefix %q", prefix)
		}
	}
	for _, suffix := range limits.ForbiddenSuffixes {
		if strings.HasSuffix(name, suffix) {
			return fmt.Sprintf("matches the forbidden suffix %q", suffix)
		}
	}

	hasAllowList := len(limits.AllowedNames) > 0 || len(limits.AllowedPrefixes) > 0 || len(limits.AllowedSuffixes) > 0
	if !hasAllowList {
		return ""
	}
	if slices.Contains(limits.AllowedNames, name) {
		return ""
	}
	for _, prefix := range limits.AllowedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return ""
		}
	}
	for _, suffix := range limits.AllowedSuffixes {
		if strings.HasSuffix(name, suffix) {
			return ""
		}
	}
	return "does not match any allowed name, prefix or suffix"
}
