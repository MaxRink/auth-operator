// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyScope defines which namespaces this policy governs.
type PolicyScope struct {
	// NamespaceSelector selects namespaces by label selector.
	// +kubebuilder:validation:Optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// Namespaces is an explicit list of namespace names. Use "*" to make the
	// policy explicitly cluster-wide; this is required for cluster-scoped
	// generated resources such as ClusterRoles and ClusterRoleBindings.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Namespaces []string `json:"namespaces,omitempty"`
}

// RoleRefLimits controls which role references are allowed or forbidden.
type RoleRefLimits struct {
	// AllowedRoleRefs is a list of allowed role names. Supports simple wildcards:
	// "prefix*" and "*suffix". An empty list means no role refs are allowed (default-deny).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MinLength=1
	AllowedRoleRefs []string `json:"allowedRoleRefs,omitempty"`

	// AllowedRoleRefSelector selects allowed roles by label.
	// +kubebuilder:validation:Optional
	AllowedRoleRefSelector *metav1.LabelSelector `json:"allowedRoleRefSelector,omitempty"`

	// ForbiddenRoleRefs is a list of explicitly forbidden role names.
	// Takes precedence over AllowedRoleRefs.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenRoleRefs []string `json:"forbiddenRoleRefs,omitempty"`

	// ForbiddenRoleRefSelector selects forbidden roles by label.
	// +kubebuilder:validation:Optional
	ForbiddenRoleRefSelector *metav1.LabelSelector `json:"forbiddenRoleRefSelector,omitempty"`
}

// NamespaceLimits controls which namespaces can be targeted by bindings.
type NamespaceLimits struct {
	// AllowedNamespaceSelector selects allowed namespaces by label.
	// +kubebuilder:validation:Optional
	AllowedNamespaceSelector *metav1.LabelSelector `json:"allowedNamespaceSelector,omitempty"`

	// ForbiddenNamespaces is a list of namespace names that may not be targeted.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenNamespaces []string `json:"forbiddenNamespaces,omitempty"`

	// ForbiddenNamespacePrefixes is a list of namespace name prefixes that may not be targeted.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenNamespacePrefixes []string `json:"forbiddenNamespacePrefixes,omitempty"`

	// MaxTargetNamespaces limits the number of target namespaces per binding.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	MaxTargetNamespaces *int32 `json:"maxTargetNamespaces,omitempty"`
}

// BindingLimits defines constraints on role bindings created by restricted definitions.
type BindingLimits struct {
	// AllowClusterRoleBindings controls whether ClusterRoleBindings may be created.
	// Default is false (deny by default).
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	AllowClusterRoleBindings bool `json:"allowClusterRoleBindings"`

	// ClusterRoleBindingLimits constrains which ClusterRoles may be referenced
	// from ClusterRoleBindings or RoleBindings.
	// +kubebuilder:validation:Optional
	ClusterRoleBindingLimits *RoleRefLimits `json:"clusterRoleBindingLimits,omitempty"`

	// RoleBindingLimits constrains which namespaced Roles may be referenced in RoleBindings.
	// +kubebuilder:validation:Optional
	RoleBindingLimits *RoleRefLimits `json:"roleBindingLimits,omitempty"`

	// TargetNamespaceLimits constrains which namespaces may be targeted.
	// +kubebuilder:validation:Optional
	TargetNamespaceLimits *NamespaceLimits `json:"targetNamespaceLimits,omitempty"`
}

// ResourceVerbRule specifies a forbidden combination of resource, API group, and verbs.
type ResourceVerbRule struct {
	// Resource is the resource name (e.g., "pods", "secrets").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Resource string `json:"resource"`

	// APIGroup is the API group of the resource. Empty string means core group.
	// +kubebuilder:validation:Optional
	APIGroup string `json:"apiGroup,omitempty"`

	// Verbs are the verbs forbidden on this resource.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Verbs []string `json:"verbs"`
}

// RoleLimits defines constraints on roles created by RestrictedRoleDefinitions.
type RoleLimits struct {
	// AllowClusterRoles controls whether ClusterRoles may be generated.
	// Default is false (deny by default).
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	AllowClusterRoles bool `json:"allowClusterRoles"`

	// ForbiddenVerbs is a list of verbs that must not appear in generated roles.
	// Constrained impersonation verbs may be listed here, either fully spelled out
	// ("impersonate:user-info") or as a wildcard pattern ("impersonate:*",
	// "impersonate-on:*"). MaxItems is 64 because each constrained impersonation
	// mode x verb combination is a separate verb string.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenVerbs []string `json:"forbiddenVerbs,omitempty"`

	// ForbiddenResources is a list of resources that must not appear in generated roles.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenResources []string `json:"forbiddenResources,omitempty"`

	// ForbiddenAPIGroups is a list of API groups that must not appear in generated roles.
	// Use an empty string for the core API group.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	ForbiddenAPIGroups []string `json:"forbiddenAPIGroups,omitempty"`

	// ForbiddenResourceVerbs is a list of specific resource+verb combinations that are forbidden.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	ForbiddenResourceVerbs []ResourceVerbRule `json:"forbiddenResourceVerbs,omitempty"`

	// MaxRulesPerRole limits the number of rules in a single generated role.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	MaxRulesPerRole *int32 `json:"maxRulesPerRole,omitempty"`

	// ConstrainedImpersonation constrains Kubernetes constrained impersonation
	// (KEP-5284) grants declared by RestrictedRoleDefinitions governed by this
	// policy. When omitted, constrained impersonation grants are forbidden entirely
	// (deny by default) — a RestrictedRoleDefinition that sets
	// spec.constrainedImpersonation is reported as non-compliant.
	// +kubebuilder:validation:Optional
	ConstrainedImpersonation *ConstrainedImpersonationLimits `json:"constrainedImpersonation,omitempty"`
}

// ConstrainedImpersonationLimits constrains Kubernetes constrained impersonation
// (KEP-5284) grants that RestrictedRoleDefinitions may declare.
//
// This complements RoleLimits.ForbiddenVerbs and
// RoleLimits.ForbiddenResourceVerbs, which can also match generated
// `impersonate:<mode>` / `impersonate-on:<mode>:<verb>` verbs directly. The
// dedicated block exists because the generated verbs are synthesised by the
// operator rather than authored by the tenant, so a verb-string denylist alone is
// easy to bypass by choosing a different mode.
type ConstrainedImpersonationLimits struct {
	// Allowed enables constrained impersonation grants under this policy.
	// Defaults to false (deny by default).
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	Allowed bool `json:"allowed"`

	// AllowedModes restricts which impersonation modes may be used. An empty list
	// with allowed=true permits every mode.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=4
	AllowedModes []ImpersonationMode `json:"allowedModes,omitempty"`

	// AllowedIdentityResources restricts which identity resources may be granted.
	// An empty list with allowed=true permits every identity resource.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=6
	AllowedIdentityResources []ImpersonationIdentityResource `json:"allowedIdentityResources,omitempty"`

	// IdentityNameLimits constrains the identity names (resourceNames) a tenant may
	// list in identity rules, using the same allow/deny prefix and suffix semantics
	// as subject limits.
	// +kubebuilder:validation:Optional
	IdentityNameLimits *NameMatchLimits `json:"identityNameLimits,omitempty"`

	// ForbiddenActionVerbs lists underlying request verbs that must not appear in
	// action rules. Entries are the bare verbs (e.g. "delete"), not the
	// `impersonate-on:<mode>:` encoded form.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenActionVerbs []string `json:"forbiddenActionVerbs,omitempty"`

	// ForbidLegacyFallback requires that the RestrictedRoleDefinition also excludes
	// the legacy bare "impersonate" verb via restrictedVerbs. This closes knob #8 of
	// the KEP integration surface: a pre-existing blanket `impersonate` grant wins by
	// fallback and silently defeats every constraint expressed here.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	ForbidLegacyFallback bool `json:"forbidLegacyFallback"`

	// MaxIdentityNames limits how many identity names a single grant may allowlist
	// across all identity rules. Nil means unlimited.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	MaxIdentityNames *int32 `json:"maxIdentityNames,omitempty"`
}

// NameMatchLimits defines name-based allow/deny patterns for subjects.
type NameMatchLimits struct {
	// AllowedNames is a list of allowed subject names.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MinLength=1
	AllowedNames []string `json:"allowedNames,omitempty"`

	// ForbiddenNames is a list of forbidden subject names.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenNames []string `json:"forbiddenNames,omitempty"`

	// AllowedPrefixes is a list of allowed name prefixes.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	AllowedPrefixes []string `json:"allowedPrefixes,omitempty"`

	// ForbiddenPrefixes is a list of forbidden name prefixes.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenPrefixes []string `json:"forbiddenPrefixes,omitempty"`

	// AllowedSuffixes is a list of allowed name suffixes.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	AllowedSuffixes []string `json:"allowedSuffixes,omitempty"`

	// ForbiddenSuffixes is a list of forbidden name suffixes.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenSuffixes []string `json:"forbiddenSuffixes,omitempty"`
}

// SARef is a reference to a specific ServiceAccount.
type SARef struct {
	// Name of the ServiceAccount.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the ServiceAccount.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
}

// SACreationConfig controls ServiceAccount auto-creation behaviour.
type SACreationConfig struct {
	// AllowAutoCreate controls whether ServiceAccounts may be auto-created.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	AllowAutoCreate bool `json:"allowAutoCreate"`

	// AllowedCreationNamespaceSelector selects namespaces where SA creation is allowed.
	// +kubebuilder:validation:Optional
	AllowedCreationNamespaceSelector *metav1.LabelSelector `json:"allowedCreationNamespaceSelector,omitempty"`

	// AllowedCreationNamespaces is an explicit list of namespaces where SA creation is allowed.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MinLength=1
	AllowedCreationNamespaces []string `json:"allowedCreationNamespaces,omitempty"`

	// AutomountServiceAccountToken controls automount for auto-created SAs.
	// +kubebuilder:validation:Optional
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`

	// DisableAdoption records that pre-existing ServiceAccounts must stay external
	// unless they are already owned by the same RestrictedBindDefinition. Unowned
	// ServiceAccounts and ServiceAccounts owned by another RestrictedBindDefinition
	// are always treated as external subjects and are never adopted or modified.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	DisableAdoption bool `json:"disableAdoption"`
}

// ServiceAccountLimits defines constraints on ServiceAccount subjects.
type ServiceAccountLimits struct {
	// AllowedNamespaceSelector selects namespaces whose SAs may be referenced.
	// +kubebuilder:validation:Optional
	AllowedNamespaceSelector *metav1.LabelSelector `json:"allowedNamespaceSelector,omitempty"`

	// ForbiddenNamespaces is a list of namespaces whose SAs may not be referenced.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenNamespaces []string `json:"forbiddenNamespaces,omitempty"`

	// ForbiddenNamespacePrefixes is a list of namespace prefixes to deny.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenNamespacePrefixes []string `json:"forbiddenNamespacePrefixes,omitempty"`

	// Creation constrains ServiceAccount auto-creation behaviour.
	// +kubebuilder:validation:Optional
	Creation *SACreationConfig `json:"creation,omitempty"`
}

// SubjectLimits defines constraints on the subjects a tenant may use.
type SubjectLimits struct {
	// AllowedKinds controls which subject kinds are allowed.
	// Valid values: "User", "Group", "ServiceAccount".
	// An empty list means no subject kinds are allowed (default-deny).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=3
	// +kubebuilder:validation:items:MinLength=1
	AllowedKinds []string `json:"allowedKinds,omitempty"`

	// ForbiddenKinds lists subject kinds that are explicitly forbidden.
	// Takes precedence over AllowedKinds.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=3
	// +kubebuilder:validation:items:MinLength=1
	ForbiddenKinds []string `json:"forbiddenKinds,omitempty"`

	// UserLimits constrains User subject names.
	// +kubebuilder:validation:Optional
	UserLimits *NameMatchLimits `json:"userLimits,omitempty"`

	// GroupLimits constrains Group subject names.
	// +kubebuilder:validation:Optional
	GroupLimits *NameMatchLimits `json:"groupLimits,omitempty"`

	// ServiceAccountLimits constrains ServiceAccount subjects.
	// +kubebuilder:validation:Optional
	ServiceAccountLimits *ServiceAccountLimits `json:"serviceAccountLimits,omitempty"`
}

// DefaultPolicyAssignment defines identities that must use this policy by default
// when creating RestrictedBindDefinition/RestrictedRoleDefinition resources.
type DefaultPolicyAssignment struct {
	// Groups lists requester group names for which this policy is the default.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MinLength=1
	Groups []string `json:"groups,omitempty"`

	// ServiceAccounts lists requester ServiceAccounts for which this policy is the default.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	ServiceAccounts []SARef `json:"serviceAccounts,omitempty"`
}

// ImpersonationExtra is a single Impersonate-Extra-<key> entry used for
// apply-time impersonation.
type ImpersonationExtra struct {
	// Key is the extra key. It must be a lowercase, domain-prefixed path, matching
	// the apiserver's constrained-impersonation validateExtra() rules.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key"`

	// Values are the extra values for Key. At least one non-empty value is required;
	// the apiserver denies empty value lists and empty-string values.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	Values []string `json:"values"`
}

// ImpersonationConfig controls apply-time impersonation for
// RestrictedBindDefinition and RestrictedRoleDefinition reconciliation.
// RBACPolicy write access is a cluster trust boundary: a policy author can choose
// any identity here, and admission only validates structural correctness. The
// impersonated identity's own Kubernetes RBAC is the authoritative permission
// check during apply operations.
//
// ### The header-mixing trap (KEP-5284)
//
// The apiserver selects the `serviceaccount` and node constrained-impersonation
// modes only when the Impersonate-User header is the ONLY impersonation header
// set. Sending Impersonate-Uid, Impersonate-Group or Impersonate-Extra-* alongside
// a `system:serviceaccount:...` or `system:node:...` username silently skips those
// modes, falls through to `user-info` (which refuses node and ServiceAccount
// usernames) and finally to legacy impersonation. Admission therefore rejects
// combining ServiceAccountRef with UID, Groups or Extra.
//
// +kubebuilder:validation:XValidation:rule="!(has(self.serviceAccountRef) && ((has(self.uid) && size(self.uid) > 0) || (has(self.groups) && size(self.groups) > 0) || (has(self.extra) && size(self.extra) > 0)))",message="serviceAccountRef is mutually exclusive with uid, groups and extra: setting any of them makes the apiserver skip the serviceaccount constrained-impersonation mode and silently fall back to legacy impersonation"
// +kubebuilder:validation:XValidation:rule="!(has(self.userName) && has(self.serviceAccountRef))",message="userName and serviceAccountRef are mutually exclusive"
// +kubebuilder:validation:XValidation:rule="!has(self.groups) || !self.groups.exists(g, g == 'system:masters')",message="impersonating the system:masters group is not allowed"
type ImpersonationConfig struct {
	// Enabled enables impersonation during restricted resource apply operations.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// ServiceAccountRef is the ServiceAccount identity used for impersonated apply
	// operations, rendered as system:serviceaccount:<namespace>:<name>. Exactly one
	// of ServiceAccountRef or UserName is required when enabled is true.
	//
	// Mutually exclusive with UID, Groups and Extra — see the header-mixing trap in
	// the type documentation.
	// +kubebuilder:validation:Optional
	ServiceAccountRef *SARef `json:"serviceAccountRef,omitempty"`

	// UserName is a raw impersonated username, used instead of ServiceAccountRef
	// when the apply identity is not a ServiceAccount. Combined with UID, Groups and
	// Extra this expresses the full `user-info` constrained-impersonation identity.
	//
	// A `system:node:<name>` username is rejected: node impersonation forces
	// Groups=[system:nodes] and is not a meaningful apply identity for this operator.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=253
	UserName string `json:"userName,omitempty"`

	// UID is the impersonated UID, sent as the Impersonate-Uid header. Requires
	// UserName and is checked by the apiserver against
	// authentication.k8s.io/uids with the `impersonate:user-info` verb.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=253
	UID string `json:"uid,omitempty"`

	// Groups are the impersonated groups, sent as repeated Impersonate-Group
	// headers. Requires UserName. "system:masters" is rejected because constrained
	// impersonation hard-denies it.
	//
	// Note: at four or more groups the apiserver first attempts a single wildcard
	// ("*") group authorization check before falling back to per-group checks.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	Groups []string `json:"groups,omitempty"`

	// Extra are the impersonated extra values, sent as Impersonate-Extra-<key>
	// headers. Requires UserName.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=16
	Extra []ImpersonationExtra `json:"extra,omitempty"`

	// Mode records which constrained-impersonation mode the configured identity is
	// expected to select. It is advisory: the apiserver derives the mode from the
	// username and header set, it cannot be chosen by the client. Admission verifies
	// that the configured identity actually selects the declared mode, turning a
	// silent legacy fallback into an admission error.
	// +kubebuilder:validation:Optional
	Mode ImpersonationMode `json:"mode,omitempty"`
}

// EffectiveUsername renders the impersonated username for the configuration, or
// an empty string when no identity is configured.
func (ic *ImpersonationConfig) EffectiveUsername() string {
	if ic == nil {
		return ""
	}
	if ic.ServiceAccountRef != nil && ic.ServiceAccountRef.Name != "" && ic.ServiceAccountRef.Namespace != "" {
		return ServiceAccountUsernamePrefix + ic.ServiceAccountRef.Namespace + ":" + ic.ServiceAccountRef.Name
	}
	return ic.UserName
}

// SelectedMode returns the constrained-impersonation mode the apiserver will
// actually select for this configuration, applying the same
// only-username-is-set precondition as the apiserver.
//
// It returns an empty mode when the configuration would fall through to legacy
// impersonation, which is the footgun this operator guards against.
func (ic *ImpersonationConfig) SelectedMode() ImpersonationMode {
	if ic == nil {
		return ""
	}
	username := ic.EffectiveUsername()
	if username == "" {
		return ""
	}
	onlyUsernameSet := ic.UID == "" && len(ic.Groups) == 0 && len(ic.Extra) == 0

	switch {
	case strings.HasPrefix(username, NodeUsernamePrefix):
		// Node impersonation requires only-username-set; otherwise the apiserver
		// falls through to user-info, which refuses node usernames, then to legacy.
		if !onlyUsernameSet {
			return ""
		}
		return ImpersonationModeArbitraryNode
	case strings.HasPrefix(username, ServiceAccountUsernamePrefix):
		if !onlyUsernameSet {
			return ""
		}
		return ImpersonationModeServiceAccount
	default:
		return ImpersonationModeUserInfo
	}
}

// RBACPolicySpec defines the desired state of RBACPolicy.
// +kubebuilder:validation:XValidation:rule="has(self.appliesTo.namespaceSelector) || (has(self.appliesTo.namespaces) && size(self.appliesTo.namespaces) > 0)",message="appliesTo must specify at least namespaceSelector or namespaces"
type RBACPolicySpec struct {
	// AppliesTo defines the namespace scope this policy governs.
	// Static Namespaces entries and NamespaceSelector are enforced at evaluation time;
	// selector-based scope checks require a LabelGetter so namespace labels can be
	// resolved during controller reconciliation.
	// +kubebuilder:validation:Required
	AppliesTo PolicyScope `json:"appliesTo"`

	// BindingLimits constrains role bindings that may be created.
	// +kubebuilder:validation:Optional
	BindingLimits *BindingLimits `json:"bindingLimits,omitempty"`

	// RoleLimits constrains roles that may be generated.
	// +kubebuilder:validation:Optional
	RoleLimits *RoleLimits `json:"roleLimits,omitempty"`

	// SubjectLimits constrains the subjects a tenant may use.
	// +kubebuilder:validation:Optional
	SubjectLimits *SubjectLimits `json:"subjectLimits,omitempty"`

	// DefaultAssignment defines requester identities that must use this policy by default
	// when creating restricted resources.
	// +kubebuilder:validation:Optional
	DefaultAssignment *DefaultPolicyAssignment `json:"defaultAssignment,omitempty"`

	// Impersonation configures ServiceAccount impersonation for restricted resource
	// apply operations governed by this policy.
	// +kubebuilder:validation:Optional
	Impersonation *ImpersonationConfig `json:"impersonation,omitempty"`
}

// RBACPolicyStatus defines the observed state of RBACPolicy.
type RBACPolicyStatus struct {
	// ObservedGeneration is the last observed generation of the resource.
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// BoundResourceCount is the number of RestrictedBindDefinitions and
	// RestrictedRoleDefinitions currently referencing this policy.
	// +kubebuilder:validation:Optional
	BoundResourceCount int32 `json:"boundResourceCount,omitempty"`

	// Conditions defines current service state of the RBACPolicy.
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// RBACPolicy is the Schema for the rbacpolicies API.
// It defines RBAC guardrails that RestrictedBindDefinitions and
// RestrictedRoleDefinitions must comply with.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=rbacpolicies,scope=Cluster,shortName=rbacpol
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status",description="Whether the RBACPolicy is ready"
// +kubebuilder:printcolumn:name="Bound",type="integer",JSONPath=".status.boundResourceCount",description="Number of bound restricted resources"
// +kubebuilder:printcolumn:name="Namespaces",type="string",JSONPath=".spec.appliesTo.namespaces",priority=1,description="Explicit namespace scope"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time since creation"
type RBACPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec   RBACPolicySpec   `json:"spec"`
	Status RBACPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RBACPolicyList contains a list of RBACPolicy.
type RBACPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RBACPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RBACPolicy{}, &RBACPolicyList{})
}

// GetConditions returns the conditions of the RBACPolicy.
func (p *RBACPolicy) GetConditions() []metav1.Condition {
	return p.Status.Conditions
}

// SetConditions sets the conditions of the RBACPolicy.
func (p *RBACPolicy) SetConditions(conditions []metav1.Condition) {
	p.Status.Conditions = conditions
}
