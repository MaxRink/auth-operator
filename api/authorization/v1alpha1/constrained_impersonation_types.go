// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Kubernetes constrained impersonation (KEP-5284) verb vocabulary.
//
// The upstream apiserver builds these verb strings inline in unexported code
// (k8s.io/apiserver/pkg/endpoints/filters/impersonation/mode.go), so there are
// no exported Go constants to reuse. They are defined here as the single source
// of truth for this operator.
const (
	// ImpersonateVerbPrefix prefixes the identity verb, e.g. "impersonate:user-info".
	ImpersonateVerbPrefix = "impersonate:"
	// ImpersonateOnVerbPrefix prefixes the action verb, e.g. "impersonate-on:user-info:list".
	ImpersonateOnVerbPrefix = "impersonate-on:"
	// LegacyImpersonateVerb is the classic (pre-KEP-5284) impersonation verb. It is
	// evaluated against the core API group and acts as a fallback that silently
	// defeats every constrained-impersonation restriction when granted.
	LegacyImpersonateVerb = "impersonate"
	// ConstrainedImpersonationFeatureGate is the kube-apiserver feature gate name.
	// Alpha in 1.35 (off), beta in 1.36 (on by default), GA planned for 1.38.
	ConstrainedImpersonationFeatureGate = "ConstrainedImpersonation"
)

// ImpersonationMode selects one of the constrained impersonation modes defined by
// KEP-5284. The mode is derived by the apiserver from the Impersonate-User header
// value; this field declares which mode the generated RBAC grant targets.
// +kubebuilder:validation:Enum=user-info;serviceaccount;arbitrary-node;associated-node
type ImpersonationMode string

// Constrained impersonation modes, in apiserver evaluation order.
const (
	// ImpersonationModeAssociatedNode allows a requesting ServiceAccount to
	// impersonate only the node it is scheduled on. Identity rules take no names.
	ImpersonationModeAssociatedNode ImpersonationMode = "associated-node"
	// ImpersonationModeArbitraryNode allows impersonating any system:node:<name>.
	ImpersonationModeArbitraryNode ImpersonationMode = "arbitrary-node"
	// ImpersonationModeServiceAccount allows impersonating system:serviceaccount:<ns>:<name>.
	ImpersonationModeServiceAccount ImpersonationMode = "serviceaccount"
	// ImpersonationModeUserInfo allows impersonating any non-node, non-ServiceAccount
	// identity, including uid, groups and extra values.
	ImpersonationModeUserInfo ImpersonationMode = "user-info"
)

// AllImpersonationModes lists every supported constrained impersonation mode in
// apiserver evaluation order.
func AllImpersonationModes() []ImpersonationMode {
	return []ImpersonationMode{
		ImpersonationModeAssociatedNode,
		ImpersonationModeArbitraryNode,
		ImpersonationModeServiceAccount,
		ImpersonationModeUserInfo,
	}
}

// ImpersonationIdentityResource is the resource in the authentication.k8s.io API
// group that an identity rule grants against.
// +kubebuilder:validation:Enum=users;groups;uids;userextras;serviceaccounts;nodes
type ImpersonationIdentityResource string

// Identity resources checked by the apiserver during constrained impersonation.
// All are evaluated against the authentication.k8s.io API group; legacy
// impersonation uses the core ("") group instead.
const (
	// ImpersonationResourceUsers matches a generic Impersonate-User value.
	ImpersonationResourceUsers ImpersonationIdentityResource = "users"
	// ImpersonationResourceGroups matches each Impersonate-Group value.
	ImpersonationResourceGroups ImpersonationIdentityResource = "groups"
	// ImpersonationResourceUIDs matches the Impersonate-Uid value.
	ImpersonationResourceUIDs ImpersonationIdentityResource = "uids"
	// ImpersonationResourceUserExtras matches Impersonate-Extra-<key> values. The
	// extra key becomes the RBAC subresource, i.e. "userextras/<key>".
	ImpersonationResourceUserExtras ImpersonationIdentityResource = "userextras"
	// ImpersonationResourceServiceAccounts matches an Impersonate-User value of the
	// form system:serviceaccount:<ns>:<name>. This is the only identity resource
	// that may be granted from a namespaced Role.
	ImpersonationResourceServiceAccounts ImpersonationIdentityResource = "serviceaccounts"
	// ImpersonationResourceNodes matches an Impersonate-User value of the form
	// system:node:<name>.
	ImpersonationResourceNodes ImpersonationIdentityResource = "nodes"
)

// AllImpersonationIdentityResources lists every supported identity resource.
func AllImpersonationIdentityResources() []ImpersonationIdentityResource {
	return []ImpersonationIdentityResource{
		ImpersonationResourceUsers,
		ImpersonationResourceGroups,
		ImpersonationResourceUIDs,
		ImpersonationResourceUserExtras,
		ImpersonationResourceServiceAccounts,
		ImpersonationResourceNodes,
	}
}

// SystemMastersGroup is the cluster-admin group that constrained impersonation
// hard-denies. Granting it would be a silent privilege escalation, so the
// operator rejects it at admission time as well.
const SystemMastersGroup = "system:masters"

// NodesGroup is the group the apiserver force-assigns when a node is
// impersonated. Groups can never be impersonated alongside a node username.
const NodesGroup = "system:nodes"

// NodeUsernamePrefix prefixes node usernames.
const NodeUsernamePrefix = "system:node:"

// ServiceAccountUsernamePrefix prefixes ServiceAccount usernames.
const ServiceAccountUsernamePrefix = "system:serviceaccount:"

// ImpersonationIdentityRule grants permission to assume a specific class of
// identity while impersonating. Each rule becomes one RBAC PolicyRule in the
// authentication.k8s.io API group carrying the `impersonate:<mode>` verb.
//
// Identity rules for users, groups, uids, userextras and nodes are cluster-scoped
// and therefore require a ClusterRole target. Only serviceaccounts identity rules
// may be expressed from a namespaced Role.
type ImpersonationIdentityRule struct {
	// Resource is the identity resource this rule grants against.
	// +kubebuilder:validation:Required
	Resource ImpersonationIdentityResource `json:"resource"`

	// ExtraKey is the domain-prefixed extra key when Resource is "userextras".
	// It becomes the RBAC subresource, producing resources: ["userextras/<key>"].
	// Must be lowercase and a valid domain-prefixed path, matching the apiserver's
	// own validateExtra() checks. Required for userextras, forbidden otherwise.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=253
	ExtraKey string `json:"extraKey,omitempty"`

	// Names is the allowlist written to the PolicyRule's resourceNames. Values are
	// usernames, group names, UIDs, ServiceAccount names, node names or extra
	// values depending on Resource. "*" grants every name for this resource.
	//
	// Leave empty only for the associated-node mode, where the apiserver performs
	// the node association check itself and the rule intentionally carries no
	// resourceNames. For every other mode an empty Names list would grant
	// unrestricted impersonation and is rejected.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	Names []string `json:"names,omitempty"`
}

// ImpersonationActionRule grants permission to perform specific verbs on specific
// target resources *while* impersonating in the declared mode. Each rule becomes
// one RBAC PolicyRule carrying `impersonate-on:<mode>:<verb>` verbs against the
// target request's own API group, resource and namespace — there is no group
// override, so apiGroups/resources describe the impersonated request's target.
type ImpersonationActionRule struct {
	// APIGroups are the target API groups. Use "" for the core group and "*" for
	// all groups.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=253
	APIGroups []string `json:"apiGroups"`

	// Resources are the target resources, optionally with a subresource
	// ("pods/log"). Use "*" for all resources.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	Resources []string `json:"resources"`

	// ResourceNames optionally restricts the target resource names.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	ResourceNames []string `json:"resourceNames,omitempty"`

	// Verbs are the *underlying* request verbs, e.g. ["get", "list", "watch"].
	// The operator rewrites each entry to `impersonate-on:<mode>:<verb>`; do not
	// pre-encode the prefix here.
	//
	// The apiserver has no prefix wildcard for action verbs: "*" is accepted by
	// RBAC as a full wildcard, but "impersonate-on:<mode>:*" is not a thing.
	// Passing "*" therefore emits the bare "*" verb, which grants every verb
	// including plain (non-impersonated) access, so it is rejected by validation.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z][a-z0-9]*$`
	Verbs []string `json:"verbs"`
}

// ConstrainedImpersonationSpec is the first-class, typed expression of a
// Kubernetes constrained impersonation (KEP-5284) grant. The operator translates
// it into the exact RBAC PolicyRules the apiserver expects, so operators do not
// need to hand-write magic verb strings such as "impersonate-on:user-info:list".
//
// IMPORTANT — grants union, they do not correlate. The effective permission is
// the full cross product of every granted identity and every granted action. It
// is not possible to express "userA only for pods AND userB only for secrets" in
// a single grant; use two separate RoleDefinitions bound to different subjects.
//
// +kubebuilder:validation:XValidation:rule="self.mode != 'associated-node' || !self.identities.exists(r, has(r.names) && size(r.names) > 0)",message="associated-node identity rules must not set names; the apiserver performs the node association check itself"
// +kubebuilder:validation:XValidation:rule="self.mode != 'associated-node' || self.identities.all(r, r.resource == 'nodes')",message="associated-node mode only supports the 'nodes' identity resource"
// +kubebuilder:validation:XValidation:rule="self.mode != 'arbitrary-node' || self.identities.all(r, r.resource == 'nodes')",message="arbitrary-node mode only supports the 'nodes' identity resource"
// +kubebuilder:validation:XValidation:rule="self.mode != 'serviceaccount' || self.identities.all(r, r.resource == 'serviceaccounts')",message="serviceaccount mode only supports the 'serviceaccounts' identity resource"
// +kubebuilder:validation:XValidation:rule="self.mode != 'user-info' || self.identities.all(r, r.resource != 'nodes' && r.resource != 'serviceaccounts')",message="user-info mode must not use the 'nodes' or 'serviceaccounts' identity resources; those buckets are reserved for the node and serviceaccount modes"
// +kubebuilder:validation:XValidation:rule="self.identities.all(r, r.resource == 'userextras' ? (has(r.extraKey) && size(r.extraKey) > 0) : (!has(r.extraKey) || size(r.extraKey) == 0))",message="extraKey is required for the 'userextras' identity resource and forbidden for all others"
// +kubebuilder:validation:XValidation:rule="!self.identities.exists(r, r.resource == 'groups' && has(r.names) && r.names.exists(n, n == 'system:masters'))",message="impersonating the system:masters group is not allowed"
type ConstrainedImpersonationSpec struct {
	// Mode selects the constrained impersonation mode the generated verbs target.
	// +kubebuilder:validation:Required
	Mode ImpersonationMode `json:"mode"`

	// Identities are the identity allowlist rules. They generate cluster-scoped
	// PolicyRules in the authentication.k8s.io API group with the
	// `impersonate:<mode>` verb.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Identities []ImpersonationIdentityRule `json:"identities"`

	// Actions are the action rules describing which requests may be made while
	// impersonating. They generate PolicyRules with `impersonate-on:<mode>:<verb>`
	// verbs against the target resources.
	//
	// An empty Actions list produces an identity-only grant, which by itself
	// authorizes nothing: the apiserver runs the action check FIRST and falls back
	// to legacy impersonation when it fails. Admission emits a warning in that case.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	Actions []ImpersonationActionRule `json:"actions,omitempty"`
}

// IdentityVerb returns the `impersonate:<mode>` identity verb for the mode.
func IdentityVerb(mode ImpersonationMode) string {
	return ImpersonateVerbPrefix + string(mode)
}

// ActionVerb returns the `impersonate-on:<mode>:<verb>` action verb for the mode
// and underlying request verb.
func ActionVerb(mode ImpersonationMode, verb string) string {
	return ImpersonateOnVerbPrefix + string(mode) + ":" + verb
}

// IsImpersonationVerb reports whether verb is a constrained impersonation verb
// (either an identity or an action verb). It does not report true for the legacy
// bare "impersonate" verb.
func IsImpersonationVerb(verb string) bool {
	return strings.HasPrefix(verb, ImpersonateVerbPrefix) || strings.HasPrefix(verb, ImpersonateOnVerbPrefix)
}

// ParsedImpersonationVerb is the decomposed form of a constrained impersonation verb.
type ParsedImpersonationVerb struct {
	// Mode is the impersonation mode encoded in the verb.
	Mode ImpersonationMode
	// Action is the underlying request verb for `impersonate-on:` verbs and is
	// empty for `impersonate:` identity verbs.
	Action string
	// IsAction is true for `impersonate-on:<mode>:<verb>` verbs.
	IsAction bool
}

// ParseImpersonationVerb decomposes a constrained impersonation verb. It returns
// ok=false for the legacy "impersonate" verb, for plain verbs, and for verbs whose
// mode is not a known constrained impersonation mode.
func ParseImpersonationVerb(verb string) (parsed ParsedImpersonationVerb, ok bool) {
	if action, found := strings.CutPrefix(verb, ImpersonateOnVerbPrefix); found {
		mode, underlying, split := strings.Cut(action, ":")
		if !split || underlying == "" || !isKnownMode(ImpersonationMode(mode)) {
			return ParsedImpersonationVerb{}, false
		}
		return ParsedImpersonationVerb{Mode: ImpersonationMode(mode), Action: underlying, IsAction: true}, true
	}
	if mode, found := strings.CutPrefix(verb, ImpersonateVerbPrefix); found {
		if !isKnownMode(ImpersonationMode(mode)) {
			return ParsedImpersonationVerb{}, false
		}
		return ParsedImpersonationVerb{Mode: ImpersonationMode(mode)}, true
	}
	return ParsedImpersonationVerb{}, false
}

func isKnownMode(mode ImpersonationMode) bool {
	return slices.Contains(AllImpersonationModes(), mode)
}

// RequiresClusterScope reports whether the identity resource can only be granted
// from a ClusterRole. Only serviceaccounts identity rules may live in a
// namespaced Role.
func (r ImpersonationIdentityResource) RequiresClusterScope() bool {
	return r != ImpersonationResourceServiceAccounts
}

// identityRuleResource renders the RBAC resources[] entry for the rule,
// appending the extra key as a subresource for userextras.
func (rule *ImpersonationIdentityRule) identityRuleResource() string {
	if rule.Resource == ImpersonationResourceUserExtras {
		return string(ImpersonationResourceUserExtras) + "/" + rule.ExtraKey
	}
	return string(rule.Resource)
}

// BuildConstrainedImpersonationRules translates a ConstrainedImpersonationSpec
// into the RBAC PolicyRules the apiserver evaluates.
//
// Identity rules land in the authentication.k8s.io API group with the
// `impersonate:<mode>` verb. Action rules keep the caller's target apiGroups and
// resources and carry `impersonate-on:<mode>:<verb>` verbs.
//
// Rules are emitted in a deterministic order so Server-Side Apply does not see
// spurious diffs across reconciles.
func BuildConstrainedImpersonationRules(spec *ConstrainedImpersonationSpec) ([]rbacv1.PolicyRule, error) {
	if spec == nil {
		return nil, nil
	}
	if !isKnownMode(spec.Mode) {
		return nil, fmt.Errorf("unknown constrained impersonation mode %q", spec.Mode)
	}

	// Group identity rules by rendered resource so a single PolicyRule carries the
	// union of names for that resource. This keeps generated roles compact and
	// stable regardless of authoring order.
	namesByResource := make(map[string][]string, len(spec.Identities))
	for i := range spec.Identities {
		rule := &spec.Identities[i]
		resource := rule.identityRuleResource()
		namesByResource[resource] = append(namesByResource[resource], rule.Names...)
	}

	resources := make([]string, 0, len(namesByResource))
	for resource := range namesByResource {
		resources = append(resources, resource)
	}
	sort.Strings(resources)

	identityVerb := IdentityVerb(spec.Mode)
	rules := make([]rbacv1.PolicyRule, 0, len(resources)+len(spec.Actions))
	for _, resource := range resources {
		names := dedupeSorted(namesByResource[resource])
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{authenticationv1.GroupName},
			Resources:     []string{resource},
			ResourceNames: names,
			Verbs:         []string{identityVerb},
		})
	}

	for i := range spec.Actions {
		action := &spec.Actions[i]
		verbs := make([]string, 0, len(action.Verbs))
		for _, verb := range action.Verbs {
			verbs = append(verbs, ActionVerb(spec.Mode, verb))
		}
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     dedupeSortedAllowEmpty(action.APIGroups),
			Resources:     dedupeSorted(action.Resources),
			ResourceNames: dedupeSorted(action.ResourceNames),
			Verbs:         dedupeSorted(verbs),
		})
	}

	return rules, nil
}

// dedupeSorted returns a sorted, de-duplicated copy with empty strings removed.
// It returns nil for an empty result so the field is omitted from generated YAML.
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// dedupeSortedAllowEmpty behaves like dedupeSorted but preserves the empty string,
// which is the legitimate spelling of the core API group in a PolicyRule.
func dedupeSortedAllowEmpty(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// ValidateConstrainedImpersonationSpec performs the semantic validation that CEL
// cannot express, mirroring the apiserver's own constrained-impersonation
// restrictions so invalid grants are rejected at admission instead of silently
// failing at request time.
//
// targetIsClusterRole selects whether cluster-scoped identity resources are
// permitted; a namespaced Role may only carry serviceaccounts identity rules.
func ValidateConstrainedImpersonationSpec(
	spec *ConstrainedImpersonationSpec,
	targetIsClusterRole bool,
	fldPath *field.Path,
) field.ErrorList {
	if spec == nil {
		return nil
	}

	var allErrs field.ErrorList

	if !isKnownMode(spec.Mode) {
		modes := make([]string, 0, len(AllImpersonationModes()))
		for _, m := range AllImpersonationModes() {
			modes = append(modes, string(m))
		}
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("mode"), string(spec.Mode), modes))
		return allErrs
	}

	if len(spec.Identities) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("identities"),
			"at least one identity rule is required"))
	}

	for i := range spec.Identities {
		allErrs = append(allErrs,
			validateIdentityRule(&spec.Identities[i], spec.Mode, targetIsClusterRole, fldPath.Child("identities").Index(i))...)
	}

	for i := range spec.Actions {
		allErrs = append(allErrs, validateActionRule(&spec.Actions[i], fldPath.Child("actions").Index(i))...)
	}

	return allErrs
}

func validateIdentityRule(
	rule *ImpersonationIdentityRule,
	mode ImpersonationMode,
	targetIsClusterRole bool,
	fldPath *field.Path,
) field.ErrorList {
	var allErrs field.ErrorList

	if !slices.Contains(AllImpersonationIdentityResources(), rule.Resource) {
		resources := make([]string, 0, len(AllImpersonationIdentityResources()))
		for _, r := range AllImpersonationIdentityResources() {
			resources = append(resources, string(r))
		}
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("resource"), string(rule.Resource), resources))
		return allErrs
	}

	// Cluster scope: only serviceaccounts identity rules work from a namespaced Role.
	if !targetIsClusterRole && rule.Resource.RequiresClusterScope() {
		allErrs = append(allErrs, field.Forbidden(fldPath.Child("resource"),
			fmt.Sprintf("identity resource %q is cluster-scoped and requires targetRole 'ClusterRole'; only %q may be granted from a namespaced Role",
				rule.Resource, ImpersonationResourceServiceAccounts)))
	}

	allErrs = append(allErrs, validateIdentityRuleModeCompatibility(rule, mode, fldPath)...)
	allErrs = append(allErrs, validateIdentityRuleExtraKey(rule, fldPath)...)
	allErrs = append(allErrs, validateIdentityRuleNames(rule, mode, fldPath)...)

	return allErrs
}

func validateIdentityRuleModeCompatibility(
	rule *ImpersonationIdentityRule,
	mode ImpersonationMode,
	fldPath *field.Path,
) field.ErrorList {
	var allErrs field.ErrorList
	resourcePath := fldPath.Child("resource")

	switch mode {
	case ImpersonationModeAssociatedNode, ImpersonationModeArbitraryNode:
		// Impersonating a node forces Groups=[system:nodes]; nothing else can be set.
		if rule.Resource != ImpersonationResourceNodes {
			allErrs = append(allErrs, field.Forbidden(resourcePath,
				fmt.Sprintf("mode %q only supports the %q identity resource because the apiserver forces the impersonated groups to [%s]",
					mode, ImpersonationResourceNodes, NodesGroup)))
		}
	case ImpersonationModeServiceAccount:
		// Impersonating a ServiceAccount forces its computed group list.
		if rule.Resource != ImpersonationResourceServiceAccounts {
			allErrs = append(allErrs, field.Forbidden(resourcePath,
				fmt.Sprintf("mode %q only supports the %q identity resource because the apiserver computes the impersonated groups from the ServiceAccount namespace",
					mode, ImpersonationResourceServiceAccounts)))
		}
	case ImpersonationModeUserInfo:
		// The user-info bucket is reserved for identities with no Kubernetes schema.
		if rule.Resource == ImpersonationResourceNodes || rule.Resource == ImpersonationResourceServiceAccounts {
			allErrs = append(allErrs, field.Forbidden(resourcePath,
				fmt.Sprintf("mode %q rejects the %q identity resource; node and ServiceAccount identities are reserved for the %q and %q modes",
					mode, rule.Resource, ImpersonationModeArbitraryNode, ImpersonationModeServiceAccount)))
		}
	}

	return allErrs
}

func validateIdentityRuleExtraKey(rule *ImpersonationIdentityRule, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList
	extraKeyPath := fldPath.Child("extraKey")

	if rule.Resource != ImpersonationResourceUserExtras {
		if rule.ExtraKey != "" {
			allErrs = append(allErrs, field.Forbidden(extraKeyPath,
				fmt.Sprintf("extraKey may only be set when resource is %q", ImpersonationResourceUserExtras)))
		}
		return allErrs
	}

	// Mirror the apiserver's validateExtra() key checks so an invalid key is
	// rejected here rather than producing a rule the apiserver always denies.
	if rule.ExtraKey == "" {
		allErrs = append(allErrs, field.Required(extraKeyPath,
			fmt.Sprintf("extraKey is required when resource is %q", ImpersonationResourceUserExtras)))
		return allErrs
	}
	if rule.ExtraKey != strings.ToLower(rule.ExtraKey) {
		allErrs = append(allErrs, field.Invalid(extraKeyPath, rule.ExtraKey,
			"must be lowercase; the apiserver denies non-lowercase extra keys"))
	}
	allErrs = append(allErrs, utilvalidation.IsDomainPrefixedPath(extraKeyPath, rule.ExtraKey)...)

	return allErrs
}

func validateIdentityRuleNames(
	rule *ImpersonationIdentityRule,
	mode ImpersonationMode,
	fldPath *field.Path,
) field.ErrorList {
	var allErrs field.ErrorList
	namesPath := fldPath.Child("names")

	// associated-node rules intentionally carry no resourceNames: the apiserver
	// authorizes against name "*" and does the node association check itself.
	if mode == ImpersonationModeAssociatedNode {
		if len(rule.Names) > 0 {
			allErrs = append(allErrs, field.Forbidden(namesPath,
				fmt.Sprintf("mode %q must not set names; the apiserver authorizes the wildcard node name and performs the association check itself", mode)))
		}
		return allErrs
	}

	if len(rule.Names) == 0 {
		allErrs = append(allErrs, field.Required(namesPath,
			"at least one name is required; an empty allowlist would grant unrestricted impersonation for this resource"))
		return allErrs
	}

	for i, name := range rule.Names {
		namePath := namesPath.Index(i)
		if name == "" {
			allErrs = append(allErrs, field.Invalid(namePath, name, "must not be empty"))
			continue
		}
		allErrs = append(allErrs, validateIdentityName(rule.Resource, name, namePath)...)
	}

	return allErrs
}

func validateIdentityName(
	resource ImpersonationIdentityResource,
	name string,
	namePath *field.Path,
) field.ErrorList {
	var allErrs field.ErrorList

	switch resource {
	case ImpersonationResourceGroups:
		// The apiserver hard-denies system:masters in constrained mode; reject it
		// here too so the grant never reaches the cluster.
		if name == SystemMastersGroup {
			allErrs = append(allErrs, field.Forbidden(namePath,
				fmt.Sprintf("impersonating the %q group is not allowed", SystemMastersGroup)))
		}
	case ImpersonationResourceUsers:
		// users identity rules match the raw Impersonate-User value, which the
		// user-info mode refuses for node and ServiceAccount usernames.
		if name != rbacv1.ResourceAll && isReservedUsername(name) {
			allErrs = append(allErrs, field.Invalid(namePath, name,
				fmt.Sprintf("node (%s) and ServiceAccount (%s) usernames are reserved; use the %q identity resource with mode %q, or %q with mode %q",
					NodeUsernamePrefix, ServiceAccountUsernamePrefix,
					ImpersonationResourceNodes, ImpersonationModeArbitraryNode,
					ImpersonationResourceServiceAccounts, ImpersonationModeServiceAccount)))
		}
	case ImpersonationResourceNodes, ImpersonationResourceServiceAccounts:
		// nodes/serviceaccounts rules take the bare name, not the full username.
		if strings.HasPrefix(name, NodeUsernamePrefix) || strings.HasPrefix(name, ServiceAccountUsernamePrefix) {
			allErrs = append(allErrs, field.Invalid(namePath, name,
				fmt.Sprintf("must be the bare %s name, not the full impersonation username", resource)))
		}
	}

	return allErrs
}

func isReservedUsername(name string) bool {
	return strings.HasPrefix(name, NodeUsernamePrefix) || strings.HasPrefix(name, ServiceAccountUsernamePrefix)
}

// ConstrainedImpersonationWarnings returns non-fatal admission warnings for a
// grant. These cover the KEP's documented footguns that are legal but very
// likely not what the author intended.
func ConstrainedImpersonationWarnings(spec *ConstrainedImpersonationSpec, fieldName string) []string {
	if spec == nil {
		return nil
	}

	var warnings []string

	if len(spec.Actions) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%s: no actions are declared. The apiserver evaluates the impersonate-on:%s:<verb> action check FIRST, "+
				"so an identity-only grant authorizes nothing and every request falls back to legacy impersonation.",
			fieldName, spec.Mode))
	}

	if len(spec.Identities) > 1 && len(spec.Actions) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%s: constrained impersonation grants UNION rather than correlate. The effective permission is the full "+
				"cross product of all %d identities and all %d action rules; it cannot express per-identity actions. "+
				"Split into separate definitions if per-identity scoping is required.",
			fieldName, len(spec.Identities), len(spec.Actions)))
	}

	for i := range spec.Actions {
		if slices.Contains(spec.Actions[i].APIGroups, rbacv1.APIGroupAll) &&
			slices.Contains(spec.Actions[i].Resources, rbacv1.ResourceAll) {
			warnings = append(warnings, fmt.Sprintf(
				"%s.actions[%d]: grants impersonate-on:%s on all resources in all API groups.",
				fieldName, i, spec.Mode))
		}
	}

	return warnings
}

func validateActionRule(rule *ImpersonationActionRule, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	if len(rule.APIGroups) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("apiGroups"),
			`at least one apiGroup is required; use "" for the core group`))
	}
	if len(rule.Resources) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("resources"), "at least one resource is required"))
	}
	if len(rule.Verbs) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("verbs"), "at least one verb is required"))
	}

	for i, verb := range rule.Verbs {
		verbPath := fldPath.Child("verbs").Index(i)
		if verb == "" {
			allErrs = append(allErrs, field.Invalid(verbPath, verb, "must not be empty"))
			continue
		}
		// The apiserver has no impersonate-on:<mode>:* prefix wildcard. Emitting a
		// bare "*" verb would grant unrestricted non-impersonated access instead.
		if verb == rbacv1.VerbAll {
			allErrs = append(allErrs, field.Forbidden(verbPath,
				fmt.Sprintf("constrained impersonation has no action verb wildcard: %q cannot be expressed. "+
					"Enumerate the underlying verbs explicitly.", ActionVerb(ImpersonationModeUserInfo, rbacv1.VerbAll))))
			continue
		}
		// Reject pre-encoded verbs: the operator adds the prefix itself, and a
		// doubly-prefixed verb would never match any request.
		if IsImpersonationVerb(verb) || verb == LegacyImpersonateVerb {
			allErrs = append(allErrs, field.Invalid(verbPath, verb,
				"must be the underlying request verb (e.g. \"list\"); the impersonate-on:<mode>: prefix is added automatically"))
		}
	}

	return allErrs
}
