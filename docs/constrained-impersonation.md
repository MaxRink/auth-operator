<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Constrained Impersonation (KEP-5284)

auth-operator can express Kubernetes **constrained impersonation** grants with a
first-class typed API instead of hand-written magic verb strings.

---

## Table of Contents

- [What constrained impersonation is](#what-constrained-impersonation-is)
- [Version support and compatibility contract](#version-support-and-compatibility-contract)
- [The typed API](#the-typed-api)
- [Modes](#modes)
- [Identity resources](#identity-resources)
- [Action rules](#action-rules)
- [Generated RBAC](#generated-rbac)
- [Guardrails and footguns](#guardrails-and-footguns)
- [Policy governance (RestrictedRoleDefinition)](#policy-governance-restrictedroledefinition)
- [Apply-time impersonation (RBACPolicy)](#apply-time-impersonation-rbacpolicy)
- [Webhook authorizer](#webhook-authorizer)
- [Status and observability](#status-and-observability)
- [Testing](#testing)

---

## What constrained impersonation is

Classic Kubernetes impersonation is all-or-nothing: a subject granted the
`impersonate` verb on `users` can impersonate that user for **any** request.
Constrained impersonation (KEP-5284) splits this into two independent checks:

| Check | Verb | Answers |
|---|---|---|
| **Identity** | `impersonate:<mode>` | *Which identities may I assume?* |
| **Action** | `impersonate-on:<mode>:<verb>` | *What may I do while impersonating?* |

Both must pass. The **action check runs first**; if it fails the request falls back
to legacy impersonation. The impersonator never needs the target permission itself
— the impersonated identity does.

Identity checks are evaluated against the `authentication.k8s.io` API group
(legacy impersonation uses the core `""` group). No new HTTP headers are involved:
the same `Impersonate-User`, `Impersonate-Uid`, `Impersonate-Group` and
`Impersonate-Extra-<key>` headers are used, and `rest.ImpersonationConfig` is
unchanged.

---

## Version support and compatibility contract

| Kubernetes | Gate state | Operator behaviour |
|---|---|---|
| **< 1.35** | gate does not exist | Grants apply and are **inert**. Condition `ConstrainedImpersonationEffective=False`, reason `FeatureGateDisabled` (or `VersionTooOld`), plus a Warning event. Reconciliation still succeeds. |
| **1.35, gate off** (default) | alpha, off | Same as above. |
| **1.35, gate on** | alpha, explicit | Grants are live. Condition `True`, reason `FeatureGateEnabled`. |
| **1.36+, default** | beta, on | Grants are live. Condition `True`, reason `FeatureGateEnabled`. |
| **1.36+, gate off** | beta, explicit off | Grants apply and are inert. Condition `False`, reason `FeatureGateDisabled`. |

Key guarantees:

- **The operator never assumes the gate is on** and never refuses to start.
- **All new CRD fields are optional** with zero-value defaults that reproduce
  today's behaviour exactly. Existing objects reconcile byte-identically when the
  new fields are unset.
- **Generated RBAC stays valid on old clusters.** RBAC verbs and resources are
  free-form strings, so a ClusterRole containing `impersonate:user-info` is
  accepted by any API server — it simply grants nothing. That silent-no-privilege
  failure mode is surfaced explicitly (see
  [Status and observability](#status-and-observability)) rather than being reported
  as a plain success.
- **Legacy impersonation behaviour is unchanged.** The bare `impersonate` verb
  continues to be authorized exactly as before on every version.

### How the gate is detected

The operator probes at runtime rather than comparing versions:

1. Read the API server's own `kubernetes_feature_enabled{name="ConstrainedImpersonation"}`
   gauge from `/metrics`. This is authoritative because it reflects
   `--feature-gates` overrides, so a gate explicitly disabled on 1.36 is detected
   correctly.
2. If `/metrics` is unreadable, fall back to a server-version comparison, isolated
   in a single helper. Unparseable or unknown versions produce `Unknown`, never a
   guess. A 1.35 server also yields `Unknown` because the gate is alpha there and
   only the metric can reveal its effective state.

Reading `/metrics` requires one new read-only grant
(`nonResourceURLs: ["/metrics"], verbs: ["get"]`), controlled by
`controller.constrainedImpersonation.capabilityDetection` (default `true`). With it
disabled the operator still works; it just reports `Unknown` more often.

There is deliberately **no** SubjectAccessReview-based probe: a
SelfSubjectAccessReview for `impersonate:user-info` succeeds on any version because
verbs are free-form strings, so it would be actively misleading.

---

## The typed API

`RoleDefinition` and `RestrictedRoleDefinition` both accept
`spec.constrainedImpersonation`:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: jane-pod-reader
spec:
  targetRole: ClusterRole
  targetName: jane-pod-reader
  scopeNamespaced: false
  # Close the legacy fallback so the constraint cannot be silently defeated.
  restrictedVerbs: ["impersonate"]
  constrainedImpersonation:
    mode: user-info
    identities:
      - resource: users
        names: ["jane.doe@example.com"]
    actions:
      - apiGroups: [""]
        resources: ["pods"]
        verbs: ["list", "watch"]
```

The raw path still works: `impersonate:<mode>` and `impersonate-on:<mode>:<verb>`
are now accepted in `spec.restrictedVerbs` and
`spec.restrictedApis[].verbs`, and in `RBACPolicy`'s
`spec.roleLimits.forbiddenVerbs`.

### Why a typed API

The alternative — letting users type the verb strings directly — was rejected
because:

- The verb spellings have **no exported Go constants upstream**; they are built
  inline in unexported apiserver code. A typo produces a rule that is accepted by
  RBAC and silently never matches.
- The identity API group (`authentication.k8s.io`), the `userextras/<key>`
  subresource form, the "associated-node takes no resourceNames" rule and the
  forced group lists for nodes and ServiceAccounts are all non-obvious invariants
  that a typed API can enforce at admission time.
- Every mode restriction (which identity resources are legal, which usernames are
  reserved) becomes checkable instead of being discovered at request time as an
  opaque 403.

The typed spec generates the rules; the raw verb path remains for escape hatches
and for restricting/forbidding grants.

---

## Modes

The API server derives the mode from the `Impersonate-User` value and the header
set — it cannot be chosen by the client. `spec.constrainedImpersonation.mode`
declares which mode the generated verbs target.

| Mode | Selected when | Identity resource | Names |
|---|---|---|---|
| `associated-node` | user is `system:node:<name>`, only the username is set, and the requesting SA's `authentication.kubernetes.io/node-name` extra matches | `nodes` | must be empty |
| `arbitrary-node` | user is `system:node:<name>`, only the username is set | `nodes` | node names |
| `serviceaccount` | user is `system:serviceaccount:<ns>:<name>`, only the username is set | `serviceaccounts` | SA names |
| `user-info` | user is neither a node nor a ServiceAccount | `users`, `groups`, `uids`, `userextras` | as appropriate |

Evaluation order is `associated-node`, `arbitrary-node`, `serviceaccount`,
`user-info`, then legacy.

---

## Identity resources

| Resource | RBAC form | Matches |
|---|---|---|
| `users` | `users` | the `Impersonate-User` value |
| `groups` | `groups` | each `Impersonate-Group` value (one check per group) |
| `uids` | `uids` | the `Impersonate-Uid` value |
| `userextras` | `userextras/<extraKey>` | each `Impersonate-Extra-<key>` value |
| `serviceaccounts` | `serviceaccounts` | the SA name, namespaced |
| `nodes` | `nodes` | the node name |

Only `serviceaccounts` identity rules may be granted from a **namespaced Role**;
everything else is cluster-scoped and requires `targetRole: ClusterRole`.

`userextras` requires `extraKey`, which must be a lowercase, domain-prefixed path
— the same validation the API server applies.

---

## Action rules

Action rules describe the **target** request, using its own API group, resource and
namespace. There is no group override.

```yaml
    actions:
      - apiGroups: [""]
        resources: ["pods", "pods/log"]
        resourceNames: ["specific-pod"]   # optional
        verbs: ["get", "list", "watch"]
```

`verbs` are the **underlying** request verbs. The operator rewrites each to
`impersonate-on:<mode>:<verb>`; do not pre-encode the prefix.

There is no prefix wildcard: `impersonate-on:user-info:*` cannot be expressed.
Passing `verbs: ["*"]` would emit a bare `*`, granting unrestricted
non-impersonated access, so it is rejected. Enumerate verbs explicitly.

---

## Generated RBAC

The example above produces:

```yaml
rules:
# identity rule — authentication.k8s.io group
- apiGroups: ["authentication.k8s.io"]
  resources: ["users"]
  resourceNames: ["jane.doe@example.com"]
  verbs: ["impersonate:user-info"]
# action rule — the target request's own group and resource
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["impersonate-on:user-info:list", "impersonate-on:user-info:watch"]
```

Rules are emitted in a deterministic order and identity rules for the same resource
are merged, so Server-Side Apply sees no spurious diffs across reconciles.

Generated rules are **appended** to the discovery-derived rules of the target role,
so a definition can combine ordinary resource access with an impersonation grant.
`constrainedImpersonation` is mutually exclusive with `aggregateFrom`, whose rules
are owned by the Kubernetes aggregation controller.

---

## Guardrails and footguns

### Enforced at admission (rejected)

| Guardrail | Why |
|---|---|
| `system:masters` in a group grant | The API server hard-denies it in constrained mode; the grant would be dead weight and misleading. |
| empty-string group name | Denied by the API server. |
| `associated-node` with `names` | The API server authorizes the wildcard node name and does the association check itself. |
| wrong identity resource for the mode | Node and SA impersonation force the group list; `user-info` refuses node and SA usernames. |
| node/SA usernames in a `users` rule | Reserved buckets; use the `nodes` or `serviceaccounts` resource with the matching mode. |
| full usernames in `nodes`/`serviceaccounts` rules | Those rules take the bare name. |
| invalid `extraKey` (empty, non-lowercase, not domain-prefixed) | Mirrors the API server's `validateExtra()`. |
| `verbs: ["*"]` in an action rule | No prefix wildcard exists; a bare `*` would over-grant. |
| pre-encoded action verbs | Would produce a doubly-prefixed verb that never matches. |
| cluster-scoped identity resource on a namespaced Role | Would never match. |
| empty `names` outside `associated-node` | Would grant unrestricted impersonation for that resource. |
| **header mixing** in `RBACPolicy.spec.impersonation` | See below. |

### The header-mixing trap

The API server selects the `serviceaccount` and node modes **only when
`Impersonate-User` is the only impersonation header set**. Adding
`Impersonate-Uid`, `Impersonate-Group` or `Impersonate-Extra-*` alongside a
`system:serviceaccount:...` or `system:node:...` username silently skips those
modes, falls through to `user-info` (which refuses those usernames) and then to
**legacy impersonation** — bypassing every constrained-impersonation restriction.

`RBACPolicy.spec.impersonation` therefore rejects combining `serviceAccountRef`
with `uid`, `groups` or `extra`, both via CEL and in the admission webhook.

### Warned about (admitted with a warning)

| Warning | Why |
|---|---|
| no `actions` declared | The action check runs first, so an identity-only grant authorizes nothing and every request falls back to legacy. |
| multiple identities plus actions | **Grants union, they do not correlate.** The effective permission is the full cross product of all identities and all actions. "userA only for pods AND userB only for secrets" is not expressible in one grant — use separate definitions. |
| `apiGroups: ["*"]` with `resources: ["*"]` | Grants impersonated access to everything. |

### The legacy-fallback escape hatch

A pre-existing blanket legacy `impersonate` grant **wins by fallback** and silently
defeats any constraint. The operator only reports a grant as effective when the
definition explicitly excludes that verb:

```yaml
  restrictedVerbs: ["impersonate"]   # or ["*"]
```

Otherwise `ConstrainedImpersonationEffective` is `False` with reason
`LegacyFallbackReachable`. A `RBACPolicy` can require this via
`roleLimits.constrainedImpersonation.forbidLegacyFallback: true`.

---

## Policy governance (RestrictedRoleDefinition)

Constrained impersonation is **deny by default** for restricted definitions: a
policy must opt in.

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: tenant-policy
spec:
  appliesTo:
    namespaces: ["*"]
  roleLimits:
    allowClusterRoles: true
    # Generic verb denylists also match the generated verbs, with wildcards:
    forbiddenVerbs: ["impersonate:arbitrary-node", "impersonate-on:*"]
    constrainedImpersonation:
      allowed: true
      allowedModes: ["user-info"]
      allowedIdentityResources: ["users", "groups"]
      identityNameLimits:
        allowedSuffixes: ["@example.com"]
        forbiddenNames: ["root@example.com"]
      forbiddenActionVerbs: ["delete", "deletecollection"]
      forbidLegacyFallback: true
      maxIdentityNames: 32
```

| Field | Effect |
|---|---|
| `allowed` | Master switch. `false` (the default) forbids all grants. |
| `allowedModes` | Restricts the mode. Empty means all modes. |
| `allowedIdentityResources` | Restricts identity resources. Empty means all. |
| `identityNameLimits` | Allow/deny names, prefixes and suffixes for identity names. Denials win; a non-empty allowlist is default-deny. |
| `forbiddenActionVerbs` | Forbids underlying verbs (bare form, wildcards supported). |
| `forbidLegacyFallback` | Requires `impersonate` in `restrictedVerbs`. |
| `maxIdentityNames` | Caps the total allowlist size across all identity rules. |

`roleLimits.forbiddenVerbs` and `roleLimits.forbiddenResourceVerbs` additionally
match the generated verb strings directly, so an existing policy can forbid
`impersonate:*`-style grants without knowing about the typed API.

Violations appear in `status.policyViolations` and set
`PolicyCompliant=False`.

---

## Apply-time impersonation (RBACPolicy)

`RBACPolicy.spec.impersonation` controls the identity the operator uses when
applying restricted resources. It now exposes the full `user-info` identity:

```yaml
spec:
  impersonation:
    enabled: true
    userName: rbac-applier@example.com
    uid: "abc-123"
    groups: ["platform-appliers"]
    extra:
      - key: example.com/scopes
        values: ["rbac-write"]
    mode: user-info      # advisory; validated against the identity
```

or, for a ServiceAccount identity (mutually exclusive with the above):

```yaml
spec:
  impersonation:
    enabled: true
    serviceAccountRef:
      namespace: platform
      name: rbac-applier
    mode: serviceaccount
```

`mode` is **advisory**: the API server derives the mode itself. Admission verifies
that the configured identity actually selects the declared mode, turning a silent
legacy fallback into an admission error.

Node usernames are rejected as an apply identity: node impersonation forces
`Groups=[system:nodes]`, which cannot write RBAC objects.

Note: at four or more groups the API server first attempts a single wildcard (`*`)
group authorization check before falling back to per-group checks.

---

## Webhook authorizer

### Impersonation verb policy

KEP-5284 warns that *a permissive webhook that allows unknown verbs silently grants
constrained impersonation*. Because Kubernetes RBAC treats `verbs: ["*"]` as
matching every verb — including `impersonate:user-info` — any pre-existing wildcard
allow rule would become an unintended impersonation grant the moment the gate turns
on.

`WebhookAuthorizer.spec.impersonationVerbPolicy` controls this:

| Value | Behaviour |
|---|---|
| `RequireExplicitVerb` (**default**) | A constrained impersonation verb only matches a rule that lists it **literally**. `verbs: ["*"]` does not match. Ordinary verbs, including legacy `impersonate`, are unaffected. |
| `AllowWildcard` | Plain RBAC semantics: `verbs: ["*"]` matches impersonation verbs too. |
| `Deny` | Explicitly denies any matching constrained impersonation request regardless of the principal lists — a cluster-wide kill switch. |

The default is applied in code as well as in the CRD, so authorizers stored before
the field existed also get the fail-safe behaviour.

### UID and extra principal matchers

`Principal` gained `uid` and `extra`, and the SAR handler now reads `spec.uid` and
`spec.extra` (previously ignored entirely):

```yaml
spec:
  impersonationVerbPolicy: RequireExplicitVerb
  allowedPrincipals:
    - user: system:serviceaccount:kube-system:node-agent
      uid: "c0ffee-..."                      # pin to one identity instance
      extra:
        - key: authentication.kubernetes.io/node-name
          values: ["worker-1"]               # or ["*"] for "present with any value"
  resourceRules:
    - verbs: ["impersonate:associated-node"]
      apiGroups: ["authentication.k8s.io"]
      resources: ["nodes"]
```

Matching semantics: every populated matcher kind must match (AND), while
multi-valued matchers such as `groups` and each extra's `values` match on
intersection (OR). `user` and `groups` remain OR-matched with each other for
backwards compatibility. A principal with **no** matcher never matches.

`authentication.kubernetes.io/node-name` is the attribute the `associated-node`
mode is keyed on, which is what makes node-scoped authorization decisions
expressible.

---

## Status and observability

### Condition

`RoleDefinition` and `RestrictedRoleDefinition` gain
`ConstrainedImpersonationEffective`:

| Status | Reason | Meaning |
|---|---|---|
| `True` | `FeatureGateEnabled` | Grants are live. |
| `False` | `FeatureGateDisabled` | The gate is off or the API server predates 1.35. Grants are **inert**. |
| `False` | `LegacyFallbackReachable` | `impersonate` is not in `restrictedVerbs`, so a blanket legacy grant can silently defeat the constraint. |
| `Unknown` | `FeatureStateUnknown` | Detection was inconclusive (no `/metrics` access, unparseable version, or a 1.35 alpha server). |

The condition is **not** wired into `Ready`: the operator applied exactly what was
asked for, and failing reconciliation would make the operator unusable on clusters
where `/metrics` is unreadable. It is a warning surface. A Warning event is emitted
alongside a non-`True` state.

### API server metrics and audit

The API server itself exposes (ALPHA stability, subsystem `impersonation`, labels
`{mode, decision}`):

- `apiserver_impersonation_attempts_total`
- `apiserver_impersonation_attempts_duration_seconds`
- `apiserver_impersonation_authorization_attempts_total`
- `apiserver_impersonation_authorization_attempts_duration_seconds`

Audit events gain `authenticationMetadata.impersonationConstraint`, set to the
identity verb used and omitted for legacy impersonation. Set the audit policy level
to at least `Metadata` to capture it. Requests over 500ms also get the
`apiserver.latency.k8s.io/impersonation` annotation.

---

## Testing

```bash
# Unit + envtest, with the gate at the API server default (on for 1.36).
make test

# Same suites with the gate explicitly disabled.
make test-envtest-constrained-impersonation-disabled

# Real kind e2e, gate enabled.
make test-e2e-constrained-impersonation

# Real kind e2e, gate disabled — asserts graceful degradation.
make test-e2e-constrained-impersonation-disabled
```

The envtest suites accept `AUTH_OPERATOR_ENVTEST_FEATURE_GATES` using
kube-apiserver `--feature-gates` syntax, so any gate combination can be exercised
without touching test code.

The e2e suite reads `E2E_CONSTRAINED_IMPERSONATION` (`enabled` or `disabled`) and
asserts different outcomes for the same inputs, which is how the compatibility
matrix is verified end to end against a live API server.
