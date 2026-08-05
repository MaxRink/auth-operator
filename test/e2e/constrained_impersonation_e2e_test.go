//go:build e2e

/*
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

// Constrained impersonation (KEP-5284) end-to-end tests.
//
// These specs run against a live kind apiserver and actually perform impersonated
// requests, rather than only asserting that the generated RBAC looks right. That
// distinction matters: the verb spellings, the authentication.k8s.io API group and
// the action-check-runs-first ordering are all only observable against a real
// apiserver.
//
// The suite runs in two configurations, selected by E2E_CONSTRAINED_IMPERSONATION:
//
//	enabled  — make test-e2e-constrained-impersonation
//	           kind cluster with --feature-gates=ConstrainedImpersonation=true
//	disabled — make test-e2e-constrained-impersonation-disabled
//	           kind cluster with --feature-gates=ConstrainedImpersonation=false
//
// With the gate disabled the same grants must still apply cleanly, must be
// reported as inert via the ConstrainedImpersonationEffective condition, and the
// impersonated request must be DENIED — while a legacy `impersonate` grant keeps
// working. That is the backwards-compatibility contract.
var _ = Describe("Constrained Impersonation (KEP-5284)", Ordered, Label("constrained-impersonation"), func() {
	const (
		ciNamespace  = "e2e-constrained-impersonation"
		ciOperatorNS = "auth-operator-ci-e2e"
		ciRelease    = "auth-operator-ci-e2e"
		ciChartPath  = "chart/auth-operator"

		// The tenant ServiceAccount that will act as the impersonator.
		impersonatorSA = "e2e-impersonator"
		// The identity it is allowed to impersonate.
		targetUser = "e2e-target-user@example.com"
		// An identity it is NOT allowed to impersonate, for the negative case.
		forbiddenUser = "e2e-forbidden-user@example.com"

		grantRDName        = "e2e-ci-grant"
		grantClusterRole   = "e2e-ci-grant-role"
		legacyRDName       = "e2e-ci-legacy"
		legacyClusterRole  = "e2e-ci-legacy-role"
		targetRDName       = "e2e-ci-target"
		targetClusterRole  = "e2e-ci-target-role"
		ciReconcileTimeout = 3 * time.Minute
		ciPollInterval     = 3 * time.Second
	)

	// gateEnabled reflects how the cluster under test was configured. The specs
	// assert different outcomes for the same inputs depending on it, which is
	// exactly the compatibility matrix the feature has to satisfy.
	gateEnabled := os.Getenv("E2E_CONSTRAINED_IMPERSONATION") != "disabled"

	// impersonatorKubeconfig is a dedicated kubeconfig whose ONLY credential is the
	// impersonator ServiceAccount's bearer token. It is built in BeforeAll and is
	// what makes these assertions meaningful.
	var impersonatorKubeconfig string

	// canI reports whether the impersonator, while impersonating impersonatedUser,
	// may actually perform verb on resource. It issues a REAL request rather than a
	// SubjectAccessReview.
	//
	// Three traps make it easy to write an assertion here that silently proves
	// nothing, and all three were hit while developing this suite:
	//
	//  1. kubectl's --as is a plain string flag, so `--as A --as B` does NOT chain.
	//     The second value overwrites the first, leaving the test's own identity
	//     impersonating only B.
	//  2. Passing --token alongside a kubeconfig that carries a client certificate
	//     does not switch identity either: the client cert wins, so the request is
	//     still authenticated as the kubeconfig's (admin) user. Hence the dedicated
	//     token-only kubeconfig, whose identity is verified when it is built.
	//  3. `kubectl auth can-i --as X` does not probe the verb you name. It CREATEs a
	//     selfsubjectaccessreviews resource while impersonating, so under constrained
	//     impersonation the apiserver looks for
	//     impersonate-on:user-info:create on selfsubjectaccessreviews --
	//     NOT impersonate-on:user-info:list on configmaps. An SSAR-based probe
	//     therefore answers a different question than the grant expresses.
	//
	// Issuing the real request is the only way to exercise the intended action rule.
	canI := func(impersonatedUser, verb, resource, namespace string) (bool, string) {
		args := make([]string, 0, 6)
		switch verb {
		case "list":
			args = append(args, "get", resource)
		case "get":
			// Read a resource that always exists in a fresh namespace.
			args = append(args, "get", resource, "kube-root-ca.crt")
		case "delete":
			args = append(args, "delete", resource, "kube-root-ca.crt", "--dry-run=server")
		default:
			args = append(args, verb, resource)
		}
		args = append(args,
			"-n", namespace,
			"--kubeconfig", impersonatorKubeconfig,
			"--as", impersonatedUser,
		)
		cmd := utils.CommandContext(context.Background(), "kubectl", args...)
		out, err := utils.Run(cmd)
		text := strings.TrimSpace(string(out))
		// A forbidden request exits non-zero with a "forbidden"/"cannot" message; any
		// other error (e.g. a genuine connectivity failure) also counts as not
		// allowed, and the returned text is surfaced by the callers for diagnosis.
		return err == nil, text
	}

	// buildImpersonatorKubeconfig writes a kubeconfig that authenticates purely as
	// the impersonator ServiceAccount: same cluster and CA as the test's own
	// kubeconfig, but a fresh user entry holding only the SA token, with no client
	// certificate that could take precedence.
	buildImpersonatorKubeconfig := func() (string, error) {
		run := func(args ...string) (string, error) {
			out, err := utils.Run(utils.CommandContext(context.Background(), "kubectl", args...))
			return strings.TrimSpace(string(out)), err
		}

		token, err := run("create", "token", impersonatorSA, "-n", ciNamespace, "--duration", "60m")
		if err != nil {
			return "", fmt.Errorf("mint impersonator token: %w", err)
		}

		path := filepath.Join(os.TempDir(), fmt.Sprintf("ao-e2e-impersonator-%d.kubeconfig", os.Getpid()))
		// Start from a flattened copy of the current context so the server address
		// and CA bundle are correct, then replace the credential outright.
		raw, err := run("config", "view", "--minify", "--raw", "--flatten", "-o", "yaml")
		if err != nil {
			return "", fmt.Errorf("export kubeconfig: %w", err)
		}
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			return "", fmt.Errorf("write kubeconfig: %w", err)
		}

		const saUser = "e2e-impersonator-sa"
		if _, err := run("--kubeconfig", path, "config", "set-credentials", saUser, "--token", token); err != nil {
			return "", fmt.Errorf("set impersonator credentials: %w", err)
		}
		ctxName, err := run("--kubeconfig", path, "config", "current-context")
		if err != nil {
			return "", fmt.Errorf("read current context: %w", err)
		}
		if _, err := run("--kubeconfig", path, "config", "set-context", ctxName, "--user", saUser); err != nil {
			return "", fmt.Errorf("point context at impersonator user: %w", err)
		}

		// Verify the identity actually switched. Without this the whole suite can
		// silently degrade to asserting cluster-admin's permissions.
		who, err := run("--kubeconfig", path, "auth", "whoami", "-o", "jsonpath={.status.userInfo.username}")
		if err != nil {
			return "", fmt.Errorf("verify impersonator identity: %w", err)
		}
		want := fmt.Sprintf("system:serviceaccount:%s:%s", ciNamespace, impersonatorSA)
		if who != want {
			return "", fmt.Errorf("kubeconfig authenticates as %q, want %q", who, want)
		}
		return path, nil
	}

	// applyManifest applies a YAML document from a string.
	applyManifest := func(manifest string) error {
		return utils.ApplyManifest(manifest)
	}

	conditionStatus := func(resource, name, conditionType string) string {
		jsonPath := fmt.Sprintf(`{.status.conditions[?(@.type=="%s")].status}`, conditionType)
		value, err := utils.GetResourceField(resource, name, "", jsonPath)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(value)
	}

	conditionReason := func(resource, name, conditionType string) string {
		jsonPath := fmt.Sprintf(`{.status.conditions[?(@.type=="%s")].reason}`, conditionType)
		value, err := utils.GetResourceField(resource, name, "", jsonPath)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(value)
	}

	BeforeAll(func() {
		setSuiteOutputDir("constrained-impersonation")

		By(fmt.Sprintf("Running with ConstrainedImpersonation gate expected %s",
			map[bool]string{true: "ENABLED", false: "DISABLED"}[gateEnabled]))

		By("Reporting the API server's view of the feature gate")
		// Informational only: the assertions below key off the harness variable so a
		// misconfigured cluster produces a clear failure rather than a silent skip.
		cmd := utils.CommandContext(context.Background(), "kubectl", "get", "--raw", "/metrics")
		if out, err := utils.Run(cmd); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "ConstrainedImpersonation") {
					_, _ = fmt.Fprintf(GinkgoWriter, "apiserver: %s\n", strings.TrimSpace(line))
				}
			}
		} else {
			_, _ = fmt.Fprintf(GinkgoWriter, "could not read apiserver /metrics: %v\n", err)
		}

		By("Creating the constrained impersonation test namespace")
		createNamespaceIfNotExists(ciNamespace, nil)

		By("Loading the operator image into the kind cluster")
		Expect(utils.LoadImageToKindClusterWithName(projectImage)).To(Succeed())

		By("Installing auth-operator via Helm")
		imageRepo := strings.Split(projectImage, ":")[0]
		imageTag := strings.Split(projectImage, ":")[1]
		if imageTag == "" {
			imageTag = defaultImageTag
		}
		helmCmd := utils.CommandContext(context.Background(), "helm", "upgrade", "--install", ciRelease, ciChartPath,
			"--namespace", ciOperatorNS,
			"--create-namespace",
			"--set", "image.repository="+imageRepo,
			"--set", "image.tag="+imageTag,
			"--set", "image.pullPolicy=IfNotPresent",
			// Capability detection needs read access to the apiserver /metrics endpoint.
			"--set", "controller.constrainedImpersonation.capabilityDetection=true",
			"--wait", "--timeout", "5m",
		)
		_, err := utils.Run(helmCmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install auth-operator via Helm")

		By("Waiting for the controller and webhook to be ready")
		Expect(utils.WaitForDeploymentAvailable("control-plane=controller-manager", ciOperatorNS, deployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", ciOperatorNS, deployTimeout)).To(Succeed())
		Expect(utils.WaitForWebhookReady(deployTimeout)).To(Succeed())

		By("Creating the impersonator ServiceAccount")
		Expect(applyManifest(fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
`, impersonatorSA, ciNamespace))).To(Succeed())

		By("Building a kubeconfig that authenticates as the impersonator ServiceAccount")
		// The impersonator must authenticate as itself for the impersonation
		// assertions to mean anything; see the canI comment.
		Eventually(func() error {
			path, err := buildImpersonatorKubeconfig()
			if err != nil {
				return err
			}
			impersonatorKubeconfig = path
			return nil
		}, ciReconcileTimeout, ciPollInterval).Should(Succeed())
		Expect(impersonatorKubeconfig).NotTo(BeEmpty())
	})

	AfterAll(func() {
		if utils.ShouldTeardown() {
			By("Uninstalling the Helm release")
			cmd := utils.CommandContext(context.Background(), "helm", "uninstall", ciRelease, "--namespace", ciOperatorNS)
			_, _ = utils.Run(cmd)
		}
		By("Cleaning up constrained impersonation test resources")
		for _, name := range []string{grantRDName, legacyRDName, targetRDName} {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", name, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}
		for _, name := range []string{
			"e2e-ci-grant-binding", "e2e-ci-legacy-binding", "e2e-ci-legacy-target-binding", "e2e-ci-target-binding",
		} {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete", "clusterrolebinding", name, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}
		utils.CleanupNamespace(ciNamespace)
	})

	Context("Typed API generates the exact RBAC the apiserver expects", func() {
		It("reconciles a constrained impersonation RoleDefinition into the correct ClusterRole", func() {
			By("Creating a RoleDefinition with a typed constrainedImpersonation grant")
			Expect(applyManifest(fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: %s
spec:
  targetRole: ClusterRole
  targetName: %s
  scopeNamespaced: false
  # Restrict every discovered verb so the generated role carries ONLY the
  # constrained impersonation rules. This also closes the legacy fallback,
  # which the operator requires before reporting the grant as effective.
  restrictedVerbs: ["*"]
  constrainedImpersonation:
    mode: user-info
    identities:
      - resource: users
        names: ["%s"]
    actions:
      - apiGroups: [""]
        resources: ["configmaps"]
        verbs: ["list", "get"]
`, grantRDName, grantClusterRole, targetUser))).To(Succeed())

			By("Waiting for the RoleDefinition to become Ready")
			Eventually(func() string {
				return conditionStatus("roledefinition", grantRDName, "Ready")
			}, ciReconcileTimeout, ciPollInterval).Should(Equal("True"))

			By("Verifying the generated ClusterRole carries the identity rule in authentication.k8s.io")
			Eventually(func() (string, error) {
				return utils.GetResourceField("clusterrole", grantClusterRole, "", "{.rules}")
			}, ciReconcileTimeout, ciPollInterval).Should(And(
				ContainSubstring("authentication.k8s.io"),
				ContainSubstring("users"),
				ContainSubstring(targetUser),
				ContainSubstring("impersonate:user-info"),
			))

			By("Verifying the generated ClusterRole carries the action rule with the impersonate-on verbs")
			rules, err := utils.GetResourceField("clusterrole", grantClusterRole, "", "{.rules}")
			Expect(err).NotTo(HaveOccurred())
			Expect(rules).To(ContainSubstring("impersonate-on:user-info:list"))
			Expect(rules).To(ContainSubstring("impersonate-on:user-info:get"))
			Expect(rules).To(ContainSubstring("configmaps"))

			By("Binding the generated ClusterRole to the impersonator ServiceAccount")
			Expect(applyManifest(fmt.Sprintf(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: e2e-ci-grant-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %s
subjects:
  - kind: ServiceAccount
    name: %s
    namespace: %s
`, grantClusterRole, impersonatorSA, ciNamespace))).To(Succeed())

			By("Granting the impersonated target user permission to read configmaps")
			// The impersonator never needs the target permission itself, but the
			// impersonated identity does, otherwise the request is denied for an
			// unrelated reason and the test would prove nothing.
			Expect(applyManifest(fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: %s
spec:
  targetRole: ClusterRole
  targetName: %s
  scopeNamespaced: true
  restrictedApis:
    - name: "*"
`, targetRDName, targetClusterRole))).To(Succeed())
			Eventually(func() string {
				return conditionStatus("roledefinition", targetRDName, "Ready")
			}, ciReconcileTimeout, ciPollInterval).Should(Equal("True"))

			// The generated role above is intentionally empty, so grant the target user
			// configmap read access with a plain ClusterRole instead.
			Expect(applyManifest(fmt.Sprintf(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: e2e-ci-target-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - kind: User
    name: %s
    apiGroup: rbac.authorization.k8s.io
`, targetUser))).To(Succeed())
		})

		It("reports the ConstrainedImpersonationEffective condition matching the cluster's gate state", func() {
			// This is the graceful-degradation surface. On a cluster with the gate off,
			// the RoleDefinition still reconciles to Ready, but this condition is False
			// with reason FeatureGateDisabled — never a silent success.
			expectedStatus := "True"
			if !gateEnabled {
				expectedStatus = "False"
			}
			Eventually(func() string {
				return conditionStatus("roledefinition", grantRDName, "ConstrainedImpersonationEffective")
			}, ciReconcileTimeout, ciPollInterval).Should(Equal(expectedStatus),
				"ConstrainedImpersonationEffective must reflect the API server's actual feature gate state")

			reason := conditionReason("roledefinition", grantRDName, "ConstrainedImpersonationEffective")
			_, _ = fmt.Fprintf(GinkgoWriter, "ConstrainedImpersonationEffective reason: %s\n", reason)
			if gateEnabled {
				Expect(reason).To(Equal("FeatureGateEnabled"))
			} else {
				Expect(reason).To(Equal("FeatureGateDisabled"))
			}
		})

		It("keeps the RoleDefinition Ready regardless of the gate state", func() {
			// Backwards compatibility: an inert grant is a warning, not a reconcile
			// failure. The operator did apply exactly what was asked for.
			Expect(conditionStatus("roledefinition", grantRDName, "Ready")).To(Equal("True"))
			Expect(conditionStatus("roledefinition", grantRDName, "Stalled")).NotTo(Equal("True"))
		})
	})

	Context("Impersonated requests against the live apiserver", func() {
		It("allows the granted identity and action when the feature gate is enabled", func() {
			if !gateEnabled {
				Skip("requires the ConstrainedImpersonation feature gate to be enabled")
			}

			By("Performing a configmap list while impersonating the granted target user")
			Eventually(func() bool {
				allowed, detail := canI(targetUser, "list", "configmaps", ciNamespace)
				if !allowed {
					_, _ = fmt.Fprintf(GinkgoWriter, "can-i (granted): %s\n", detail)
				}
				return allowed
			}, ciReconcileTimeout, ciPollInterval).Should(BeTrue(),
				"the impersonator should be allowed to list configmaps while impersonating the granted user")
		})

		It("denies an identity that was NOT granted", func() {
			if !gateEnabled {
				Skip("requires the ConstrainedImpersonation feature gate to be enabled")
			}

			By("Attempting to impersonate a user outside the identity allowlist")
			// The identity rule lists only targetUser in resourceNames, so this must be
			// denied even though the action rule would permit the verb.
			Consistently(func() bool {
				allowed, detail := canI(forbiddenUser, "list", "configmaps", ciNamespace)
				if allowed {
					_, _ = fmt.Fprintf(GinkgoWriter, "can-i (forbidden identity) unexpectedly allowed: %s\n", detail)
				}
				return allowed
			}, 20*time.Second, ciPollInterval).Should(BeFalse(),
				"impersonating an identity outside the allowlist must be denied")
		})

		It("denies a verb that was NOT granted by any action rule", func() {
			if !gateEnabled {
				Skip("requires the ConstrainedImpersonation feature gate to be enabled")
			}

			By("Attempting a delete, which no impersonate-on rule grants")
			// The apiserver runs the impersonate-on:<mode>:<verb> action check FIRST, so
			// an ungranted verb fails before the identity check even runs.
			Consistently(func() bool {
				allowed, detail := canI(targetUser, "delete", "configmaps", ciNamespace)
				if allowed {
					_, _ = fmt.Fprintf(GinkgoWriter, "can-i (forbidden verb) unexpectedly allowed: %s\n", detail)
				}
				return allowed
			}, 20*time.Second, ciPollInterval).Should(BeFalse(),
				"a verb with no matching impersonate-on action rule must be denied")
		})

		It("denies the impersonated request when the feature gate is DISABLED", func() {
			if gateEnabled {
				Skip("this spec asserts the gate-disabled fallback behaviour")
			}

			By("Verifying the constrained impersonation grant is inert")
			// The ClusterRole exists and contains impersonate:user-info, but the
			// apiserver never matches it because the filter is not installed. The
			// request therefore falls through to legacy impersonation, which the
			// impersonator has not been granted, and is denied.
			Consistently(func() bool {
				allowed, detail := canI(targetUser, "list", "configmaps", ciNamespace)
				if allowed {
					_, _ = fmt.Fprintf(GinkgoWriter, "can-i unexpectedly allowed with the gate off: %s\n", detail)
				}
				return allowed
			}, 20*time.Second, ciPollInterval).Should(BeFalse(),
				"with the feature gate disabled the constrained impersonation grant must not authorize anything")
		})
	})

	Context("Legacy impersonation fallback compatibility", func() {
		It("keeps a legacy blanket impersonate grant working on every gate state", func() {
			// No-regression assertion: the legacy verb path must be untouched by this
			// feature on both gate configurations. A cluster that upgrades to 1.36 must
			// not see existing legacy grants change behaviour.
			By("Creating a legacy blanket impersonate ClusterRole")
			Expect(applyManifest(fmt.Sprintf(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
rules:
  - apiGroups: [""]
    resources: ["users"]
    verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: e2e-ci-legacy-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %s
subjects:
  - kind: ServiceAccount
    name: %s
    namespace: %s
`, legacyClusterRole, legacyClusterRole, impersonatorSA, ciNamespace))).To(Succeed())

			By("Granting the forbidden user the target permission so only impersonation is under test")
			// Without this the request would be denied because the IMPERSONATED identity
			// lacks configmap access, not because impersonation was refused, and the spec
			// would prove nothing.
			Expect(applyManifest(fmt.Sprintf(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: e2e-ci-legacy-target-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - kind: User
    name: %s
    apiGroup: rbac.authorization.k8s.io
`, forbiddenUser))).To(Succeed())

			By("Verifying the legacy grant authorizes impersonation of any user")
			// The legacy rule has no resourceNames, so even the user that constrained
			// impersonation forbids becomes reachable. This is exactly the
			// legacy-fallback footgun the operator documents and warns about.
			Eventually(func() bool {
				allowed, detail := canI(forbiddenUser, "get", "configmaps", ciNamespace)
				if !allowed {
					_, _ = fmt.Fprintf(GinkgoWriter, "can-i (legacy) : %s\n", detail)
				}
				return allowed
			}, ciReconcileTimeout, ciPollInterval).Should(BeTrue(),
				"a blanket legacy impersonate grant must keep working unchanged")

			By("Cleaning up the legacy grant so it does not leak into other specs")
			for _, args := range [][]string{
				{"delete", "clusterrolebinding", "e2e-ci-legacy-binding", "--ignore-not-found=true"},
				{"delete", "clusterrolebinding", "e2e-ci-legacy-target-binding", "--ignore-not-found=true"},
				{"delete", "clusterrole", legacyClusterRole, "--ignore-not-found=true"},
			} {
				cmd := utils.CommandContext(context.Background(), "kubectl", args...)
				_, _ = utils.Run(cmd)
			}
		})
	})

	Context("Guardrails are enforced by admission against a live apiserver", func() {
		It("rejects a system:masters group grant", func() {
			err := applyManifest(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: e2e-ci-masters
spec:
  targetRole: ClusterRole
  targetName: e2e-ci-masters-role
  scopeNamespaced: false
  constrainedImpersonation:
    mode: user-info
    identities:
      - resource: groups
        names: ["system:masters"]
`)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("system:masters"))
		})

		It("rejects a wildcard action verb because there is no prefix wildcard", func() {
			err := applyManifest(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: e2e-ci-wildcard
spec:
  targetRole: ClusterRole
  targetName: e2e-ci-wildcard-role
  scopeNamespaced: false
  constrainedImpersonation:
    mode: user-info
    identities:
      - resource: users
        names: ["someone"]
    actions:
      - apiGroups: [""]
        resources: ["pods"]
        verbs: ["*"]
`)
			Expect(err).To(HaveOccurred())
		})

		It("rejects mixing an RBACPolicy serviceAccountRef with uid (the header-mixing trap)", func() {
			err := applyManifest(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: e2e-ci-trap-policy
spec:
  appliesTo:
    namespaces: ["*"]
  impersonation:
    enabled: true
    serviceAccountRef:
      namespace: default
      name: applier
    uid: "some-uid"
`)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("legacy impersonation"))
		})

		It("rejects an associated-node grant that sets names", func() {
			err := applyManifest(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: e2e-ci-assoc-names
spec:
  targetRole: ClusterRole
  targetName: e2e-ci-assoc-names-role
  scopeNamespaced: false
  constrainedImpersonation:
    mode: associated-node
    identities:
      - resource: nodes
        names: ["some-node"]
`)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("RBACPolicy governance of constrained impersonation grants", func() {
		const (
			ciPolicyName = "e2e-ci-policy"
			ciRRDName    = "e2e-ci-rrd"
			ciRRDRole    = "e2e-ci-rrd-role"
		)

		AfterAll(func() {
			for _, args := range [][]string{
				{"delete", "restrictedroledefinition", ciRRDName, "--ignore-not-found=true"},
				{"delete", "rbacpolicy", ciPolicyName, "--ignore-not-found=true"},
			} {
				cmd := utils.CommandContext(context.Background(), "kubectl", args...)
				_, _ = utils.Run(cmd)
			}
		})

		It("reports a grant as non-compliant when the policy does not allow it", func() {
			By("Creating a policy that permits ClusterRoles but not constrained impersonation")
			Expect(applyManifest(fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: %s
spec:
  appliesTo:
    namespaces: ["*"]
  roleLimits:
    allowClusterRoles: true
`, ciPolicyName))).To(Succeed())

			By("Creating a RestrictedRoleDefinition with a constrained impersonation grant")
			Expect(applyManifest(fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedRoleDefinition
metadata:
  name: %s
spec:
  policyRef:
    name: %s
  targetRole: ClusterRole
  targetName: %s
  scopeNamespaced: false
  restrictedVerbs: ["*"]
  constrainedImpersonation:
    mode: user-info
    identities:
      - resource: users
        names: ["%s"]
    actions:
      - apiGroups: [""]
        resources: ["configmaps"]
        verbs: ["list"]
`, ciRRDName, ciPolicyName, ciRRDRole, targetUser))).To(Succeed())

			By("Expecting PolicyCompliant to become False (deny by default)")
			Eventually(func() string {
				return conditionStatus("restrictedroledefinition", ciRRDName, "PolicyCompliant")
			}, ciReconcileTimeout, ciPollInterval).Should(Equal("False"),
				"constrained impersonation must be denied by default under a policy that does not opt in")

			violations, err := utils.GetResourceField("restrictedroledefinition", ciRRDName, "", "{.status.policyViolations}")
			Expect(err).NotTo(HaveOccurred())
			Expect(violations).To(ContainSubstring("constrained impersonation is not allowed by policy"))
		})

		It("becomes compliant once the policy opts in", func() {
			By("Patching the policy to allow constrained impersonation")
			patch := `{"spec":{"roleLimits":{"allowClusterRoles":true,"constrainedImpersonation":{"allowed":true,` +
				`"allowedModes":["user-info"],"forbidLegacyFallback":true}}}}`
			cmd := utils.CommandContext(context.Background(), "kubectl", "patch", "rbacpolicy", ciPolicyName,
				"--type", "merge", "-p", patch)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Expecting the RestrictedRoleDefinition to become compliant and Ready")
			Eventually(func() string {
				return conditionStatus("restrictedroledefinition", ciRRDName, "PolicyCompliant")
			}, ciReconcileTimeout, ciPollInterval).Should(Equal("True"))
			Eventually(func() string {
				return conditionStatus("restrictedroledefinition", ciRRDName, "Ready")
			}, ciReconcileTimeout, ciPollInterval).Should(Equal("True"))

			By("Verifying the generated ClusterRole carries the impersonation rules")
			Eventually(func() (string, error) {
				return utils.GetResourceField("clusterrole", ciRRDRole, "", "{.rules}")
			}, ciReconcileTimeout, ciPollInterval).Should(And(
				ContainSubstring("impersonate:user-info"),
				ContainSubstring("impersonate-on:user-info:list"),
			))
		})

		It("rejects a forbidden mode via allowedModes", func() {
			By("Restricting the policy to the serviceaccount mode only")
			patch := `{"spec":{"roleLimits":{"allowClusterRoles":true,"constrainedImpersonation":{"allowed":true,` +
				`"allowedModes":["serviceaccount"],"forbidLegacyFallback":true}}}}`
			cmd := utils.CommandContext(context.Background(), "kubectl", "patch", "rbacpolicy", ciPolicyName,
				"--type", "merge", "-p", patch)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Expecting the user-info grant to become non-compliant")
			Eventually(func() string {
				return conditionStatus("restrictedroledefinition", ciRRDName, "PolicyCompliant")
			}, ciReconcileTimeout, ciPollInterval).Should(Equal("False"))

			violations, err := utils.GetResourceField("restrictedroledefinition", ciRRDName, "", "{.status.policyViolations}")
			Expect(err).NotTo(HaveOccurred())
			Expect(violations).To(ContainSubstring("not allowed by policy"))
		})
	})
})
