// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package envtestutil provides shared helpers for configuring envtest control
// planes across the operator's test suites.
package envtestutil

import (
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// FeatureGatesEnvVar lets CI and developers override the feature gates passed to
// the envtest kube-apiserver, e.g.
//
//	AUTH_OPERATOR_ENVTEST_FEATURE_GATES=ConstrainedImpersonation=false make test
//
// The value uses the standard kube-apiserver --feature-gates syntax,
// "Gate1=true,Gate2=false". An empty or unset value leaves the API server at its
// defaults, which is what makes the whole matrix (gate default-on, explicitly off)
// runnable from the same suite.
const FeatureGatesEnvVar = "AUTH_OPERATOR_ENVTEST_FEATURE_GATES"

// ApplyFeatureGates appends --feature-gates to the envtest kube-apiserver
// arguments. It must be called before env.Start().
//
// controller-runtime's ControlPlane.GetAPIServer().Configure() returns an
// Arguments set whose Append semantics accumulate values for repeated flags, so
// callers can layer several gate specifications.
//
// A nil env or an empty gates string is a no-op, so callers can pass the value of
// FeatureGatesFromEnv unconditionally.
func ApplyFeatureGates(env *envtest.Environment, gates string) {
	if env == nil {
		return
	}
	gates = strings.TrimSpace(gates)
	if gates == "" {
		return
	}
	env.ControlPlane.GetAPIServer().Configure().Append("feature-gates", gates)
}

// FeatureGatesFromEnv reads the feature-gate override from FeatureGatesEnvVar.
func FeatureGatesFromEnv() string {
	return strings.TrimSpace(os.Getenv(FeatureGatesEnvVar))
}

// ApplyFeatureGatesFromEnv applies the FeatureGatesEnvVar override, if any, and
// reports the value that was applied so suites can log it.
func ApplyFeatureGatesFromEnv(env *envtest.Environment) string {
	gates := FeatureGatesFromEnv()
	ApplyFeatureGates(env, gates)
	return gates
}

// FeatureGateSpec renders a single "Gate=bool" specification.
func FeatureGateSpec(gate string, enabled bool) string {
	return fmt.Sprintf("%s=%t", gate, enabled)
}
