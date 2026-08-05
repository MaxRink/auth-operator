// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package envtestutil

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// configuredFeatureGates reads back the --feature-gates values staged on the
// envtest control plane.
func configuredFeatureGates(env *envtest.Environment) []string {
	return env.ControlPlane.GetAPIServer().Configure().Get("feature-gates").Get(nil)
}

func TestFeatureGateSpec(t *testing.T) {
	t.Parallel()

	if got := FeatureGateSpec("ConstrainedImpersonation", true); got != "ConstrainedImpersonation=true" {
		t.Errorf("FeatureGateSpec(enabled) = %q", got)
	}
	if got := FeatureGateSpec("ConstrainedImpersonation", false); got != "ConstrainedImpersonation=false" {
		t.Errorf("FeatureGateSpec(disabled) = %q", got)
	}
}

func TestApplyFeatureGates(t *testing.T) {
	t.Parallel()

	t.Run("nil environment is a no-op", func(t *testing.T) {
		t.Parallel()
		ApplyFeatureGates(nil, "ConstrainedImpersonation=false")
	})

	t.Run("empty gates leave the arguments untouched", func(t *testing.T) {
		t.Parallel()
		env := &envtest.Environment{}
		ApplyFeatureGates(env, "   ")
		if got := configuredFeatureGates(env); len(got) != 0 {
			t.Errorf("expected no feature-gates argument, got %v", got)
		}
	})

	t.Run("gates are appended to the apiserver arguments", func(t *testing.T) {
		t.Parallel()
		env := &envtest.Environment{}
		ApplyFeatureGates(env, "ConstrainedImpersonation=false")
		got := configuredFeatureGates(env)
		if len(got) != 1 || got[0] != "ConstrainedImpersonation=false" {
			t.Errorf("feature-gates = %v, want [ConstrainedImpersonation=false]", got)
		}
	})

	t.Run("gates accumulate across calls", func(t *testing.T) {
		t.Parallel()
		env := &envtest.Environment{}
		ApplyFeatureGates(env, "ConstrainedImpersonation=false")
		ApplyFeatureGates(env, "AnotherGate=true")
		if got := configuredFeatureGates(env); len(got) != 2 {
			t.Errorf("feature-gates = %v, want 2 entries", got)
		}
	})
}

func TestApplyFeatureGatesFromEnv(t *testing.T) {
	// Not parallel: this mutates process environment.
	t.Setenv(FeatureGatesEnvVar, " ConstrainedImpersonation=false ")

	if got := FeatureGatesFromEnv(); got != "ConstrainedImpersonation=false" {
		t.Errorf("FeatureGatesFromEnv() = %q, want the trimmed value", got)
	}

	env := &envtest.Environment{}
	if got := ApplyFeatureGatesFromEnv(env); got != "ConstrainedImpersonation=false" {
		t.Errorf("ApplyFeatureGatesFromEnv() = %q", got)
	}
	if got := configuredFeatureGates(env); len(got) != 1 {
		t.Errorf("expected the feature-gates argument to be applied, got %v", got)
	}
}

func TestApplyFeatureGatesFromEnvUnset(t *testing.T) {
	t.Setenv(FeatureGatesEnvVar, "")

	env := &envtest.Environment{}
	if got := ApplyFeatureGatesFromEnv(env); got != "" {
		t.Errorf("ApplyFeatureGatesFromEnv() = %q, want empty", got)
	}
}
