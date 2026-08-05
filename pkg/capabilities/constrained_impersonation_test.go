// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package capabilities

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/version"
)

// stubMetrics returns a fixed /metrics body or error.
type stubMetrics struct {
	body  string
	err   error
	calls atomic.Int32
}

func (s *stubMetrics) FetchAPIServerMetrics(context.Context) ([]byte, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return []byte(s.body), nil
}

// stubVersion returns a fixed server version or error.
type stubVersion struct {
	gitVersion string
	err        error
}

func (s *stubVersion) ServerVersion() (*version.Info, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &version.Info{GitVersion: s.gitVersion}, nil
}

func featureMetricsBody(gate string, value string) string {
	return strings.Join([]string{
		"# HELP kubernetes_feature_enabled [BETA] This metric records the data about the stage and enablement of a k8s feature.",
		"# TYPE kubernetes_feature_enabled gauge",
		`kubernetes_feature_enabled{name="AnyVolumeDataSource",stage="BETA"} 1`,
		fmt.Sprintf(`kubernetes_feature_enabled{name=%q,stage="BETA"} %s`, gate, value),
		`kubernetes_feature_enabled{name="ZZZUnrelated",stage=""} 0`,
		"",
	}, "\n")
}

func TestParseFeatureGateMetric(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		gate        string
		wantEnabled bool
		wantFound   bool
	}{
		{
			name:        "gate enabled",
			body:        featureMetricsBody("ConstrainedImpersonation", "1"),
			gate:        "ConstrainedImpersonation",
			wantEnabled: true,
			wantFound:   true,
		},
		{
			name:      "gate disabled",
			body:      featureMetricsBody("ConstrainedImpersonation", "0"),
			gate:      "ConstrainedImpersonation",
			wantFound: true,
		},
		{
			name:        "float formatting is tolerated",
			body:        featureMetricsBody("ConstrainedImpersonation", "1.0"),
			gate:        "ConstrainedImpersonation",
			wantEnabled: true,
			wantFound:   true,
		},
		{
			name:        "scientific notation is tolerated",
			body:        featureMetricsBody("ConstrainedImpersonation", "1e+00"),
			gate:        "ConstrainedImpersonation",
			wantEnabled: true,
			wantFound:   true,
		},
		{
			name: "gate absent (pre-1.35 apiserver)",
			body: featureMetricsBody("SomeOtherGate", "1"),
			gate: "ConstrainedImpersonation",
		},
		{
			name: "empty body",
			body: "",
			gate: "ConstrainedImpersonation",
		},
		{
			name: "comment lines are ignored",
			body: `# kubernetes_feature_enabled{name="ConstrainedImpersonation"} 1`,
			gate: "ConstrainedImpersonation",
		},
		{
			name: "non-numeric value is ignored",
			body: `kubernetes_feature_enabled{name="ConstrainedImpersonation",stage="BETA"} NaNish`,
			gate: "ConstrainedImpersonation",
		},
		{
			name: "substring gate names do not match",
			body: featureMetricsBody("ConstrainedImpersonationExtra", "1"),
			gate: "ConstrainedImpersonation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			enabled, found := ParseFeatureGateMetric([]byte(tt.body), tt.gate)
			if found != tt.wantFound {
				t.Fatalf("found = %t, want %t", found, tt.wantFound)
			}
			if enabled != tt.wantEnabled {
				t.Errorf("enabled = %t, want %t", enabled, tt.wantEnabled)
			}
		})
	}
}

func TestParseMajorMinor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in     string
		major  int
		minor  int
		wantOK bool
	}{
		{in: "v1.36.1", major: 1, minor: 36, wantOK: true},
		{in: "1.36.1", major: 1, minor: 36, wantOK: true},
		{in: "v1.35.0-alpha.1", major: 1, minor: 35, wantOK: true},
		{in: "v1.34.9-eks-1a2b3c", major: 1, minor: 34, wantOK: true},
		{in: "v1.36.0+k3s1", major: 1, minor: 36, wantOK: true},
		{in: "v1.35+", major: 1, minor: 35, wantOK: true},
		{in: "  v1.36.2  ", major: 1, minor: 36, wantOK: true},
		{in: "v2.0.0", major: 2, minor: 0, wantOK: true},
		// Unparseable inputs must fail rather than default to a comparison.
		{in: ""},
		{in: "v1"},
		{in: "unknown"},
		{in: "vX.Y.Z"},
		{in: "v1.x.3"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			major, minor, ok := parseMajorMinor(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("parseMajorMinor(%q) ok = %t, want %t", tt.in, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if major != tt.major || minor != tt.minor {
				t.Errorf("parseMajorMinor(%q) = %d.%d, want %d.%d", tt.in, major, minor, tt.major, tt.minor)
			}
		})
	}
}

func TestStateFromVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		gitVersion string
		wantState  State
		wantReason string
	}{
		{
			name:       "1.36 is beta and on by default",
			gitVersion: "v1.36.1",
			wantState:  StateEnabled,
			wantReason: "VersionSupportsFeature",
		},
		{
			name:       "1.37 is still supported",
			gitVersion: "v1.37.0",
			wantState:  StateEnabled,
			wantReason: "VersionSupportsFeature",
		},
		{
			name:       "1.35 is alpha so the effective state is unknown",
			gitVersion: "v1.35.4",
			wantState:  StateUnknown,
			wantReason: "FeatureGateAlpha",
		},
		{
			name:       "1.34 predates the feature",
			gitVersion: "v1.34.0",
			wantState:  StateDisabled,
			wantReason: "VersionTooOld",
		},
		{
			name:       "1.29 predates the feature",
			gitVersion: "v1.29.10",
			wantState:  StateDisabled,
			wantReason: "VersionTooOld",
		},
		{
			name:       "unparseable version degrades to unknown",
			gitVersion: "not-a-version",
			wantState:  StateUnknown,
			wantReason: "VersionUnknown",
		},
		{
			name:       "empty version degrades to unknown",
			gitVersion: "",
			wantState:  StateUnknown,
			wantReason: "VersionUnknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := stateFromVersion(tt.gitVersion)
			if got.State != tt.wantState {
				t.Errorf("state = %q, want %q (detail: %s)", got.State, tt.wantState, got.Detail)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", got.Reason, tt.wantReason)
			}
			if got.Detail == "" {
				t.Error("detail must never be empty: it is surfaced to users in conditions and events")
			}
		})
	}
}

func TestDetectorConstrainedImpersonation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		metrics       MetricsFetcher
		versionGetter VersionGetter
		wantState     State
		wantReason    string
	}{
		{
			name:          "metrics say enabled",
			metrics:       &stubMetrics{body: featureMetricsBody("ConstrainedImpersonation", "1")},
			versionGetter: &stubVersion{gitVersion: "v1.36.1"},
			wantState:     StateEnabled,
			wantReason:    "FeatureGateEnabled",
		},
		{
			name: "metrics override the version: explicitly disabled on 1.36",
			// This is the case a pure version comparison would get wrong.
			metrics:       &stubMetrics{body: featureMetricsBody("ConstrainedImpersonation", "0")},
			versionGetter: &stubVersion{gitVersion: "v1.36.1"},
			wantState:     StateDisabled,
			wantReason:    "FeatureGateDisabled",
		},
		{
			name:          "metrics override the version: explicitly enabled on 1.35 alpha",
			metrics:       &stubMetrics{body: featureMetricsBody("ConstrainedImpersonation", "1")},
			versionGetter: &stubVersion{gitVersion: "v1.35.0"},
			wantState:     StateEnabled,
			wantReason:    "FeatureGateEnabled",
		},
		{
			name:          "gate missing from metrics falls back to the version",
			metrics:       &stubMetrics{body: featureMetricsBody("SomeOtherGate", "1")},
			versionGetter: &stubVersion{gitVersion: "v1.34.0"},
			wantState:     StateDisabled,
			wantReason:    "VersionTooOld",
		},
		{
			name:          "metrics fetch error falls back to the version",
			metrics:       &stubMetrics{err: fmt.Errorf("forbidden")},
			versionGetter: &stubVersion{gitVersion: "v1.36.1"},
			wantState:     StateEnabled,
			wantReason:    "VersionSupportsFeature",
		},
		{
			name:       "no metrics and no version is unknown, never a guess",
			wantState:  StateUnknown,
			wantReason: "VersionUnknown",
		},
		{
			name:          "version error degrades to unknown",
			versionGetter: &stubVersion{err: fmt.Errorf("unauthorized")},
			wantState:     StateUnknown,
			wantReason:    "VersionUnknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := &Detector{Metrics: tt.metrics, Version: tt.versionGetter}
			got := d.ConstrainedImpersonation(context.Background())
			if got.State != tt.wantState {
				t.Errorf("state = %q, want %q (detail: %s)", got.State, tt.wantState, got.Detail)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", got.Reason, tt.wantReason)
			}
			if got.Supported() != (tt.wantState == StateEnabled) {
				t.Errorf("Supported() = %t for state %q", got.Supported(), got.State)
			}
		})
	}
}

func TestDetectorCaching(t *testing.T) {
	t.Parallel()

	metrics := &stubMetrics{body: featureMetricsBody("ConstrainedImpersonation", "1")}
	now := time.Now()
	d := &Detector{
		Metrics:     metrics,
		CacheTTL:    time.Minute,
		nowOverride: func() time.Time { return now },
	}

	for range 5 {
		if !d.ConstrainedImpersonation(context.Background()).Supported() {
			t.Fatal("expected supported")
		}
	}
	if calls := metrics.calls.Load(); calls != 1 {
		t.Errorf("expected 1 probe within the TTL, got %d", calls)
	}

	// Advancing past the TTL must re-probe so a control-plane upgrade is picked up
	// without restarting the operator.
	now = now.Add(2 * time.Minute)
	d.ConstrainedImpersonation(context.Background())
	if calls := metrics.calls.Load(); calls != 2 {
		t.Errorf("expected a re-probe after the TTL expired, got %d calls", calls)
	}

	// Invalidate forces an immediate re-probe.
	d.Invalidate()
	d.ConstrainedImpersonation(context.Background())
	if calls := metrics.calls.Load(); calls != 3 {
		t.Errorf("expected a re-probe after Invalidate, got %d calls", calls)
	}
}

func TestDetectorDefaultCacheTTL(t *testing.T) {
	t.Parallel()

	d := &Detector{}
	if got := d.cacheTTL(); got != defaultCacheTTL {
		t.Errorf("cacheTTL() = %v, want %v", got, defaultCacheTTL)
	}
	d.CacheTTL = -time.Second
	if got := d.cacheTTL(); got != defaultCacheTTL {
		t.Errorf("negative CacheTTL should fall back to the default, got %v", got)
	}
}
