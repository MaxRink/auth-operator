// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package capabilities

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/log"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

// State is a tri-state capability answer. Unknown is a distinct, first-class
// value: the operator must never silently treat "could not determine" as either
// supported or unsupported.
type State string

// Capability states.
const (
	// StateEnabled means the capability was positively confirmed as available.
	StateEnabled State = "Enabled"
	// StateDisabled means the capability was positively confirmed as unavailable,
	// either because the feature gate is off or because the API server predates it.
	StateDisabled State = "Disabled"
	// StateUnknown means detection did not produce a conclusive answer, e.g. the
	// operator lacks get access to the /metrics endpoint and the server version
	// could not be parsed. Callers must treat this as "proceed but warn".
	StateUnknown State = "Unknown"
)

// featureGateMetricName is the apiserver metric that reports the effective state
// of every registered feature gate. It is the most direct runtime signal
// available: it reflects the gate's actual computed value including
// --feature-gates overrides, rather than being inferred from the release.
const featureGateMetricName = "kubernetes_feature_enabled"

// firstSupportedMinor is the first Kubernetes minor version in which
// ConstrainedImpersonation exists at all (1.35, alpha). Below this the verbs are
// inert no matter what.
const firstSupportedMinor = 35

// defaultOnMinor is the first Kubernetes minor version in which
// ConstrainedImpersonation is beta and therefore on by default (1.36).
const defaultOnMinor = 36

// Machine-readable capability probe reasons, suitable for condition reason fields.
const (
	// ReasonFeatureGateEnabled means the API server reported the gate as enabled.
	ReasonFeatureGateEnabled = "FeatureGateEnabled"
	// ReasonFeatureGateDisabled means the API server reported the gate as disabled.
	ReasonFeatureGateDisabled = "FeatureGateDisabled"
	// ReasonFeatureGateAlpha means the gate exists but is alpha and off by default,
	// and its effective state could not be confirmed.
	ReasonFeatureGateAlpha = "FeatureGateAlpha"
	// ReasonVersionSupportsFeature means the API server release has the gate at beta
	// (on by default), inferred from the version because the metric was unreadable.
	ReasonVersionSupportsFeature = "VersionSupportsFeature"
	// ReasonVersionTooOld means the API server release predates the feature entirely.
	ReasonVersionTooOld = "VersionTooOld"
	// ReasonVersionUnknown means neither the metric nor the version could be read.
	ReasonVersionUnknown = "VersionUnknown"
)

// Result is the outcome of a capability probe.
type Result struct {
	// State is the tri-state answer.
	State State
	// Reason is a short, stable machine-readable reason suitable for a condition
	// reason field.
	Reason string
	// Detail is a human-readable explanation naming the required version and gate,
	// suitable for a condition message, event or admission warning.
	Detail string
	// ServerVersion is the detected API server version string, when known.
	ServerVersion string
}

// Supported reports whether the capability was positively confirmed. Unknown
// counts as not-confirmed, so callers that gate behaviour on this stay safe.
func (r Result) Supported() bool {
	return r.State == StateEnabled
}

// MetricsFetcher fetches the raw Prometheus text exposition from the API server's
// /metrics endpoint. It is an interface so tests can supply fixtures without a
// live cluster.
type MetricsFetcher interface {
	FetchAPIServerMetrics(ctx context.Context) ([]byte, error)
}

// VersionGetter reports the API server version. discovery.DiscoveryInterface
// satisfies this.
type VersionGetter interface {
	ServerVersion() (*version.Info, error)
}

var _ VersionGetter = discovery.DiscoveryInterface(nil)

// Detector probes the API server for constrained impersonation support and
// caches the answer.
//
// Detection strategy, in order of preference:
//
//  1. Parse the apiserver's own `kubernetes_feature_enabled` metric. This is
//     authoritative: it reflects --feature-gates overrides rather than guessing
//     from the release, so an explicitly disabled gate on 1.36 is detected
//     correctly.
//  2. Fall back to a server version comparison, which is isolated in
//     stateFromVersion and treats unparseable versions as Unknown.
//
// There is deliberately no SubjectAccessReview-based probe: RBAC verbs are
// free-form strings, so a SelfSubjectAccessReview for `impersonate:user-info`
// succeeds on any version and would be actively misleading.
type Detector struct {
	// Metrics fetches the apiserver /metrics body. Optional; when nil, detection
	// falls back to the version comparison.
	Metrics MetricsFetcher
	// Version reports the API server version. Optional; when nil and Metrics is
	// inconclusive, the result is Unknown.
	Version VersionGetter
	// CacheTTL bounds how long a probe result is reused. Zero means the default.
	CacheTTL time.Duration

	mu          sync.Mutex
	cached      *Result
	cachedAt    time.Time
	nowOverride func() time.Time
}

// defaultCacheTTL is how long a capability probe result is reused. Feature gates
// only change when the control plane restarts, so a coarse TTL is fine, but it is
// bounded so a rolling control-plane upgrade is picked up without an operator
// restart.
const defaultCacheTTL = 10 * time.Minute

func (d *Detector) now() time.Time {
	if d.nowOverride != nil {
		return d.nowOverride()
	}
	return time.Now()
}

func (d *Detector) cacheTTL() time.Duration {
	if d.CacheTTL <= 0 {
		return defaultCacheTTL
	}
	return d.CacheTTL
}

// ConstrainedImpersonation returns the cached or freshly probed capability state.
// It never returns an error: a failed probe degrades to StateUnknown so the
// operator keeps working on clusters where it cannot read /metrics.
func (d *Detector) ConstrainedImpersonation(ctx context.Context) Result {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cached != nil && d.now().Sub(d.cachedAt) < d.cacheTTL() {
		return *d.cached
	}

	result := d.probe(ctx)
	d.cached = &result
	d.cachedAt = d.now()
	return result
}

// Invalidate clears the cached probe result, forcing the next call to re-probe.
func (d *Detector) Invalidate() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cached = nil
}

func (d *Detector) probe(ctx context.Context) Result {
	logger := log.FromContext(ctx).WithName("capabilities")

	serverVersion := ""
	if d.Version != nil {
		if info, err := d.Version.ServerVersion(); err != nil {
			logger.V(1).Info("failed to read API server version for capability detection", "error", err)
		} else if info != nil {
			serverVersion = info.GitVersion
		}
	}

	if d.Metrics != nil {
		body, err := d.Metrics.FetchAPIServerMetrics(ctx)
		if err != nil {
			logger.V(1).Info("failed to read API server /metrics for capability detection; falling back to version comparison",
				"error", err)
		} else if enabled, found := ParseFeatureGateMetric(body, authorizationv1alpha1.ConstrainedImpersonationFeatureGate); found {
			if enabled {
				return Result{
					State:         StateEnabled,
					Reason:        ReasonFeatureGateEnabled,
					Detail:        fmt.Sprintf("API server reports feature gate %s=true", authorizationv1alpha1.ConstrainedImpersonationFeatureGate),
					ServerVersion: serverVersion,
				}
			}
			return Result{
				State:  StateDisabled,
				Reason: ReasonFeatureGateDisabled,
				Detail: fmt.Sprintf(
					"API server reports feature gate %s=false. Constrained impersonation grants are inert: "+
						"the generated RBAC rules are accepted but never matched. Enable the gate with "+
						"--feature-gates=%s=true on kube-apiserver (Kubernetes 1.35+; on by default from 1.36).",
					authorizationv1alpha1.ConstrainedImpersonationFeatureGate,
					authorizationv1alpha1.ConstrainedImpersonationFeatureGate),
				ServerVersion: serverVersion,
			}
		}
	}

	return stateFromVersion(serverVersion)
}

// stateFromVersion infers the capability state from a Kubernetes version string.
// This is the single isolated place where a version comparison happens.
//
// Unparseable or empty versions yield StateUnknown rather than a guess. A 1.35
// server yields StateUnknown too, because the gate is alpha and off by default
// there but may have been explicitly enabled — only the /metrics probe can tell.
func stateFromVersion(gitVersion string) Result {
	major, minor, ok := parseMajorMinor(gitVersion)
	if !ok {
		return Result{
			State:  StateUnknown,
			Reason: ReasonVersionUnknown,
			Detail: fmt.Sprintf(
				"could not determine API server version (%q) or read the %s metric, so support for feature gate %s is unknown. "+
					"Constrained impersonation requires Kubernetes 1.35+ with the gate enabled (1.36+ has it on by default).",
				gitVersion, featureGateMetricName, authorizationv1alpha1.ConstrainedImpersonationFeatureGate),
			ServerVersion: gitVersion,
		}
	}

	switch {
	case major > 1 || minor >= defaultOnMinor:
		return Result{
			State:  StateEnabled,
			Reason: ReasonVersionSupportsFeature,
			Detail: fmt.Sprintf(
				"API server %s has feature gate %s at beta (on by default). Could not read the %s metric to confirm it was not explicitly disabled.",
				gitVersion, authorizationv1alpha1.ConstrainedImpersonationFeatureGate, featureGateMetricName),
			ServerVersion: gitVersion,
		}
	case minor >= firstSupportedMinor:
		return Result{
			State:  StateUnknown,
			Reason: ReasonFeatureGateAlpha,
			Detail: fmt.Sprintf(
				"API server %s has feature gate %s at alpha (off by default) and the %s metric could not be read, "+
					"so its effective state is unknown. Verify --feature-gates=%s=true on kube-apiserver.",
				gitVersion, authorizationv1alpha1.ConstrainedImpersonationFeatureGate, featureGateMetricName,
				authorizationv1alpha1.ConstrainedImpersonationFeatureGate),
			ServerVersion: gitVersion,
		}
	default:
		return Result{
			State:  StateDisabled,
			Reason: ReasonVersionTooOld,
			Detail: fmt.Sprintf(
				"API server %s predates constrained impersonation (KEP-5284, added in Kubernetes 1.35). "+
					"Generated impersonate:<mode> and impersonate-on:<mode>:<verb> grants are accepted by RBAC but are inert and grant nothing.",
				gitVersion),
			ServerVersion: gitVersion,
		}
	}
}

// parseMajorMinor extracts the major and minor version from a Kubernetes
// gitVersion string such as "v1.36.1" or "v1.36.1-eks-1234". It is deliberately
// tolerant: anything it cannot confidently parse returns ok=false so callers
// degrade to Unknown instead of comparing against a wrong number.
func parseMajorMinor(gitVersion string) (major, minor int, ok bool) {
	v := strings.TrimSpace(gitVersion)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return 0, 0, false
	}
	// Drop any pre-release or build metadata suffix.
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	// Trim a trailing "+" style minor (e.g. "1.35+") which some distributions emit.
	minor, err = strconv.Atoi(strings.TrimSuffix(parts[1], "+"))
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// ParseFeatureGateMetric extracts the effective state of a named feature gate
// from a Prometheus text exposition body, matching lines of the form:
//
//	kubernetes_feature_enabled{name="ConstrainedImpersonation",stage="BETA"} 1
//
// It returns found=false when the gate is not present in the payload, which is
// the expected outcome on API servers that do not know the gate at all.
func ParseFeatureGateMetric(body []byte, gateName string) (enabled, found bool) {
	needle := featureGateMetricName + `{`
	nameLabel := `name="` + gateName + `"`

	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	// Feature-gate metric lines are short, but the apiserver /metrics body contains
	// very long lines elsewhere; raise the limit so scanning does not abort early.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, needle) {
			continue
		}
		labelsEnd := strings.LastIndex(line, "}")
		if labelsEnd < 0 {
			continue
		}
		if !strings.Contains(line[:labelsEnd], nameLabel) {
			continue
		}
		value := strings.TrimSpace(line[labelsEnd+1:])
		// Prometheus gauges are floats; "1", "1.0" and "1e+00" all mean enabled.
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			continue
		}
		return parsed != 0, true
	}
	return false, false
}
