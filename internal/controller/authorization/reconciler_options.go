// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"go.opentelemetry.io/otel/trace"

	"github.com/telekom/auth-operator/pkg/capabilities"
)

// tracerSetter is implemented by reconcilers that support OpenTelemetry tracing.
type tracerSetter interface {
	setTracer(trace.Tracer)
}

// capabilityDetectorSetter is implemented by reconcilers that can surface
// optional API server capability state (currently constrained impersonation).
type capabilityDetectorSetter interface {
	setCapabilityDetector(capabilityDetector)
}

// ReconcilerOption is a type-safe functional option for configuring reconcilers.
type ReconcilerOption func(tracerSetter)

// WithTracer returns a ReconcilerOption that sets the OpenTelemetry tracer on
// any reconciler that implements tracerSetter (RoleDefinition, BindDefinition).
func WithTracer(t trace.Tracer) ReconcilerOption {
	return func(r tracerSetter) {
		r.setTracer(t)
	}
}

// WithCapabilityDetector returns a ReconcilerOption that wires an API server
// capability detector into reconcilers that support it. Reconcilers that do not
// implement capabilityDetectorSetter ignore the option, so a single option list
// can be shared across all reconcilers.
//
// Without a detector, constrained impersonation grants still reconcile normally;
// their ConstrainedImpersonationEffective condition is reported as Unknown.
func WithCapabilityDetector(d *capabilities.Detector) ReconcilerOption {
	return func(r tracerSetter) {
		setter, ok := r.(capabilityDetectorSetter)
		if !ok || d == nil {
			return
		}
		setter.setCapabilityDetector(d)
	}
}
