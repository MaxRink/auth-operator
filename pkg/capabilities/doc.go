// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package capabilities detects optional Kubernetes API server capabilities at
// runtime so the operator can degrade gracefully instead of generating RBAC that
// silently grants nothing.
//
// The only capability modelled today is Kubernetes constrained impersonation
// (KEP-5284), which is gated behind the ConstrainedImpersonation kube-apiserver
// feature gate.
package capabilities
