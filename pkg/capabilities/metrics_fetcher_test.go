// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package capabilities

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
)

func TestNewRESTMetricsFetcherRejectsNilConfig(t *testing.T) {
	t.Parallel()

	if _, err := NewRESTMetricsFetcher(nil); err == nil {
		t.Fatal("expected an error for a nil rest config")
	}
}

func TestRESTMetricsFetcherFetchesMetrics(t *testing.T) {
	t.Parallel()

	body := featureMetricsBody("ConstrainedImpersonation", "1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	fetcher, err := NewRESTMetricsFetcher(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatalf("NewRESTMetricsFetcher() unexpected error: %v", err)
	}

	got, err := fetcher.FetchAPIServerMetrics(context.Background())
	if err != nil {
		t.Fatalf("FetchAPIServerMetrics() unexpected error: %v", err)
	}
	if string(got) != body {
		t.Errorf("body mismatch:\ngot:  %q\nwant: %q", got, body)
	}

	// And the detector should read it end to end.
	d := &Detector{Metrics: fetcher}
	if result := d.ConstrainedImpersonation(context.Background()); result.State != StateEnabled {
		t.Errorf("state = %q, want Enabled (detail: %s)", result.State, result.Detail)
	}
}

func TestRESTMetricsFetcherWrapsErrors(t *testing.T) {
	t.Parallel()

	// A cluster where the operator lacks get access to /metrics must produce a
	// wrapped error, which the detector then degrades to StateUnknown rather than
	// failing reconciliation.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	fetcher, err := NewRESTMetricsFetcher(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatalf("NewRESTMetricsFetcher() unexpected error: %v", err)
	}

	if _, err := fetcher.FetchAPIServerMetrics(context.Background()); err == nil {
		t.Fatal("expected an error for a forbidden /metrics response")
	} else if !strings.Contains(err.Error(), "fetch API server /metrics") {
		t.Errorf("error is not wrapped with context: %v", err)
	}

	// Detection must degrade, not fail.
	d := &Detector{Metrics: fetcher, Version: &stubVersion{gitVersion: "v1.34.0"}}
	if result := d.ConstrainedImpersonation(context.Background()); result.State != StateDisabled {
		t.Errorf("state = %q, want Disabled via the version fallback", result.State)
	}
}
