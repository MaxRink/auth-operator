// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package capabilities

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
)

// RESTMetricsFetcher reads the API server's /metrics endpoint over an existing
// REST config.
//
// This requires a nonResourceURLs: ["/metrics"], verbs: ["get"] grant on the
// operator's ClusterRole. That grant is added by this feature and is gated behind
// the Helm value controller.constrainedImpersonation.capabilityDetection (default
// true); setting it to false omits the rule entirely.
//
// When the grant is absent the fetch fails with a 403 and detection does not fail
// the reconcile: the Detector falls back to comparing the API server version, and
// degrades to StateUnknown only when even that is unavailable.
type RESTMetricsFetcher struct {
	client rest.Interface
}

var _ MetricsFetcher = (*RESTMetricsFetcher)(nil)

// NewRESTMetricsFetcher builds a fetcher from a controller-runtime rest.Config.
func NewRESTMetricsFetcher(cfg *rest.Config) (*RESTMetricsFetcher, error) {
	if cfg == nil {
		return nil, fmt.Errorf("rest config must not be nil")
	}
	// Copy so the caller's config (content type, rate limiter) is untouched: the
	// /metrics endpoint returns Prometheus text exposition, not JSON.
	//
	// UnversionedRESTClientFor still requires a NegotiatedSerializer even though the
	// response body is read raw via DoRaw, so a scheme-backed codec factory is
	// supplied to satisfy the constructor.
	metricsConfig := rest.CopyConfig(cfg)
	metricsConfig.GroupVersion = &schema.GroupVersion{}
	metricsConfig.NegotiatedSerializer = serializer.NewCodecFactory(runtime.NewScheme()).WithoutConversion()
	metricsConfig.APIPath = "/"
	client, err := rest.UnversionedRESTClientFor(metricsConfig)
	if err != nil {
		return nil, fmt.Errorf("build /metrics REST client: %w", err)
	}
	return &RESTMetricsFetcher{client: client}, nil
}

// FetchAPIServerMetrics returns the raw Prometheus text exposition body.
func (f *RESTMetricsFetcher) FetchAPIServerMetrics(ctx context.Context) ([]byte, error) {
	body, err := f.client.Get().AbsPath("/metrics").DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch API server /metrics: %w", err)
	}
	return body, nil
}
