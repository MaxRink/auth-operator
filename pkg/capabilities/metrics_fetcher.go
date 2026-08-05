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
// REST config. The operator already has get access to /metrics via its
// non-resource URL grant, so no new RBAC is needed for the common case; when the
// grant is missing, the fetch fails and detection degrades to StateUnknown.
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
