// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"net/http"

	"github.com/okta/okta-sdk-golang/v6/okta"
)

// ListRiskProviders fetches the org's risk providers from
// `/api/v1/risk/providers`.
//
// The SDK models a risk provider but no longer generates a client for the
// collection endpoint, so the request is issued here. The resource this backs
// reports which third-party risk signals Okta accepts at authentication time
// and what it does with them, which is not something to drop because a
// generator stopped emitting the call.
//
// The returned http.Response is the first page's response, so callers can tell
// an org without the feature (404, or 410 once retired) from a real failure.
func (m *ApiExtension) ListRiskProviders(ctx context.Context) ([]okta.RiskProvider, *http.Response, error) {
	providers := []okta.RiskProvider{}
	nextURL := m.url("/api/v1/risk/providers")
	var firstResp *http.Response

	for nextURL != "" {
		var page []okta.RiskProvider
		resp, err := m.get(ctx, nextURL, &page)
		if firstResp == nil {
			firstResp = resp
		}
		if err != nil {
			return nil, firstResp, err
		}
		providers = append(providers, page...)
		if resp == nil {
			break
		}
		nextURL = nextPageURL(nextURL, resp.Header.Values("Link"))
	}

	return providers, firstResp, nil
}
