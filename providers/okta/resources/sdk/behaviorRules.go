// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"net/http"
)

// ListBehaviorRules fetches behavior detection rules from `/api/v1/behaviors`.
//
// The SDK's BehaviorAPI.ListBehaviorDetectionRules cannot be used here: the
// generated BehaviorRule type declares created/lastUpdated as time.Time with
// strict RFC3339 unmarshaling, but this legacy endpoint returns timestamps in
// Okta's space-separated form (for example "2026-07-20 17:34:59.0"), so the
// SDK's own Execute() fails to unmarshal the response before any mapping runs.
// Decoding into untyped maps sidesteps the SDK's time parsing; the caller
// parses the timestamps leniently.
//
// The returned http.Response is the first page's response so callers can treat
// a 404 as an empty result.
func (m *ApiExtension) ListBehaviorRules(ctx context.Context) ([]map[string]any, *http.Response, error) {
	rules := []map[string]any{}
	nextURL := m.url("/api/v1/behaviors")
	var firstResp *http.Response

	for nextURL != "" {
		var page []map[string]any
		resp, err := m.get(ctx, nextURL, &page)
		if firstResp == nil {
			firstResp = resp
		}
		if err != nil {
			return nil, resp, err
		}
		rules = append(rules, page...)
		if resp == nil {
			break
		}
		nextURL = nextPageURL(nextURL, resp.Header.Values("Link"))
	}

	return rules, firstResp, nil
}
