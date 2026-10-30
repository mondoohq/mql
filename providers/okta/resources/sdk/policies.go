// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// PolicyWrapper models the fields we expose from Okta's /api/v1/policies
// endpoint. We decode the policy ourselves (rather than via the generated SDK)
// because the policy listing is a discriminated union whose `settings` block
// varies per policy type; capturing `conditions` and `settings` as raw JSON
// preserves the full shape for the dict fields.
type PolicyWrapper struct {
	Id          string          `json:"id,omitempty"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Priority    int64           `json:"priority,omitempty"`
	Status      string          `json:"status,omitempty"`
	System      *bool           `json:"system,omitempty"`
	Type        string          `json:"type,omitempty"`
	Created     *time.Time      `json:"created,omitempty"`
	LastUpdated *time.Time      `json:"lastUpdated,omitempty"`
	Conditions  json.RawMessage `json:"conditions,omitempty"`
	Settings    json.RawMessage `json:"settings,omitempty"`
}

// maxPages bounds the pagination loops so a malformed or cycling
// `Link: rel="next"` header cannot spin forever and hang a scan. At queryLimit
// (200) per page this covers 200k records, far beyond any real org.
const maxPages = 1000

// ListPolicies retrieves all policies of the given type, following Okta's
// `Link: <url>; rel="next"` pagination until no `next` link remains. It returns
// the first page's http.Response so callers can branch on the status code (e.g.
// treat 404 or an "invalid policy type" 400 as an empty result).
func (m *ApiExtension) ListPolicies(ctx context.Context, policyType string, limit int) ([]*PolicyWrapper, *http.Response, error) {
	params := url.Values{}
	params.Set("type", policyType)
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	nextURL := m.urlWithParams("/api/v1/policies", params)

	policies := []*PolicyWrapper{}
	var firstResp *http.Response
	for i := 0; i < maxPages && nextURL != ""; i++ {
		var page []*PolicyWrapper
		resp, err := m.get(ctx, nextURL, &page)
		if firstResp == nil {
			firstResp = resp
		}
		if err != nil {
			return nil, resp, err
		}
		policies = append(policies, page...)
		if resp == nil {
			break
		}
		nextURL = nextPageURL(nextURL, resp.Header.Values("Link"))
	}

	return policies, firstResp, nil
}

// ListPolicyRules fetches all rules for a policy, following Okta's
// `Link: <url>; rel="next"` pagination until no `next` link remains. Rules are
// returned as raw JSON objects because the rule shape is a per-policy-type
// discriminated union that the caller decodes into its own struct. This backs
// the ACCESS_POLICY rule listing, which the generated SDK does not expose.
func (m *ApiExtension) ListPolicyRules(ctx context.Context, policyId string, limit int) ([]json.RawMessage, error) {
	params := url.Values{}
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	nextURL := m.urlWithParams("/api/v1/policies/"+url.PathEscape(policyId)+"/rules", params)

	rules := []json.RawMessage{}
	for i := 0; i < maxPages && nextURL != ""; i++ {
		page := []json.RawMessage{}
		resp, err := m.get(ctx, nextURL, &page)
		if err != nil {
			return nil, err
		}
		rules = append(rules, page...)
		if resp == nil {
			break
		}
		nextURL = nextPageURL(nextURL, resp.Header.Values("Link"))
	}

	return rules, nil
}
