// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUrlWithParams(t *testing.T) {
	t.Parallel()
	m := &ApiExtension{Host: "x.okta.com"}

	tests := []struct {
		name   string
		path   string
		params url.Values
		expect string
	}{
		{
			name:   "no params leaves off the separator",
			path:   "/api/v1/api-tokens",
			params: url.Values{},
			expect: "https://x.okta.com/api/v1/api-tokens",
		},
		{
			name:   "nil params leaves off the separator",
			path:   "/api/v1/api-tokens",
			params: nil,
			expect: "https://x.okta.com/api/v1/api-tokens",
		},
		{
			name:   "single param",
			path:   "/api/v1/api-tokens",
			params: url.Values{"limit": []string{"200"}},
			expect: "https://x.okta.com/api/v1/api-tokens?limit=200",
		},
		{
			name:   "values are escaped",
			path:   "/api/v1/policies",
			params: url.Values{"type": []string{"ACCESS POLICY"}},
			expect: "https://x.okta.com/api/v1/policies?type=ACCESS+POLICY",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, m.urlWithParams(tc.path, tc.params))
		})
	}
}
