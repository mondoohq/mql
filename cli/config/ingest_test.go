// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIngestEndpointFor(t *testing.T) {
	tests := []struct {
		name        string
		apiEndpoint string
		expected    string
	}{
		{
			name:        "us region",
			apiEndpoint: "https://us.api.mondoo.com",
			expected:    "https://ingest.us.mondoo.com",
		},
		{
			name:        "eu region",
			apiEndpoint: "https://eu.api.mondoo.com",
			expected:    "https://ingest.eu.mondoo.com",
		},
		{
			// api.mondoo.com predates the regional hosts and is an alias for
			// the US region, so it maps to the US ingest host rather than to
			// nothing.
			name:        "legacy unregioned endpoint",
			apiEndpoint: "https://api.mondoo.com",
			expected:    "https://ingest.us.mondoo.com",
		},
		{
			// A region the platform adds later needs no client release: the
			// label is carried across rather than matched against a list.
			name:        "unknown region is carried across",
			apiEndpoint: "https://ap.api.mondoo.com",
			expected:    "https://ingest.ap.mondoo.com",
		},
		{
			name:        "trailing path and slash are ignored",
			apiEndpoint: "https://eu.api.mondoo.com/",
			expected:    "https://ingest.eu.mondoo.com",
		},
		{
			name:        "port is dropped",
			apiEndpoint: "https://us.api.mondoo.com:443",
			expected:    "https://ingest.us.mondoo.com",
		},
		{
			name:        "host is matched case-insensitively",
			apiEndpoint: "https://US.API.Mondoo.COM",
			expected:    "https://ingest.us.mondoo.com",
		},
		{
			name:        "bare host without a scheme",
			apiEndpoint: "eu.api.mondoo.com",
			expected:    "https://ingest.eu.mondoo.com",
		},
		{
			name:        "surrounding whitespace is trimmed",
			apiEndpoint: "  https://us.api.mondoo.com  ",
			expected:    "https://ingest.us.mondoo.com",
		},
		{
			// Hosted regions are HTTPS-only; an http:// API endpoint does not
			// produce an http:// ingest endpoint.
			name:        "scheme is not carried over",
			apiEndpoint: "http://us.api.mondoo.com",
			expected:    "https://ingest.us.mondoo.com",
		},
		{
			// Ingest hosts exist only in the hosted mondoo.com regions. Every
			// case below derives nothing, so `status` skips the check instead
			// of probing a host that was never provisioned and reporting the
			// resulting DNS failure as a blocked firewall.
			name:        "self-hosted deployment",
			apiEndpoint: "https://mondoo.example.com",
			expected:    "",
		},
		{
			name:        "staging on another domain",
			apiEndpoint: "https://api.edge.mondoo.app",
			expected:    "",
		},
		{
			name:        "localhost development server",
			apiEndpoint: "http://localhost:8989",
			expected:    "",
		},
		{
			name:        "hosted domain without the api label",
			apiEndpoint: "https://releases.mondoo.com",
			expected:    "",
		},
		{
			name:        "deeper label than a single region",
			apiEndpoint: "https://a.b.api.mondoo.com",
			expected:    "",
		},
		{
			// The domain itself is not an API host, so it derives nothing
			// rather than the legacy US alias.
			name:        "bare hosted domain",
			apiEndpoint: "https://mondoo.com",
			expected:    "",
		},
		{
			// A suffix match on the domain alone would accept this.
			name:        "lookalike domain",
			apiEndpoint: "https://us.api.notmondoo.com",
			expected:    "",
		},
		{
			name:        "empty endpoint",
			apiEndpoint: "",
			expected:    "",
		},
		{
			name:        "unparseable endpoint",
			apiEndpoint: "https://us.api.mondoo.com/%zz",
			expected:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IngestEndpointFor(tt.apiEndpoint))
		})
	}
}

func TestUpstreamIngestEndpoint_FollowsConfiguredApiEndpoint(t *testing.T) {
	opts := &CommonOpts{APIEndpoint: "https://eu.api.mondoo.com"}

	assert.Equal(t, "https://ingest.eu.mondoo.com", opts.UpstreamIngestEndpoint())
}

func TestUpstreamIngestEndpoint_DefaultsToTheDefaultRegion(t *testing.T) {
	// With no api_endpoint configured, UpstreamApiEndpoint falls back to the
	// default US endpoint, and the ingest endpoint has to follow it there.
	opts := &CommonOpts{}

	assert.Equal(t, "https://ingest.us.mondoo.com", opts.UpstreamIngestEndpoint())
	assert.Equal(t, IngestEndpointFor(opts.UpstreamApiEndpoint()), opts.UpstreamIngestEndpoint())
}

func TestUpstreamIngestEndpoint_SelfHostedDerivesNothing(t *testing.T) {
	opts := &CommonOpts{APIEndpoint: "https://mondoo.internal.example.com"}

	assert.Empty(t, opts.UpstreamIngestEndpoint())
}
