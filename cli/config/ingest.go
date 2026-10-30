// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"net/url"
	"strings"
)

const (
	// hostedDomain is the DNS domain of Mondoo's hosted regions. Ingest
	// endpoints exist only there: a self-hosted or edge deployment publishes
	// its ingest domain in its own server config, and the client never learns
	// it (it only ever sees the host inside a signed upload URL, at upload
	// time). So anything outside this domain derives no ingest endpoint at all
	// rather than a guessed one.
	hostedDomain = "mondoo.com"

	// hostedAPILabel is the label every hosted API host carries in front of the
	// domain: "us.api.mondoo.com", or a bare "api.mondoo.com" for the legacy
	// unregioned endpoint.
	hostedAPILabel = "api"

	// ingestLabel prefixes the ingest host of a region:
	// "us.api.mondoo.com" -> "ingest.us.mondoo.com".
	ingestLabel = "ingest"

	// legacyRegion is the region behind the unregioned https://api.mondoo.com,
	// which is an alias for the US region.
	legacyRegion = "us"
)

// UpstreamIngestEndpoint returns the ingest endpoint that scan uploads are
// routed through for the configured region, or "" when none can be derived.
//
// It is the upload counterpart of UpstreamApiEndpoint and takes its region from
// it, so the region follows the same resolution order the API endpoint does
// (flag, env, config file, default). The two are separate hosts on separate
// static IPs, which is the whole reason this exists: an egress firewall can
// allow the API and still blackhole uploads.
func (c *CommonOpts) UpstreamIngestEndpoint() string {
	return IngestEndpointFor(c.UpstreamApiEndpoint())
}

// IngestEndpointFor derives the ingest endpoint that belongs to a Mondoo API
// endpoint: https://us.api.mondoo.com -> https://ingest.us.mondoo.com.
//
// It returns "" when apiEndpoint is not a hosted Mondoo API host — a
// self-hosted deployment, a staging endpoint on another domain, or localhost.
// Callers treat that as "no ingest check to run": inventing a host would turn
// an unknown into a resolution failure that reads like a blocked firewall.
func IngestEndpointFor(apiEndpoint string) string {
	region := hostedRegion(apiEndpoint)
	if region == "" {
		return ""
	}
	// Hosted regions are HTTPS-only, so the scheme is not carried over from
	// apiEndpoint.
	return "https://" + ingestLabel + "." + region + "." + hostedDomain
}

// hostedRegion extracts the region label from a hosted Mondoo API endpoint:
// "https://eu.api.mondoo.com" -> "eu", and the unregioned legacy
// "https://api.mondoo.com" -> "us". It returns "" for any host that is not
// <region>.api or api under hostedDomain.
//
// The region label itself is not checked against a list of known regions, so a
// region added to the platform later works without a client release. The cost
// is that an api_endpoint pointed at some other host under the domain (a
// token-exchange or scanner host, say) derives an ingest host that does not
// exist; that is not a value a client's api_endpoint takes, and silently
// skipping the check for a real new region is the worse failure.
func hostedRegion(apiEndpoint string) string {
	raw := strings.TrimSpace(apiEndpoint)
	if raw == "" {
		return ""
	}
	// api_endpoint is conventionally a full URL, but a bare host is accepted
	// too — url.Parse would otherwise file the whole thing under Path and
	// leave Host empty.
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	// Hostname() drops the port and the brackets around an IPv6 literal.
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	prefix, ok := strings.CutSuffix(host, "."+hostedDomain)
	if !ok {
		return ""
	}
	if prefix == hostedAPILabel {
		return legacyRegion
	}
	region, ok := strings.CutSuffix(prefix, "."+hostedAPILabel)
	if !ok || region == "" || strings.Contains(region, ".") {
		return ""
	}
	return region
}
