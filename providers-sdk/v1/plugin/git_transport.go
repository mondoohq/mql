// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"strings"

	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
)

// Azure DevOps rejects go-git's default upload-pack request with HTTP 400:
// the request carries no multi_ack_detailed, which Azure DevOps requires.
// go-git filters multi_ack and multi_ack_detailed out of what a server
// advertises (transport.UnsupportedCapabilities) before it builds the request.
// That filter is a process-global that go-git reads without locking, and mql
// providers are long-lived and shared across scans, so changing it would also
// change every GitHub and GitLab clone. The global is therefore never touched.
// Instead the http(s) transport is wrapped once, and only sessions for Azure
// DevOps hosts have their request adjusted.

// isAzureDevOpsHost reports whether host is served by Azure DevOps Services:
// dev.azure.com, or an organization host under visualstudio.com. host is a
// bare hostname; go-git's transport.Endpoint.Host carries no port.
func isAzureDevOpsHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "dev.azure.com" {
		return true
	}
	const legacySuffix = ".visualstudio.com"
	return strings.HasSuffix(host, legacySuffix) && len(host) > len(legacySuffix)
}

// adjustAzureDevOpsCapabilities makes caps what Azure DevOps accepts: exactly
// multi_ack_detailed (multi_ack and multi_ack_detailed are mutually exclusive)
// and no thin-pack. The request is edited in place, which is what go-git then
// reads to decode the response, so request and response stay consistent.
// Stating both requirements here, rather than relying on the filter list,
// keeps the ADO request correct whatever transport.UnsupportedCapabilities
// holds.
func adjustAzureDevOpsCapabilities(caps *capability.List) error {
	caps.Delete(capability.ThinPack)
	caps.Delete(capability.MultiACK)
	return caps.Set(capability.MultiACKDetailed)
}
