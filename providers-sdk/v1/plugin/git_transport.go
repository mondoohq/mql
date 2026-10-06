// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
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
// dev.azure.com, or <org>.visualstudio.com with exactly one non-empty
// organization label. host is a bare hostname; go-git's transport.Endpoint.Host
// carries no port. A host with any non-ASCII byte is never matched: Unicode case
// folding would otherwise turn a lookalike such as "vİsualstudio" (U+0130) into
// "visualstudio".
func isAzureDevOpsHost(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] >= utf8.RuneSelf {
			return false
		}
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "dev.azure.com" {
		return true
	}
	org, ok := strings.CutSuffix(host, ".visualstudio.com")
	return ok && org != "" && !strings.Contains(org, ".")
}

// adoHostMatcher decides which hosts get the Azure DevOps request. It is a
// variable only so tests can point the router at a loopback server; production
// code never reassigns it.
var adoHostMatcher = isAzureDevOpsHost

// hostRoutedTransport is a transport.Transport that delegates to base for
// every host. For Azure DevOps hosts it wraps the upload-pack session so its
// request carries the capabilities Azure DevOps requires.
type hostRoutedTransport struct {
	base transport.Transport
}

func (t *hostRoutedTransport) NewUploadPackSession(ep *transport.Endpoint, auth transport.AuthMethod) (transport.UploadPackSession, error) {
	session, err := t.base.NewUploadPackSession(ep, auth)
	if err != nil || !adoHostMatcher(ep.Host) {
		// Not Azure DevOps: hand back exactly what the base transport produced.
		return session, err
	}
	return &azureDevOpsUploadPackSession{UploadPackSession: session}, nil
}

func (t *hostRoutedTransport) NewReceivePackSession(ep *transport.Endpoint, auth transport.AuthMethod) (transport.ReceivePackSession, error) {
	return t.base.NewReceivePackSession(ep, auth)
}

// azureDevOpsUploadPackSession adjusts the upload-pack request before it is
// sent. The advertisement path is the embedded session's, unchanged.
type azureDevOpsUploadPackSession struct {
	transport.UploadPackSession
}

func (s *azureDevOpsUploadPackSession) UploadPack(ctx context.Context, req *packp.UploadPackRequest) (*packp.UploadPackResponse, error) {
	if req != nil && req.Capabilities != nil {
		if err := adjustAzureDevOpsCapabilities(req.Capabilities); err != nil {
			return nil, err
		}
	}
	return s.UploadPackSession.UploadPack(ctx, req)
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

// routeGitHosts wraps the http and https entries of go-git's protocol table in
// a hostRoutedTransport. It is idempotent: an entry that is already routed is
// left alone, so the router is never wrapped in itself.
func routeGitHosts() {
	for _, scheme := range []string{"http", "https"} {
		base := client.Protocols[scheme]
		if base == nil {
			continue
		}
		if _, routed := base.(*hostRoutedTransport); routed {
			continue
		}
		client.InstallProtocol(scheme, &hostRoutedTransport{base: base})
	}
}

var routeGitHostsOnce sync.Once

// installGitTransport routes git clones by host, once per process. go-git's
// client.Protocols map is not synchronized, so the single write happens here,
// before the first clone, in the only place in this repository that clones;
// every later call only reads the map.
func installGitTransport() {
	routeGitHostsOnce.Do(routeGitHosts)
}
