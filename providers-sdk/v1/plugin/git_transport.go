// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"sync"

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
//
// go-git has no per-clone transport either: it takes one from its
// process-global protocol table by URL scheme. So the http(s) transports are
// wrapped once, and the wrapper adjusts a request only for a clone whose
// CloneOptions.Auth is a gitServerAuth naming Azure DevOps. gitClone sets that
// from the connection's GitServerOptionKey, which the provider that discovered
// the repository set because it knows what it talked to; nothing here guesses
// from a host name. Every other clone gets the base transport's own session.

// gitServerAuth is the transport.AuthMethod gitClone sets on a clone whose
// connection names its git server. Auth is the one per-clone value go-git
// hands the transport, for the clone and again for each submodule, which is
// why the marker rides on it. It carries no credential: those stay in the URL,
// as for every other clone, and gitServerTransport hands the base transport a
// nil auth in its place so that the URL's userinfo is used as before.
type gitServerAuth struct {
	// server is the GitServerOptionKey value.
	server string
}

func (a *gitServerAuth) Name() string   { return "git-server" }
func (a *gitServerAuth) String() string { return "git-server " + a.server }

// gitServerAuthFor is the Auth for a clone of the named server: nil for "",
// which is go-git's default request.
func gitServerAuthFor(server string) transport.AuthMethod {
	if server == "" {
		return nil
	}
	return &gitServerAuth{server: server}
}

// gitServerTransport is a transport.Transport that delegates to base. A
// session asked for with a gitServerAuth is wrapped for the server it names;
// every other session is the base transport's own, asked for with the
// caller's endpoint and auth as they are.
type gitServerTransport struct {
	base transport.Transport
}

func (t *gitServerTransport) NewUploadPackSession(ep *transport.Endpoint, auth transport.AuthMethod) (transport.UploadPackSession, error) {
	marker, ok := auth.(*gitServerAuth)
	if !ok {
		// Not one of ours: hand back exactly what the base transport produces.
		return t.base.NewUploadPackSession(ep, auth)
	}
	session, err := t.base.NewUploadPackSession(ep, nil)
	if err != nil {
		return session, err
	}
	switch marker.server {
	case GitServerAzureDevOps:
		return &azureDevOpsUploadPackSession{UploadPackSession: session}, nil
	default:
		// NewGitClone refuses a value this transport does not know before a
		// clone starts. On its own the transport sends go-git's default.
		return session, nil
	}
}

func (t *gitServerTransport) NewReceivePackSession(ep *transport.Endpoint, auth transport.AuthMethod) (transport.ReceivePackSession, error) {
	if _, ok := auth.(*gitServerAuth); ok {
		auth = nil
	}
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
// keeps the Azure DevOps request correct whatever
// transport.UnsupportedCapabilities holds.
func adjustAzureDevOpsCapabilities(caps *capability.List) error {
	caps.Delete(capability.ThinPack)
	caps.Delete(capability.MultiACK)
	return caps.Set(capability.MultiACKDetailed)
}

// wrapGitTransports puts a gitServerTransport over the http and https entries
// of go-git's protocol table. It is idempotent: an entry that is already
// wrapped is left alone, so the wrapper is never wrapped in itself.
func wrapGitTransports() {
	for _, scheme := range []string{"http", "https"} {
		base := client.Protocols[scheme]
		if base == nil {
			continue
		}
		if _, wrapped := base.(*gitServerTransport); wrapped {
			continue
		}
		client.InstallProtocol(scheme, &gitServerTransport{base: base})
	}
}

var wrapGitTransportsOnce sync.Once

// installGitTransport wraps go-git's http(s) transports once per process.
// go-git's client.Protocols map is not synchronized, so the single write
// happens here, before the first clone, in the only place in this repository
// that clones; every later call only reads the map.
func installGitTransport() {
	wrapGitTransportsOnce.Do(wrapGitTransports)
}
