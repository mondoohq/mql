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
// wrapped once, and the wrapper adjusts a request only when the clone's
// context names Azure DevOps as the server. gitClone puts that in the context
// from the connection's GitServerOptionKey, which the provider that discovered
// the repository set because it knows what it talked to; nothing here guesses
// from a host name. A clone without the option sends exactly what go-git built.

// gitServerKey is the context key under which gitClone records the
// GitServerOptionKey value for the transport.
type gitServerKey struct{}

// withGitServer records server, a GitServerOptionKey value, in ctx. An empty
// server returns ctx as it is.
func withGitServer(ctx context.Context, server string) context.Context {
	if server == "" {
		return ctx
	}
	return context.WithValue(ctx, gitServerKey{}, server)
}

// gitServerFrom returns the server withGitServer recorded in ctx, or "".
func gitServerFrom(ctx context.Context) string {
	server, _ := ctx.Value(gitServerKey{}).(string)
	return server
}

// gitServerTransport is a transport.Transport that delegates to base and wraps
// each upload-pack session so that its request can be adjusted for the server
// the clone's context names. The endpoint and auth reach base as the caller
// built them.
type gitServerTransport struct {
	base transport.Transport
}

func (t *gitServerTransport) NewUploadPackSession(ep *transport.Endpoint, auth transport.AuthMethod) (transport.UploadPackSession, error) {
	session, err := t.base.NewUploadPackSession(ep, auth)
	if err != nil {
		return session, err
	}
	return &gitServerUploadPackSession{UploadPackSession: session}, nil
}

func (t *gitServerTransport) NewReceivePackSession(ep *transport.Endpoint, auth transport.AuthMethod) (transport.ReceivePackSession, error) {
	return t.base.NewReceivePackSession(ep, auth)
}

// gitServerUploadPackSession adjusts the upload-pack request before it is sent
// when the context names Azure DevOps, and otherwise hands the request to the
// embedded session untouched. The advertisement path is the embedded
// session's, unchanged.
type gitServerUploadPackSession struct {
	transport.UploadPackSession
}

func (s *gitServerUploadPackSession) UploadPack(ctx context.Context, req *packp.UploadPackRequest) (*packp.UploadPackResponse, error) {
	if gitServerFrom(ctx) == GitServerAzureDevOps && req != nil && req.Capabilities != nil {
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
