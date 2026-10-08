// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/stretchr/testify/require"
)

func TestGitServerAuthFor(t *testing.T) {
	require.Nil(t, gitServerAuthFor(""), "no option: a nil Auth, go-git's default")

	auth := gitServerAuthFor(GitServerAzureDevOps)
	require.Equal(t, &gitServerAuth{server: GitServerAzureDevOps}, auth)
	require.Equal(t, "git-server", auth.Name())
	require.Equal(t, "git-server azure-devops", auth.String())
}

func newCaps(t *testing.T, caps ...capability.Capability) *capability.List {
	t.Helper()
	list := capability.NewList()
	for _, c := range caps {
		require.NoError(t, list.Set(c))
	}
	return list
}

func TestAdjustAzureDevOpsCapabilities(t *testing.T) {
	tests := []struct {
		name string
		in   []capability.Capability
		want []string
	}{
		{
			name: "what go-git sends by default",
			in:   []capability.Capability{capability.Sideband64k, capability.OFSDelta},
			want: []string{"multi_ack_detailed", "ofs-delta", "side-band-64k"},
		},
		{
			name: "multi_ack becomes multi_ack_detailed",
			in:   []capability.Capability{capability.MultiACK, capability.Sideband64k},
			want: []string{"multi_ack_detailed", "side-band-64k"},
		},
		{
			name: "thin-pack is dropped",
			in:   []capability.Capability{capability.MultiACKDetailed, capability.ThinPack, capability.Sideband64k},
			want: []string{"multi_ack_detailed", "side-band-64k"},
		},
		{
			name: "multi_ack, multi_ack_detailed and thin-pack together",
			in:   []capability.Capability{capability.MultiACK, capability.MultiACKDetailed, capability.ThinPack},
			want: []string{"multi_ack_detailed"},
		},
		{
			name: "an empty request still gets multi_ack_detailed",
			in:   nil,
			want: []string{"multi_ack_detailed"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caps := newCaps(t, tc.in...)
			require.NoError(t, adjustAzureDevOpsCapabilities(caps))
			require.Equal(t, tc.want, capSet(caps))

			// Applying it again changes nothing.
			require.NoError(t, adjustAzureDevOpsCapabilities(caps))
			require.Equal(t, tc.want, capSet(caps))
		})
	}
}

func TestAdjustAzureDevOpsCapabilities_KeepsValuesAndStaysValid(t *testing.T) {
	req := packp.NewUploadPackRequest()
	req.Wants = []plumbing.Hash{plumbing.NewHash("1519ae7d83e8fc731716a103ee805027f122058c")}
	require.NoError(t, req.Capabilities.Set(capability.Agent, "go-git/test"))
	require.NoError(t, req.Capabilities.Set(capability.MultiACK))
	require.NoError(t, req.Capabilities.Set(capability.ThinPack))

	require.NoError(t, adjustAzureDevOpsCapabilities(req.Capabilities))

	require.Equal(t, []string{"go-git/test"}, req.Capabilities.Get(capability.Agent))
	// multi_ack together with multi_ack_detailed is what Validate rejects.
	require.NoError(t, req.Validate())
}

var errCaptured = errors.New("captured")

// captureSession records the request it is given and answers with errCaptured.
type captureSession struct {
	transport.UploadPackSession
	calls int
	got   *packp.UploadPackRequest
}

func (s *captureSession) UploadPack(_ context.Context, req *packp.UploadPackRequest) (*packp.UploadPackResponse, error) {
	s.calls++
	s.got = req
	return nil, errCaptured
}

// fakeBase is a transport.Transport that records what it is asked for and
// returns canned sessions. For every session call it keeps the endpoint
// pointer it was handed, a copy of that endpoint taken at the moment of the
// call, and the auth method, so a test can tell whether the wrapper passed the
// caller's own objects through untouched.
type fakeBase struct {
	upload    transport.UploadPackSession
	uploadErr error
	receive   transport.ReceivePackSession

	uploadEndpoint     []*transport.Endpoint
	uploadEndpointCopy []transport.Endpoint
	uploadAuth         []transport.AuthMethod
	receiveAuth        []transport.AuthMethod
}

// copyEndpoint is a value copy of ep that shares no byte slice with it.
func copyEndpoint(ep *transport.Endpoint) transport.Endpoint {
	c := *ep
	c.ClientCert = slices.Clone(ep.ClientCert)
	c.ClientKey = slices.Clone(ep.ClientKey)
	c.CaBundle = slices.Clone(ep.CaBundle)
	return c
}

func (b *fakeBase) NewUploadPackSession(ep *transport.Endpoint, auth transport.AuthMethod) (transport.UploadPackSession, error) {
	b.uploadEndpoint = append(b.uploadEndpoint, ep)
	b.uploadEndpointCopy = append(b.uploadEndpointCopy, copyEndpoint(ep))
	b.uploadAuth = append(b.uploadAuth, auth)
	return b.upload, b.uploadErr
}

func (b *fakeBase) NewReceivePackSession(_ *transport.Endpoint, auth transport.AuthMethod) (transport.ReceivePackSession, error) {
	b.receiveAuth = append(b.receiveAuth, auth)
	return b.receive, nil
}

type fakeReceiveSession struct{ transport.ReceivePackSession }

func mustEndpoint(t *testing.T, raw string) *transport.Endpoint {
	t.Helper()
	ep, err := transport.NewEndpoint(raw)
	require.NoError(t, err)
	return ep
}

// The clone URLs the tests below use: GitHub, GitLab and self-hosted shapes,
// and Azure DevOps on both of its hosts. The wrapper treats them all alike,
// because the host decides nothing.
var (
	otherHostURLs = []string{
		"https://github.com/mondoohq/mql.git",
		"https://x-access-token:token@github.com/mondoohq/mql.git",
		"https://gitlab.com/group/project.git",
		"https://user:token@gitlab.com/group/project.git",
		"https://token-only@gitlab.com/group/project.git",
		"https://bitbucket.org/team/repo.git",
		"https://gitlab.example.com:8443/group/project.git",
		"https://ci:token@git.example.com:8443/team/repo.git",
		"http://ci:token@localhost:8080/team/repo.git",
	}
	azureDevOpsURLs = []string{
		"https://dev.azure.com/fabrikam-fixture-org/scan-test/_git/ado-scan-test-iac",
		"https://ci:token@dev.azure.com:443/fabrikam-fixture-org/scan-test/_git/ado-scan-test-iac",
		"https://Fabrikam-Fixture-Org.VisualStudio.com/scan-test/_git/ado-scan-test-iac",
	}
)

// Without a gitServerAuth there is no wrapper at all: the session is the base
// transport's very own, asked for with the caller's endpoint and auth,
// whatever host the clone is for.
func TestGitServerTransport_OtherAuthGetsTheBaseSessionUntouched(t *testing.T) {
	// Each call builds a fresh auth, so the one handed to the wrapper can be
	// compared with an independent, pristine copy of itself afterwards.
	auths := []struct {
		name string
		new  func() transport.AuthMethod
	}{
		{"no auth", func() transport.AuthMethod { return nil }},
		{"basic auth", func() transport.AuthMethod {
			return &githttp.BasicAuth{Username: "ci", Password: fixtureToken}
		}},
	}
	for _, raw := range slices.Concat(otherHostURLs, azureDevOpsURLs) {
		for _, a := range auths {
			t.Run(raw+"/"+a.name, func(t *testing.T) {
				session := &captureSession{}
				base := &fakeBase{upload: session}
				wrapper := &gitServerTransport{base: base}
				ep, wantEP, auth := mustEndpoint(t, raw), mustEndpoint(t, raw), a.new()

				got, err := wrapper.NewUploadPackSession(ep, auth)

				require.NoError(t, err)
				// The very object the base transport produced: no wrapper, so the
				// request it later sends is whatever go-git built.
				require.Same(t, session, got)

				// The base transport was asked once, with the caller's own
				// endpoint and auth. Nothing in them was edited before the
				// call (the recorded copy) or after it (the caller's object).
				require.Len(t, base.uploadEndpoint, 1)
				require.Same(t, ep, base.uploadEndpoint[0], "the endpoint is the caller's, not a copy")
				require.Equal(t, *wantEP, base.uploadEndpointCopy[0], "the base saw the endpoint as the caller built it")
				require.Equal(t, *wantEP, copyEndpoint(ep), "the caller's endpoint is unchanged afterwards")
				require.Len(t, base.uploadAuth, 1)
				if auth == nil {
					require.Nil(t, base.uploadAuth[0])
				} else {
					require.Same(t, auth, base.uploadAuth[0], "the auth is the caller's, not a wrapper or a copy")
					require.Equal(t, a.new(), auth, "the auth is unchanged")
				}
			})
		}
	}
}

// A gitServerAuth naming Azure DevOps is taken off before the base transport
// sees it, so the URL's credentials are used as for every other clone, and the
// session is wrapped so that its request carries what Azure DevOps requires.
// The host plays no part: a loopback or self-hosted address is treated like
// dev.azure.com.
func TestGitServerTransport_AzureDevOpsAuthGetsTheAdjustedSession(t *testing.T) {
	for _, raw := range slices.Concat(azureDevOpsURLs, []string{
		"http://ci:token@127.0.0.1:8080/fabrikam-fixture-org/scan-test/_git/ado-scan-test-iac",
		"https://tfs.corp.example/collection/project/_git/repo",
	}) {
		t.Run(raw, func(t *testing.T) {
			session := &captureSession{}
			base := &fakeBase{upload: session}
			wrapper := &gitServerTransport{base: base}
			ep, wantEP := mustEndpoint(t, raw), mustEndpoint(t, raw)

			got, err := wrapper.NewUploadPackSession(ep, gitServerAuthFor(GitServerAzureDevOps))

			require.NoError(t, err)
			wrapped, ok := got.(*azureDevOpsUploadPackSession)
			require.True(t, ok)
			require.Same(t, session, wrapped.UploadPackSession, "wrapped around the very session the base produced")
			require.Len(t, base.uploadAuth, 1)
			require.Nil(t, base.uploadAuth[0], "the marker never reaches the base transport")
			require.Same(t, ep, base.uploadEndpoint[0])
			require.Equal(t, *wantEP, copyEndpoint(ep), "the endpoint, credentials included, is unchanged")

			// go-git's default request: neither multi_ack nor thin-pack.
			req := packp.NewUploadPackRequest()
			require.NoError(t, req.Capabilities.Set(capability.Sideband64k))
			_, err = got.UploadPack(context.Background(), req)

			require.ErrorIs(t, err, errCaptured, "the underlying session's answer is passed through")
			require.Equal(t, 1, session.calls)
			require.Same(t, req, session.got, "the request is edited in place, not copied")
			require.Equal(t, []string{"multi_ack_detailed", "side-band-64k"}, capSet(session.got.Capabilities))
		})
	}
}

// A gitServerAuth with a value this transport does not know is still taken
// off, and the session is the base transport's own. NewGitClone refuses such a
// value before a clone starts; this pins what the transport does on its own.
func TestGitServerTransport_UnknownServerGetsTheBaseSession(t *testing.T) {
	session := &captureSession{}
	base := &fakeBase{upload: session}
	wrapper := &gitServerTransport{base: base}

	got, err := wrapper.NewUploadPackSession(mustEndpoint(t, otherHostURLs[0]), &gitServerAuth{server: "gitea"})

	require.NoError(t, err)
	require.Same(t, session, got)
	require.Len(t, base.uploadAuth, 1)
	require.Nil(t, base.uploadAuth[0])
}

func TestGitServerTransport_BaseErrorsPassThroughUnchanged(t *testing.T) {
	boom := errors.New("boom")
	for name, auth := range map[string]transport.AuthMethod{
		"no auth":           nil,
		"azure devops auth": gitServerAuthFor(GitServerAzureDevOps),
	} {
		t.Run(name, func(t *testing.T) {
			session := &captureSession{}
			wrapper := &gitServerTransport{base: &fakeBase{upload: session, uploadErr: boom}}

			got, err := wrapper.NewUploadPackSession(mustEndpoint(t, azureDevOpsURLs[0]), auth)

			require.Same(t, boom, err)
			require.Same(t, session, got)
		})
	}
}

func TestGitServerTransport_ReceivePackIsNeverWrapped(t *testing.T) {
	receive := &fakeReceiveSession{}
	basic := &githttp.BasicAuth{Username: "ci", Password: fixtureToken}
	tests := map[string]struct {
		auth     transport.AuthMethod
		wantBase transport.AuthMethod // what the base transport is handed
	}{
		"no auth":           {nil, nil},
		"basic auth":        {basic, basic},
		"azure devops auth": {gitServerAuthFor(GitServerAzureDevOps), nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			base := &fakeBase{receive: receive}
			wrapper := &gitServerTransport{base: base}

			got, err := wrapper.NewReceivePackSession(mustEndpoint(t, azureDevOpsURLs[0]), tc.auth)

			require.NoError(t, err)
			require.Same(t, receive, got)
			require.Len(t, base.receiveAuth, 1)
			if tc.wantBase == nil {
				require.Nil(t, base.receiveAuth[0])
			} else {
				require.Same(t, tc.wantBase, base.receiveAuth[0])
			}
		})
	}
}

func TestAzureDevOpsSession_NilRequestsReachTheUnderlyingSession(t *testing.T) {
	// go-git validates the request itself and reports ErrEmptyUploadPackRequest;
	// the wrapper must not turn that into a nil-pointer panic.
	nilCaps := &packp.UploadPackRequest{}
	for name, req := range map[string]*packp.UploadPackRequest{
		"nil request":      nil,
		"nil capabilities": nilCaps,
	} {
		t.Run(name, func(t *testing.T) {
			session := &captureSession{}
			wrapped := &azureDevOpsUploadPackSession{UploadPackSession: session}

			var err error
			require.NotPanics(t, func() { _, err = wrapped.UploadPack(context.Background(), req) })

			require.ErrorIs(t, err, errCaptured)
			require.Equal(t, 1, session.calls)
			require.Same(t, req, session.got)
		})
	}
}

// restoreProtocols puts go-git's whole protocol table back after a test that
// rewrites it: every scheme the test replaced is reinstalled and every scheme it
// added is removed, so one test's edit can never decide the next test's result.
func restoreProtocols(t *testing.T) {
	t.Helper()
	saved := make(map[string]transport.Transport, len(client.Protocols))
	for scheme, tr := range client.Protocols {
		saved[scheme] = tr
	}
	t.Cleanup(func() {
		for scheme := range client.Protocols {
			if _, kept := saved[scheme]; !kept {
				delete(client.Protocols, scheme)
			}
		}
		for scheme, tr := range saved {
			client.InstallProtocol(scheme, tr)
		}
	})
}

func TestWrapGitTransports_WrapsHTTPAndHTTPSExactlyOnce(t *testing.T) {
	restoreProtocols(t)
	client.InstallProtocol("http", stockHTTP)
	client.InstallProtocol("https", stockHTTPS)

	wrapGitTransports()
	wrapGitTransports() // idempotent: a second call must not wrap the wrapper in itself

	for scheme, stock := range map[string]transport.Transport{"http": stockHTTP, "https": stockHTTPS} {
		wrapper, ok := client.Protocols[scheme].(*gitServerTransport)
		require.True(t, ok, scheme)
		require.Same(t, stock, wrapper.base, scheme)
	}
}

func TestWrapGitTransports_LeavesOtherSchemesAlone(t *testing.T) {
	restoreProtocols(t)
	ssh, file := client.Protocols["ssh"], client.Protocols["file"]

	wrapGitTransports()

	require.Same(t, ssh, client.Protocols["ssh"])
	require.Same(t, file, client.Protocols["file"])
}

// resetGitTransport puts go-git's http(s) transports back to its own and re-arms
// the one-time install, so the test starts like a process that has not cloned
// yet. A test that expects gitClone to install the wrapper would otherwise pass
// whenever an earlier test had already installed it.
func resetGitTransport(t *testing.T) {
	t.Helper()
	restoreProtocols(t)
	client.InstallProtocol("http", stockHTTP)
	client.InstallProtocol("https", stockHTTPS)
	wrapGitTransportsOnce = sync.Once{}
	t.Cleanup(func() { wrapGitTransportsOnce = sync.Once{} })
}

func TestInstallGitTransport_WrapsOnceHoweverOftenItIsCalled(t *testing.T) {
	resetGitTransport(t)

	installGitTransport()
	installGitTransport()

	for scheme, stock := range map[string]transport.Transport{"http": stockHTTP, "https": stockHTTPS} {
		wrapper, ok := client.Protocols[scheme].(*gitServerTransport)
		require.True(t, ok, scheme)
		require.Same(t, stock, wrapper.base, "%s: one layer over go-git's own transport", scheme)
	}
}

// The tests below clone from the in-process fake git server of
// git_fake_server_test.go over real HTTP. Both fakes listen on loopback, so
// which request a clone sends is decided by the clone option alone.

func TestClone_AzureDevOpsSucceedsWithTheServerOption(t *testing.T) {
	resetGitTransport(t)
	srv := newFakeGitServer(t, fakeAzureDevOps, fixtureToken)

	dir, closer, err := gitClone(srv.repoURL("127.0.0.1", "ci:"+fixtureToken), withGitServer(GitServerAzureDevOps))
	require.NoError(t, err)
	defer closer()

	got, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	require.Equal(t, fixtureMainTF, string(got))

	reqs := srv.uploadPackRequests()
	require.Len(t, reqs, 1)
	require.Equal(t, []string{"agent", "multi_ack_detailed", "shallow", "side-band-64k"}, capSet(reqs[0].Caps))
	// The credential in the URL was used, as for every other clone: the
	// fake would have answered 401 otherwise.
	require.NotEmpty(t, reqs[0].Header.Get("Authorization"))
}

// Without the option an Azure DevOps server still gets go-git's default request
// and rejects it: the adjustment is opted into, never inferred from the host.
func TestClone_AzureDevOpsFailsWithoutTheServerOption(t *testing.T) {
	resetGitTransport(t)
	srv := newFakeGitServer(t, fakeAzureDevOps, fixtureToken)

	dir, closer, err := gitClone(srv.repoURL("127.0.0.1", "ci:"+fixtureToken))

	require.Error(t, err)
	require.ErrorContains(t, err, "status code: 400")
	require.Empty(t, dir)
	require.Nil(t, closer)
	reqs := srv.uploadPackRequests()
	require.Len(t, reqs, 1)
	require.Equal(t, []string{"agent", "shallow", "side-band-64k"}, capSet(reqs[0].Caps))
}

func TestClone_WithoutTheOptionKeepsGoGitsDefaultRequest(t *testing.T) {
	resetGitTransport(t)
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)
	userinfo := "ci:" + fixtureToken

	// Control: go-git's own transport, no wrapper anywhere.
	_, err := cloneWithStockTransport(t, srv.repoURL("localhost", userinfo))
	require.NoError(t, err)
	// The same clone through gitClone, which installs the wrapper: once with
	// no option at all, once with the empty server that NewGitClone passes
	// for a connection without GitServerOptionKey.
	for _, opts := range [][]gitCloneOption{nil, {withGitServer("")}} {
		dir, closer, err := gitClone(srv.repoURL("localhost", userinfo), opts...)
		require.NoError(t, err)
		defer closer()
		require.FileExists(t, filepath.Join(dir, "main.tf"))
	}

	reqs := srv.uploadPackRequests()
	require.Len(t, reqs, 3)

	// The exact capability list go-git sends today: no multi_ack, no
	// multi_ack_detailed, no thin-pack. "shallow" is there because gitClone
	// clones with Depth 1.
	for i, r := range reqs {
		require.Equal(t, []string{"agent", "ofs-delta", "shallow", "side-band-64k"}, capSet(r.Caps), "request %d", i)
		require.Equal(t, []string{capability.DefaultAgent()}, r.Caps.Get(capability.Agent), "request %d", i)
		// And the request bytes and headers are identical to the control's,
		// credentials included: the wrapper adds, drops and alters none. The
		// Authorization check keeps the comparison from passing vacuously on
		// empty header sets.
		require.Equal(t, string(reqs[0].Body), string(r.Body), "request %d", i)
		require.NotEmpty(t, r.Header.Get("Authorization"), "request %d", i)
		require.Equal(t, reqs[0].Header, r.Header, "request %d", i)
	}
	adverts := srv.advertisementHeaders()
	require.Len(t, adverts, 3)
	for i, h := range adverts {
		require.NotEmpty(t, h.Get("Authorization"), "advertisement %d", i)
		require.Equal(t, adverts[0], h, "advertisement %d", i)
	}
}

func TestClone_ConcurrentClonesWithAndWithoutTheOptionDoNotInterfere(t *testing.T) {
	resetGitTransport(t)
	ado := newFakeGitServer(t, fakeAzureDevOps, fixtureToken)
	other := newFakeGitServer(t, fakeStandard, fixtureToken)
	userinfo := "ci:" + fixtureToken
	adoURL := ado.repoURL("127.0.0.1", userinfo)
	otherURL := other.repoURL("localhost", userinfo)
	filterBefore := slices.Clone(transport.UnsupportedCapabilities)

	const perServer = 6
	var wg sync.WaitGroup
	errs := make(chan error, 2*perServer)
	cloneOnce := func(url string, opts ...gitCloneOption) {
		defer wg.Done()
		dir, closer, err := gitClone(url, opts...)
		if err != nil {
			errs <- err
			return
		}
		defer closer()
		_, err = os.Stat(filepath.Join(dir, "main.tf"))
		errs <- err
	}
	for i := 0; i < perServer; i++ {
		wg.Add(2)
		go cloneOnce(adoURL, withGitServer(GitServerAzureDevOps))
		go cloneOnce(otherURL)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	adoReqs, otherReqs := ado.uploadPackRequests(), other.uploadPackRequests()
	require.Len(t, adoReqs, perServer)
	require.Len(t, otherReqs, perServer)
	for _, r := range adoReqs {
		require.Equal(t, []string{"agent", "multi_ack_detailed", "shallow", "side-band-64k"}, capSet(r.Caps))
	}
	for _, r := range otherReqs {
		require.Equal(t, []string{"agent", "ofs-delta", "shallow", "side-band-64k"}, capSet(r.Caps))
	}
	require.Equal(t, filterBefore, transport.UnsupportedCapabilities,
		"concurrent clones must leave go-git's process-global capability filter as they found it")
}

func TestClone_DoesNotTouchGoGitsGlobalCapabilityFilter(t *testing.T) {
	resetGitTransport(t)
	ado := newFakeGitServer(t, fakeAzureDevOps, fixtureToken)
	other := newFakeGitServer(t, fakeStandard, fixtureToken)
	userinfo := "ci:" + fixtureToken

	goGitDefault := []capability.Capability{capability.MultiACK, capability.MultiACKDetailed, capability.ThinPack}
	filterBefore := slices.Clone(transport.UnsupportedCapabilities)
	require.Equal(t, goGitDefault, filterBefore, "precondition: the filter starts as go-git ships it")

	for _, clone := range []struct {
		url  string
		opts []gitCloneOption
	}{
		{ado.repoURL("127.0.0.1", userinfo), []gitCloneOption{withGitServer(GitServerAzureDevOps)}},
		{other.repoURL("localhost", userinfo), nil},
	} {
		_, closer, err := gitClone(clone.url, clone.opts...)
		require.NoError(t, err)
		closer()
	}

	require.Equal(t, filterBefore, transport.UnsupportedCapabilities,
		"go-git's process-global filter must be exactly what it was before the clones")
	require.Equal(t, goGitDefault, transport.UnsupportedCapabilities,
		"go-git's process-global filter must be exactly what go-git ships")
}
