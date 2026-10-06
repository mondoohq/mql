// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/stretchr/testify/require"
)

func TestIsAzureDevOpsHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		// Azure DevOps Services
		{"dev.azure.com", true},
		{"DEV.AZURE.COM", true},
		{"dev.azure.com.", true},
		{"mondoo-ado-scan-test.visualstudio.com", true},
		{"Mondoo-ADO-Scan-Test.VisualStudio.com", true},
		{"mondoo-ado-scan-test.visualstudio.com.", true},
		{"vs-ssh.visualstudio.com", true},

		// everything else, including near misses and Azure DevOps Server
		{"", false},
		{"github.com", false},
		{"gitlab.com", false},
		{"gitlab.example.com", false},
		{"bitbucket.org", false},
		{"ssh.dev.azure.com", false},
		{"azure.com", false},
		{"visualstudio.com", false},
		{".visualstudio.com", false},
		{"..visualstudio.com", false},
		{"a.b.visualstudio.com", false},
		{"org.vİsualstudio.com", false}, // U+0130 lowercases to "i" in Unicode-aware folding
		{"notvisualstudio.com", false},
		{"evildev.azure.com", false},
		{"dev.azure.com.evil.example", false},
		{"mondoo-ado-scan-test.visualstudio.com.evil.example", false},
		{"tfs.corp.example", false},
		{"127.0.0.1", false},
		{"localhost", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			require.Equal(t, tc.want, isAzureDevOpsHost(tc.host))
		})
	}
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

// fakeBase is a transport.Transport that records the hosts it is asked about
// and returns canned sessions.
type fakeBase struct {
	upload     transport.UploadPackSession
	uploadErr  error
	receive    transport.ReceivePackSession
	uploadHost []string
}

func (b *fakeBase) NewUploadPackSession(ep *transport.Endpoint, _ transport.AuthMethod) (transport.UploadPackSession, error) {
	b.uploadHost = append(b.uploadHost, ep.Host)
	return b.upload, b.uploadErr
}

func (b *fakeBase) NewReceivePackSession(*transport.Endpoint, transport.AuthMethod) (transport.ReceivePackSession, error) {
	return b.receive, nil
}

type fakeReceiveSession struct{ transport.ReceivePackSession }

func mustEndpoint(t *testing.T, raw string) *transport.Endpoint {
	t.Helper()
	ep, err := transport.NewEndpoint(raw)
	require.NoError(t, err)
	return ep
}

func TestHostRoutedTransport_OtherHostsGetTheBaseSessionUntouched(t *testing.T) {
	for _, raw := range []string{
		"https://github.com/mondoohq/mql.git",
		"https://user:token@gitlab.com/group/project.git",
		"https://bitbucket.org/team/repo.git",
		"https://gitlab.example.com:8443/group/project.git",
		"https://ssh.dev.azure.com/v3/org/project/repo",
	} {
		t.Run(raw, func(t *testing.T) {
			session := &captureSession{}
			router := &hostRoutedTransport{base: &fakeBase{upload: session}}

			got, err := router.NewUploadPackSession(mustEndpoint(t, raw), nil)

			require.NoError(t, err)
			// The very object the base transport produced: no wrapper, so the
			// request it later sends is whatever go-git built.
			require.Same(t, session, got)
		})
	}
}

func TestHostRoutedTransport_AzureDevOpsHostsGetTheAdjustedSession(t *testing.T) {
	for _, raw := range []string{
		"https://dev.azure.com/mondoo-ado-scan-test/scan-test/_git/ado-scan-test-iac",
		"https://ci:token@dev.azure.com:443/mondoo-ado-scan-test/scan-test/_git/ado-scan-test-iac",
		"https://Mondoo-ADO-Scan-Test.VisualStudio.com/scan-test/_git/ado-scan-test-iac",
	} {
		t.Run(raw, func(t *testing.T) {
			session := &captureSession{}
			router := &hostRoutedTransport{base: &fakeBase{upload: session}}

			got, err := router.NewUploadPackSession(mustEndpoint(t, raw), nil)
			require.NoError(t, err)
			require.IsType(t, &azureDevOpsUploadPackSession{}, got)

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

func TestHostRoutedTransport_BaseErrorsPassThroughUnchanged(t *testing.T) {
	boom := errors.New("boom")
	for _, raw := range []string{
		"https://dev.azure.com/org/project/_git/repo",
		"https://github.com/mondoohq/mql.git",
	} {
		t.Run(raw, func(t *testing.T) {
			session := &captureSession{}
			router := &hostRoutedTransport{base: &fakeBase{upload: session, uploadErr: boom}}

			got, err := router.NewUploadPackSession(mustEndpoint(t, raw), nil)

			require.Same(t, boom, err)
			require.Same(t, session, got)
		})
	}
}

func TestHostRoutedTransport_ReceivePackIsNeverWrapped(t *testing.T) {
	receive := &fakeReceiveSession{}
	router := &hostRoutedTransport{base: &fakeBase{receive: receive}}

	for _, raw := range []string{
		"https://dev.azure.com/org/project/_git/repo",
		"https://github.com/mondoohq/mql.git",
	} {
		got, err := router.NewReceivePackSession(mustEndpoint(t, raw), nil)
		require.NoError(t, err)
		require.Same(t, receive, got)
	}
}

func TestAzureDevOpsSession_NilRequestsReachTheUnderlyingSession(t *testing.T) {
	// go-git validates the request itself and reports ErrEmptyUploadPackRequest;
	// the wrapper must not turn that into a nil-pointer panic.
	var nilCaps = &packp.UploadPackRequest{}
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

func TestRouteGitHosts_WrapsHTTPAndHTTPSExactlyOnce(t *testing.T) {
	restoreProtocols(t)
	client.InstallProtocol("http", stockHTTP)
	client.InstallProtocol("https", stockHTTPS)

	routeGitHosts()
	routeGitHosts() // idempotent: a second call must not wrap the router in itself

	for scheme, stock := range map[string]transport.Transport{"http": stockHTTP, "https": stockHTTPS} {
		router, ok := client.Protocols[scheme].(*hostRoutedTransport)
		require.True(t, ok, scheme)
		require.Same(t, stock, router.base, scheme)
	}
}

func TestRouteGitHosts_LeavesOtherSchemesAlone(t *testing.T) {
	restoreProtocols(t)
	ssh, file := client.Protocols["ssh"], client.Protocols["file"]

	routeGitHosts()

	require.Same(t, ssh, client.Protocols["ssh"])
	require.Same(t, file, client.Protocols["file"])
}

// resetGitTransport puts go-git's http(s) transports back to its own and re-arms
// the one-time install, so the test starts like a process that has not cloned
// yet. A test that expects gitClone to install the router would otherwise pass
// whenever an earlier test had already installed it.
func resetGitTransport(t *testing.T) {
	t.Helper()
	restoreProtocols(t)
	client.InstallProtocol("http", stockHTTP)
	client.InstallProtocol("https", stockHTTPS)
	routeGitHostsOnce = sync.Once{}
	t.Cleanup(func() { routeGitHostsOnce = sync.Once{} })
}

func TestInstallGitTransport_RoutesOnceHoweverOftenItIsCalled(t *testing.T) {
	resetGitTransport(t)

	installGitTransport()
	installGitTransport()

	for scheme, stock := range map[string]transport.Transport{"http": stockHTTP, "https": stockHTTPS} {
		router, ok := client.Protocols[scheme].(*hostRoutedTransport)
		require.True(t, ok, scheme)
		require.Same(t, stock, router.base, "%s: one layer over go-git's own transport", scheme)
	}
}

// routeLoopbackAsADO makes the router treat 127.0.0.1 as an Azure DevOps host
// for the duration of the test. "localhost" stays a non-Azure-DevOps host and
// reaches the same loopback listener, which lets one test exercise both
// branches of the router over real HTTP.
func routeLoopbackAsADO(t *testing.T) {
	t.Helper()
	prev := adoHostMatcher
	adoHostMatcher = func(host string) bool { return host == "127.0.0.1" }
	t.Cleanup(func() { adoHostMatcher = prev })
}

func TestClone_AzureDevOpsHostSucceedsThroughRouter(t *testing.T) {
	resetGitTransport(t)
	routeLoopbackAsADO(t)
	srv := newFakeGitServer(t, fakeAzureDevOps, fixtureToken)

	dir, closer, err := gitClone(srv.repoURL("127.0.0.1", "ci:"+fixtureToken))
	require.NoError(t, err)
	defer closer()

	got, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	require.Equal(t, fixtureMainTF, string(got))

	reqs := srv.uploadPackRequests()
	require.Len(t, reqs, 1)
	require.Equal(t, []string{"agent", "multi_ack_detailed", "shallow", "side-band-64k"}, capSet(reqs[0].Caps))
}

func TestClone_OtherHostsKeepGoGitsDefaultRequest(t *testing.T) {
	resetGitTransport(t)
	routeLoopbackAsADO(t) // 127.0.0.1 is "Azure DevOps"; localhost is not
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)
	userinfo := "ci:" + fixtureToken

	// Control: go-git's own transport, no router anywhere.
	_, err := cloneWithStockTransport(t, srv.repoURL("localhost", userinfo))
	require.NoError(t, err)
	// The same clone through gitClone, which installs the router.
	dir, closer, err := gitClone(srv.repoURL("localhost", userinfo))
	require.NoError(t, err)
	defer closer()
	require.FileExists(t, filepath.Join(dir, "main.tf"))

	reqs := srv.uploadPackRequests()
	require.Len(t, reqs, 2)

	// The exact capability list go-git sends today: no multi_ack, no
	// multi_ack_detailed, no thin-pack. "shallow" is there because gitClone
	// clones with Depth 1.
	for i, r := range reqs {
		require.Equal(t, []string{"agent", "ofs-delta", "shallow", "side-band-64k"}, capSet(r.Caps), "request %d", i)
		require.Equal(t, []string{capability.DefaultAgent()}, r.Caps.Get(capability.Agent), "request %d", i)
	}
	// And the request bytes are identical to the control's.
	require.Equal(t, string(reqs[0].Body), string(reqs[1].Body))
}
