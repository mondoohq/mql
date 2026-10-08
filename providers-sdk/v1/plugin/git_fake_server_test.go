// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/server"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/stretchr/testify/require"
)

// Fabricated fixture identity, in the style of Microsoft's "Fabrikam" sample
// names. Nothing here talks to a real Azure DevOps organization.
const (
	fixtureOrg     = "fabrikam-fixture-org"
	fixtureProject = "scan-test"
	fixtureRepo    = "ado-scan-test-iac"
	fixtureToken   = "fixture-pat-not-a-secret"
	fixtureMainTF  = "resource \"terraform_data\" \"example\" {}\n"
)

// fixtureRepoPath is the path of an Azure DevOps style repo URL.
func fixtureRepoPath() string {
	return "/" + fixtureOrg + "/" + fixtureProject + "/_git/" + fixtureRepo
}

// fakeGitMode picks which real-world server the fake imitates.
type fakeGitMode int

const (
	// fakeStandard imitates GitHub/GitLab: it serves whatever go-git asks for.
	fakeStandard fakeGitMode = iota
	// fakeAzureDevOps imitates Azure DevOps: an upload-pack request that does
	// not carry multi_ack_detailed is answered with HTTP 400. That is what
	// dev.azure.com and the legacy *.visualstudio.com hosts do with go-git's
	// default request. The fake also rejects thin-pack, a deliberately strict
	// extra rule: go-git never sends thin-pack by default, so no test depends
	// on it, and it has not been observed on the real service.
	fakeAzureDevOps
)

// recordedUploadPack is one upload-pack POST the fake received.
type recordedUploadPack struct {
	Body   []byte
	Caps   *capability.List
	Header http.Header
}

// fakeGitServer is an in-process smart-HTTP git server around one in-memory
// repository. The pack generation is go-git's own server package; this type
// adds the HTTP framing, side-band-64k multiplexing, Basic auth and the
// per-mode request rules.
type fakeGitServer struct {
	*httptest.Server
	mode    fakeGitMode
	token   string // when set, Basic auth must carry it as password or username
	storage *memory.Storage

	mu       sync.Mutex
	requests []recordedUploadPack
	adverts  []http.Header // headers of each info/refs GET, in arrival order
}

// newFakeGitServer starts a server serving a repository with one root commit
// holding main.tf. A non-empty token makes the server require it.
func newFakeGitServer(t *testing.T, mode fakeGitMode, token string) *fakeGitServer {
	t.Helper()
	f := &fakeGitServer{mode: mode, token: token, storage: newFixtureStorage(t)}
	f.Server = httptest.NewServer(f)
	t.Cleanup(f.Close)
	return f
}

// newEmptyFakeGitServer starts a server whose repository has no refs.
func newEmptyFakeGitServer(t *testing.T, mode fakeGitMode, token string) *fakeGitServer {
	t.Helper()
	f := &fakeGitServer{mode: mode, token: token, storage: memory.NewStorage()}
	f.Server = httptest.NewServer(f)
	t.Cleanup(f.Close)
	return f
}

// newFixtureStorage builds a repository with one root commit on refs/heads/main
// that contains a single file, main.tf.
func newFixtureStorage(t *testing.T) *memory.Storage {
	t.Helper()
	st := memory.NewStorage()

	blob := st.NewEncodedObject()
	blob.SetType(plumbing.BlobObject)
	bw, err := blob.Writer()
	require.NoError(t, err)
	_, err = bw.Write([]byte(fixtureMainTF))
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	blobHash, err := st.SetEncodedObject(blob)
	require.NoError(t, err)

	tree := &object.Tree{Entries: []object.TreeEntry{
		{Name: "main.tf", Mode: filemode.Regular, Hash: blobHash},
	}}
	treeObj := st.NewEncodedObject()
	require.NoError(t, tree.Encode(treeObj))
	treeHash, err := st.SetEncodedObject(treeObj)
	require.NoError(t, err)

	sig := object.Signature{
		Name:  "Fixture Author",
		Email: "fixture@example.invalid",
		When:  time.Unix(1700000000, 0).UTC(),
	}
	commit := &object.Commit{Author: sig, Committer: sig, Message: "fixture\n", TreeHash: treeHash}
	commitObj := st.NewEncodedObject()
	require.NoError(t, commit.Encode(commitObj))
	commitHash, err := st.SetEncodedObject(commitObj)
	require.NoError(t, err)

	require.NoError(t, st.SetReference(plumbing.NewHashReference("refs/heads/main", commitHash)))
	require.NoError(t, st.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, "refs/heads/main")))
	return st
}

// repoURL returns a clone URL for the fixture repo on this server, with the
// given userinfo ("" for none), using host in place of the listener address.
func (f *fakeGitServer) repoURL(host, userinfo string) string {
	port := f.Listener.Addr().String()
	port = port[strings.LastIndex(port, ":")+1:]
	auth := ""
	if userinfo != "" {
		auth = userinfo + "@"
	}
	return "http://" + auth + host + ":" + port + fixtureRepoPath()
}

// uploadPackRequests returns a snapshot of the recorded upload-pack POSTs.
func (f *fakeGitServer) uploadPackRequests() []recordedUploadPack {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedUploadPack(nil), f.requests...)
}

// advertisementHeaders returns a snapshot of the headers of the recorded
// info/refs GETs (the request that precedes every upload-pack POST).
func (f *fakeGitServer) advertisementHeaders() []http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]http.Header(nil), f.adverts...)
}

func (f *fakeGitServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.token != "" {
		user, pass, ok := r.BasicAuth()
		if !ok || (pass != f.token && user != f.token) {
			w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/info/refs") &&
		r.URL.Query().Get("service") == transport.UploadPackServiceName:
		f.serveAdvertisement(w, r)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/"+transport.UploadPackServiceName):
		f.serveUploadPack(w, r)
	default:
		http.NotFound(w, r)
	}
}

// newPrimedSession opens a go-git server session and advertises references
// through it. The session keeps a pointer to the advertised capability list and
// validates the request against it, so the list is adjusted in place before
// either the advertisement is sent or the request is served.
func (f *fakeGitServer) newPrimedSession(ctx context.Context) (transport.UploadPackSession, *packp.AdvRefs, error) {
	sess, err := server.NewServer(staticLoader{f.storage}).NewUploadPackSession(&transport.Endpoint{}, nil)
	if err != nil {
		return nil, nil, err
	}
	adv, err := sess.AdvertisedReferencesContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := f.setAdvertisedCapabilities(adv.Capabilities); err != nil {
		return nil, nil, err
	}
	return sess, adv, nil
}

// setAdvertisedCapabilities mirrors the advertisement recorded from the real
// Azure DevOps service: multi_ack, thin-pack, side-band, side-band-64k,
// no-progress, multi_ack_detailed, no-done, shallow, allow-tip-sha1-in-want and
// filter. A standard server additionally offers ofs-delta.
func (f *fakeGitServer) setAdvertisedCapabilities(caps *capability.List) error {
	for _, c := range []capability.Capability{
		capability.MultiACK, capability.MultiACKDetailed, capability.ThinPack,
		capability.Sideband, capability.Sideband64k, capability.NoProgress,
		capability.NoDone, capability.Shallow, capability.AllowTipSHA1InWant,
		capability.Filter,
	} {
		if err := caps.Set(c); err != nil {
			return err
		}
	}
	if f.mode == fakeAzureDevOps {
		caps.Delete(capability.OFSDelta)
	}
	return nil
}

func (f *fakeGitServer) serveAdvertisement(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.adverts = append(f.adverts, r.Header.Clone())
	f.mu.Unlock()

	sess, adv, err := f.newPrimedSession(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sess.Close()

	adv.Prefix = [][]byte{[]byte("# service=" + transport.UploadPackServiceName), pktline.Flush}
	w.Header().Set("Content-Type", "application/x-"+transport.UploadPackServiceName+"-advertisement")
	if err := adv.Encode(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (f *fakeGitServer) serveUploadPack(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req := packp.NewUploadPackRequest()
	if err := req.Decode(bytes.NewReader(body)); err != nil {
		http.Error(w, "unparseable upload-pack request: "+err.Error(), http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.requests = append(f.requests, recordedUploadPack{Body: body, Caps: req.Capabilities, Header: r.Header.Clone()})
	f.mu.Unlock()

	if f.mode == fakeAzureDevOps {
		if !req.Capabilities.Supports(capability.MultiACKDetailed) {
			http.Error(w, "fake azure devops: multi_ack_detailed is required", http.StatusBadRequest)
			return
		}
		if req.Capabilities.Supports(capability.ThinPack) {
			http.Error(w, "fake azure devops: thin-pack is not accepted", http.StatusBadRequest)
			return
		}
	}

	sess, _, err := f.newPrimedSession(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sess.Close()

	resp, err := sess.UploadPack(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Close()

	w.Header().Set("Content-Type", "application/x-"+transport.UploadPackServiceName+"-result")
	if !req.Depth.IsZero() {
		if err := resp.ShallowUpdate.Encode(w); err != nil {
			return
		}
	}
	if err := resp.ServerResponse.Encode(w, true); err != nil {
		return
	}
	mux := sideband.NewMuxer(sideband.Sideband64k, w)
	if _, err := io.Copy(mux, resp); err != nil {
		return
	}
	_ = pktline.NewEncoder(w).Flush()
}

// staticLoader serves one storer for every endpoint.
type staticLoader struct{ st storer.Storer }

func (l staticLoader) Load(*transport.Endpoint) (storer.Storer, error) { return l.st, nil }

// go-git's stock http(s) transports, captured at test-binary init, before
// anything in this package can have routed them.
var (
	stockHTTP  = client.Protocols["http"]
	stockHTTPS = client.Protocols["https"]
)

// cloneWithStockTransport clones the way gitClone does, but with go-git's
// untouched http transport installed. It is the control the wrapper is compared
// against, so its CloneOptions must mirror gitClone's: go-git sends
// "no-progress" only when Progress is nil, and gitClone passes os.Stderr.
func cloneWithStockTransport(t *testing.T, url string) (string, error) {
	t.Helper()
	routed := client.Protocols["http"]
	client.InstallProtocol("http", stockHTTP)
	defer client.InstallProtocol("http", routed)

	dir := t.TempDir()
	_, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL:               url,
		Progress:          os.Stderr,
		Depth:             1,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
	})
	return dir, err
}

// capSet renders a capability list as sorted names, ignoring values.
func capSet(caps *capability.List) []string {
	var names []string
	for _, c := range caps.All() {
		names = append(names, string(c))
	}
	sort.Strings(names)
	return names
}

func TestFakeGitServer_StandardModeServesTheFixtureToGoGitsDefaultRequest(t *testing.T) {
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)

	dir, err := cloneWithStockTransport(t, srv.repoURL("localhost", "ci:"+fixtureToken))

	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	require.Equal(t, fixtureMainTF, string(got))
	reqs := srv.uploadPackRequests()
	require.Len(t, reqs, 1)
	require.Equal(t, []string{"agent", "ofs-delta", "shallow", "side-band-64k"}, capSet(reqs[0].Caps))
}

func TestFakeGitServer_AnswersMissingAndWrongCredentialsWithAuthenticationRequired(t *testing.T) {
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)
	for name, userinfo := range map[string]string{"no credentials": "", "wrong token": "ci:not-the-token"} {
		t.Run(name, func(t *testing.T) {
			_, err := cloneWithStockTransport(t, srv.repoURL("localhost", userinfo))

			require.ErrorIs(t, err, transport.ErrAuthenticationRequired)
			require.Empty(t, srv.uploadPackRequests(), "nothing is served before authentication")
		})
	}
}

// Azure DevOps answers go-git's default upload-pack request with HTTP 400,
// because it lacks multi_ack_detailed. This is the failure the server option
// fixes.
func TestFakeGitServer_AzureDevOpsModeRejectsGoGitsDefaultRequest(t *testing.T) {
	srv := newFakeGitServer(t, fakeAzureDevOps, fixtureToken)

	_, err := cloneWithStockTransport(t, srv.repoURL("127.0.0.1", "ci:"+fixtureToken))

	require.Error(t, err)
	require.ErrorContains(t, err, "status code: 400")
	reqs := srv.uploadPackRequests()
	require.Len(t, reqs, 1)
	require.Equal(t, []string{"agent", "shallow", "side-band-64k"}, capSet(reqs[0].Caps),
		"go-git's default request carries no multi_ack_detailed")
}
