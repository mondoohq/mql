// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

// staticToken is an Entra credential that always returns the same token.
type staticToken struct{ token string }

func (s staticToken) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: s.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// sleeper records the waits a client asks for and does not wait.
type sleeper struct {
	mu    sync.Mutex
	waits []time.Duration
	err   error
}

func (s *sleeper) Sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waits = append(s.waits, d)
	return s.err
}

func entraAuth(t *testing.T, token string) *Authenticator {
	t.Helper()
	auth, err := NewAuthenticator(AuthOptions{
		TenantID:        "11111111-2222-3333-4444-555555555555",
		ClientID:        "66666666-7777-8888-9999-000000000000",
		TokenCredential: staticToken{token: token},
	})
	require.NoError(t, err)
	return auth
}

func patAuth(t *testing.T, pat string) *Authenticator {
	t.Helper()
	auth, err := NewAuthenticator(AuthOptions{Credential: vault.NewPasswordCredential("", pat)})
	require.NoError(t, err)
	return auth
}

func newFakeClient(t *testing.T, auth *Authenticator) (*Client, *fakeado.Server, *sleeper) {
	t.Helper()
	srv := fakeado.New(t)
	sl := &sleeper{}
	c, err := NewClient(fakeado.Org, auth, ClientOptions{Endpoint: srv.URL, Sleep: sl.Sleep})
	require.NoError(t, err)
	return c, srv, sl
}

func TestParseOrganization(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "bare name", input: "mondoo-ado-scan-test", want: "mondoo-ado-scan-test"},
		{name: "padded", input: "  mondoo-ado-scan-test \n", want: "mondoo-ado-scan-test"},
		{name: "dev.azure.com url", input: "https://dev.azure.com/mondoo-ado-scan-test", want: "mondoo-ado-scan-test"},
		{name: "dev.azure.com url with a project", input: "https://dev.azure.com/mondoo-ado-scan-test/scan-test/_git/repo", want: "mondoo-ado-scan-test"},
		{name: "legacy visualstudio.com host", input: "https://mondoo-ado-scan-test.visualstudio.com/scan-test", want: "mondoo-ado-scan-test"},
		{name: "legacy host in upper case", input: "https://Mondoo-Ado-Scan-Test.VisualStudio.com", want: "mondoo-ado-scan-test"},
		{name: "dev.azure.com without a scheme", input: "dev.azure.com/mondoo-ado-scan-test", want: "mondoo-ado-scan-test"},
		{name: "dev.azure.com without a scheme, with a trailing slash", input: "dev.azure.com/mondoo-ado-scan-test/", want: "mondoo-ado-scan-test"},
		{name: "dev.azure.com without a scheme, with a project and repository", input: "dev.azure.com/mondoo-ado-scan-test/scan-test/_git/repo", want: "mondoo-ado-scan-test"},
		{name: "dev.azure.com without a scheme in upper case", input: "DEV.AZURE.COM/mondoo-ado-scan-test", want: "mondoo-ado-scan-test"},
		{name: "legacy host without a scheme", input: "mondoo-ado-scan-test.visualstudio.com", want: "mondoo-ado-scan-test"},
		{name: "legacy host without a scheme, with a project and repository", input: "mondoo-ado-scan-test.visualstudio.com/scan-test/_git/repo", want: "mondoo-ado-scan-test"},
		{name: "legacy host without a scheme in upper case", input: "Mondoo-Ado-Scan-Test.VisualStudio.com/scan-test", want: "mondoo-ado-scan-test"},
		{name: "dev.azure.com without a scheme or an organization", input: "dev.azure.com/", wantErr: "not a valid organization name"},
		{name: "dev.azure.com alone", input: "dev.azure.com", wantErr: "not a valid organization name"},
		{name: "another host without a scheme", input: "example.com/mondoo-ado-scan-test", wantErr: "not a valid organization name"},
		{name: "empty", input: "", wantErr: "is empty"},
		{name: "another host", input: "https://example.com/org", wantErr: "not an Azure DevOps Services address"},
		{name: "path only", input: "https://dev.azure.com/", wantErr: "not a valid organization name"},
		{name: "bad characters", input: "org/with/slash", wantErr: "not a valid organization name"},
		{name: "leading dash", input: "-org", wantErr: "not a valid organization name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseOrganization(tc.input)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEndpointMustBeLoopback(t *testing.T) {
	for _, ok := range []string{"", "http://127.0.0.1:8080", "http://localhost:9000", "http://[::1]:7000"} {
		_, err := validateEndpoint(ok)
		assert.NoError(t, err, ok)
	}
	for _, bad := range []string{"https://dev.azure.com", "http://10.0.0.5", "http://evil.example", "ftp://127.0.0.1", "not a url"} {
		_, err := validateEndpoint(bad)
		assert.Error(t, err, bad)
	}
}

// pastedSecret stands in for a personal access token that a user pasted into
// an address as its user information. No error may repeat it.
const pastedSecret = "pastedpatvalue7q"

func TestErrorsLeaveTheUserInformationOfAnAddressOut(t *testing.T) {
	organizations := []string{
		"https://user:" + pastedSecret + "@example.com/org",
		"https://" + pastedSecret + "@example.com/org",
		"https://user:" + pastedSecret + "@dev.azure.com:badport/org",
		"user:" + pastedSecret + "@dev.azure.com",
		pastedSecret + "@dev.azure.com/org",
		// without a scheme, an address with user information is not taken as
		// an address
		"user:" + pastedSecret + "@dev.azure.com/org",
		"user:" + pastedSecret + "@org.visualstudio.com",
		pastedSecret + "@org.visualstudio.com/project",
	}
	for _, input := range organizations {
		_, err := ParseOrganization(input)
		require.Error(t, err, "organization %d", len(input))
		assert.NotContains(t, err.Error(), pastedSecret)
	}

	endpoints := []string{
		"http://user:" + pastedSecret + "@127.0.0.1:8080",
		"http://" + pastedSecret + "@localhost:9000",
		"http://user:" + pastedSecret + "@10.0.0.5",
		"http://user:" + pastedSecret + "@127.0.0.1:badport",
	}
	for _, input := range endpoints {
		_, err := validateEndpoint(input)
		require.Error(t, err, "endpoint %d", len(input))
		assert.NotContains(t, err.Error(), pastedSecret)
	}
}

func TestRedactUserinfo(t *testing.T) {
	cases := map[string]string{
		"https://user:" + pastedSecret + "@dev.azure.com/org/p/_git/r": "https://dev.azure.com/org/p/_git/r",
		"https://" + pastedSecret + "@dev.azure.com/org":               "https://dev.azure.com/org",
		"user:" + pastedSecret + "@dev.azure.com/org":                  "dev.azure.com/org",
		"http://127.0.0.1:8080/x?mail=a@b":                             "http://127.0.0.1:8080/x?mail=a@b",
		"org/project/repo":                                             "org/project/repo",
		"":                                                             "",
	}
	for input, want := range cases {
		assert.Equal(t, want, RedactUserinfo(input))
	}
}

func TestClientNeedsAValidOrganizationAndAnAuthenticator(t *testing.T) {
	_, err := NewClient("bad/org", patAuth(t, "x"), ClientOptions{})
	require.Error(t, err)
	_, err = NewClient("good-org", nil, ClientOptions{})
	require.Error(t, err)
	c, err := NewClient("good-org", patAuth(t, "x"), ClientOptions{})
	require.NoError(t, err)
	assert.Equal(t, "https://dev.azure.com/good-org", c.BaseURL())
}

func TestConnectionDataWithAnEntraBearerToken(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	data, err := c.ConnectionData(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "hosted", data.DeploymentType)
	assert.Equal(t, "5e000000-0000-4000-8000-000000000001", data.InstanceID)
}

func TestConnectionDataWithAPAT(t *testing.T) {
	c, _, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	data, err := c.ConnectionData(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "hosted", data.DeploymentType)
}

func TestSignInPageAnswerIsAnUnauthorizedError(t *testing.T) {
	c, _, sl := newFakeClient(t, patAuth(t, "a-token-the-server-does-not-know"))

	_, err := c.ConnectionData(context.Background())
	require.Error(t, err)
	assert.True(t, IsUnauthorized(err), "got %v", err)
	assert.True(t, IsNoAccess(err))
	assert.Empty(t, sl.waits, "a rejected credential is not retried")
}

func TestProjectsFollowContinuationTokens(t *testing.T) {
	c, srv, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	projects, err := c.Projects(context.Background())
	require.NoError(t, err)

	names := make([]string, 0, len(projects))
	for _, p := range projects {
		names = append(names, p.Name)
	}
	assert.Equal(t, []string{"scan-test", "scan test", "locked-down", "legacy-apps"}, names)

	reqs := srv.Requests()
	require.Len(t, reqs, 2)
	assert.Contains(t, reqs[0], "api-version=7.1")
	assert.NotContains(t, reqs[0], "continuationToken")
	assert.Contains(t, reqs[1], "continuationToken=2")
	assert.Equal(t, 4.0, c.CostUnits(), "two pages at cost 2 each")
}

func TestARepeatedContinuationTokenStopsTheWalk(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("x-ms-continuationtoken", "same-token-forever")
		_, _ = w.Write([]byte(`{"count":1,"value":[{"id":"1a","name":"p"}]}`))
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient("any-org", patAuth(t, "x"), ClientOptions{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = c.Projects(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repeated the continuation token")
	assert.Equal(t, 2, calls, "the first page, then the page that repeats the token")
}

// A server that hands out a new continuation token on every page would keep the
// walk going forever, since no token repeats.
func TestAWalkStopsAtThePageCap(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		w.Header().Set("x-ms-continuationtoken", "token-"+strconv.Itoa(n))
		_, _ = w.Write([]byte(`{"count":1,"value":[{"id":"1a","name":"p"}]}`))
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient("any-org", patAuth(t, "x"), ClientOptions{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = c.Projects(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/_apis/projects")
	assert.Contains(t, err.Error(), "1000 pages")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1000, calls)
}

func TestRepositoriesOfAProjectWithASpace(t *testing.T) {
	c, srv, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	repos, err := c.Repositories(context.Background(), "scan test")
	require.NoError(t, err)
	require.Len(t, repos, 1)
	assert.Equal(t, "ado-scan-test-iac", repos[0].Name)
	assert.Equal(t, "scan test", repos[0].Project.Name)
	assert.Equal(t, "refs/heads/main", repos[0].DefaultBranch)

	reqs := srv.Requests()
	require.Len(t, reqs, 1)
	assert.Contains(t, reqs[0], "/mondoo-ado-scan-test/scan test/_apis/git/repositories?api-version=7.1")
}

func TestCloneURLDropsTheUserInfo(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	repos, err := c.Repositories(context.Background(), "scan test")
	require.NoError(t, err)
	require.Len(t, repos, 1)

	assert.Contains(t, repos[0].RemoteURL, "mondoo-ado-scan-test@dev.azure.com", "the API embeds a user name")
	assert.Equal(t,
		"https://dev.azure.com/mondoo-ado-scan-test/scan%20test/_git/ado-scan-test-iac",
		repos[0].HTTPURL())
	assert.Empty(t, Repository{}.HTTPURL())
}

func TestAProjectThePrincipalCannotReadIsNoAccess(t *testing.T) {
	c, _, sl := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	_, err := c.Repositories(context.Background(), "locked-down")
	require.Error(t, err)
	assert.True(t, IsForbidden(err), "got %v", err)
	assert.True(t, IsNoAccess(err))
	assert.False(t, IsUnauthorized(err))
	assert.Empty(t, sl.waits, "a 403 is not retried")
}

func TestOneRepositoryByNameOrID(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	byName, err := c.Repository(context.Background(), "scan-test", "ado-scan-test-app")
	require.NoError(t, err)
	byID, err := c.Repository(context.Background(), "scan-test", fakeado.RepoAppID)
	require.NoError(t, err)
	assert.Equal(t, byName.ID, byID.ID)

	_, err = c.Repository(context.Background(), "scan-test", "no-such-repo")
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, apiStatus(err))
}

func TestOneProjectByName(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	// a project on the second page, and one with a space in its name
	for _, name := range []string{"legacy-apps", "scan test"} {
		p, err := c.Project(context.Background(), name)
		require.NoError(t, err)
		assert.Equal(t, name, p.Name)
		assert.NotEmpty(t, p.ID)
	}

	_, err := c.Project(context.Background(), "no-such-project")
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, apiStatus(err))
}

// Without its last segment the path of one project or repository is the list
// endpoint, which would answer with a list that decodes into an empty struct.
func TestAnEmptyNameIsRefusedBeforeAnyRequest(t *testing.T) {
	c, srv, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	ctx := context.Background()

	_, err := c.Project(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project name is empty")

	for _, args := range [][2]string{{"scan-test", ""}, {"scan-test", "  "}, {"", "ado-scan-test-app"}} {
		_, err = c.Repository(ctx, args[0], args[1])
		require.Error(t, err, args)
		assert.Contains(t, err.Error(), "name is empty", args)
	}
	assert.Empty(t, srv.Requests())
}

func TestItemsListTheTree(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	items, err := c.Items(context.Background(), "scan-test", fakeado.RepoIacID)
	require.NoError(t, err)

	var blobs []string
	for _, it := range items {
		if it.IsBlob() {
			blobs = append(blobs, it.Path)
		}
	}
	assert.ElementsMatch(t, []string{"/README.md", "/main.tf", "/modules/network/main.tf", "/k8s/pod.yaml", "/secrets/.env"}, blobs)
}

func TestItemsOfAnEmptyRepositoryIsRecognized(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	_, err := c.Items(context.Background(), "scan-test", fakeado.RepoEmptyID)
	require.Error(t, err)
	assert.True(t, IsEmptyRepoError(err), "got %v", err)
	assert.False(t, IsNoAccess(err))
	assert.False(t, IsEmptyRepoError(&APIError{Status: http.StatusNotFound, Message: "TF401019: not found"}))
}

func TestRetryAfterHeaderIsHonored(t *testing.T) {
	c, srv, sl := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	srv.ThrottleNext("/_apis/projects", 2, "7")

	projects, err := c.Projects(context.Background())
	require.NoError(t, err)
	assert.Len(t, projects, 4)
	assert.Equal(t, []time.Duration{7 * time.Second, 7 * time.Second}, sl.waits)
}

func TestBackoffDoublesFromFiveSecondsToASixtySecondCap(t *testing.T) {
	c, srv, sl := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	srv.ThrottleNext("/_apis/projects", 5, "")

	_, err := c.Projects(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []time.Duration{
		5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second,
	}, sl.waits)
}

func TestThrottlingThatNeverEndsGivesUp(t *testing.T) {
	c, srv, sl := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	srv.ThrottleNext("/_apis/projects", 100, "1")

	_, err := c.Projects(context.Background())
	require.Error(t, err)
	assert.Equal(t, http.StatusTooManyRequests, apiStatus(err))
	assert.Len(t, sl.waits, maxRetries)
}

func TestARetryAfterBeyondFiveMinutesFailsAtOnce(t *testing.T) {
	c, srv, sl := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	srv.ThrottleNext("/_apis/projects", 1, "3600")

	_, err := c.Projects(context.Background())
	require.Error(t, err)
	assert.Equal(t, http.StatusTooManyRequests, apiStatus(err))
	assert.Empty(t, sl.waits)
}

func TestCancellingDuringABackoffStopsTheCall(t *testing.T) {
	c, srv, sl := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	sl.err = context.Canceled
	srv.ThrottleNext("/_apis/projects", 1, "")

	_, err := c.Projects(context.Background())
	require.ErrorIs(t, err, context.Canceled)
}

func TestACancelledRequestDoesNotTakeOnTheCauseAsItsAnswer(t *testing.T) {
	// errgroup cancels its context with the error of the request that failed
	// first, and net/http returns that cause from every request the
	// cancellation cuts short. It is another request's answer: retrying it, or
	// classifying it, would treat this request as throttled or denied.
	c, _, sl := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(&APIError{Status: http.StatusTooManyRequests, Path: "/legacy-apps/_apis/git/repositories", RetryAfter: time.Second})

	_, err := c.Repositories(ctx, "scan-test")
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, sl.waits, "a cancelled request is not retried")
	assert.Zero(t, apiStatus(err), "the cause is not this request's answer")
	assert.NotContains(t, err.Error(), "legacy-apps")
}

// dropConnectionServer closes the connection of the first drops requests
// without an answer, which the client sees as a reset connection, and answers
// the rest with the organization identity. It counts every request.
func dropConnectionServer(t *testing.T, drops int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) <= drops {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = w.Write([]byte(`{"instanceId":"5e000000-0000-4000-8000-000000000001","deploymentType":"hosted"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func TestADroppedConnectionIsRetried(t *testing.T) {
	srv, requests := dropConnectionServer(t, 1)
	sl := &sleeper{}
	c, err := NewClient("any-org", patAuth(t, "x"), ClientOptions{Endpoint: srv.URL, Sleep: sl.Sleep})
	require.NoError(t, err)

	data, err := c.ConnectionData(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "hosted", data.DeploymentType)
	assert.Equal(t, int32(2), requests.Load())
	assert.Equal(t, []time.Duration{firstBackoff}, sl.waits)
}

func TestAConnectionThatKeepsDroppingGivesUp(t *testing.T) {
	const pat = "a-token-that-never-gets-an-answer"
	srv, requests := dropConnectionServer(t, 1000)
	sl := &sleeper{}
	c, err := NewClient("any-org", patAuth(t, pat), ClientOptions{Endpoint: srv.URL, Sleep: sl.Sleep})
	require.NoError(t, err)

	_, err = c.ConnectionData(context.Background())
	require.Error(t, err)
	assert.Equal(t, int32(maxRetries+1), requests.Load())
	assert.Equal(t, []time.Duration{
		5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second,
	}, sl.waits, "the same backoff as a 503")
	assert.Contains(t, err.Error(), "/any-org/_apis/connectionData")
	assert.Zero(t, apiStatus(err), "no answer is not an HTTP status")

	basicValue := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	assert.NotContains(t, err.Error(), pat)
	assert.NotContains(t, err.Error(), basicValue)
	assert.NotContains(t, err.Error(), "Basic ")
}

func TestACertificateTheClientDoesNotTrustIsNotRetried(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request gets past the handshake")
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	// The server logs every refused handshake; the test expects one.
	srv.Config.ErrorLog = stdlog.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	sl := &sleeper{}
	c, err := NewClient("any-org", patAuth(t, "x"), ClientOptions{Endpoint: srv.URL, Sleep: sl.Sleep})
	require.NoError(t, err)

	_, err = c.ConnectionData(context.Background())
	require.Error(t, err)
	var verifyErr *tls.CertificateVerificationError
	assert.ErrorAs(t, err, &verifyErr)
	assert.Empty(t, sl.waits, "a certificate that is not trusted fails the same way every time")
	assert.Equal(t, int32(1), conns.Load(), "one handshake")
}

func TestWhichTransportErrorsAreRetried(t *testing.T) {
	get := func(err error) *transportError {
		return &transportError{path: "/org/_apis/connectionData", err: &url.Error{Op: "Get", URL: "https://dev.azure.com/org/_apis/connectionData", Err: err}}
	}
	retried := map[string]error{
		"reset":          syscall.ECONNRESET,
		"refused":        syscall.ECONNREFUSED,
		"eof":            io.EOF,
		"dns":            &net.DNSError{Err: "no such host", Name: "dev.azure.com", IsNotFound: true},
		"client timeout": errors.New("context deadline exceeded (Client.Timeout exceeded while awaiting headers)"),
	}
	for name, err := range retried {
		assert.True(t, get(err).retryable(), name)
	}

	permanent := map[string]error{
		"redirect loop":      errors.New("stopped after 10 redirects"),
		"scheme":             errors.New(`unsupported protocol scheme "ftp"`),
		"header":             errors.New(`net/http: invalid header field value for "Authorization"`),
		"not trusted":        errors.New(`x509: "dev.azure.com" certificate is not trusted`),
		"verification":       &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
		"unknown authority":  x509.UnknownAuthorityError{},
		"hostname":           x509.HostnameError{Host: "dev.azure.com"},
		"invalid":            x509.CertificateInvalidError{Reason: x509.Expired},
		"wrapped hostname":   fmt.Errorf("handshake: %w", x509.HostnameError{Host: "dev.azure.com"}),
		"wrapped authority":  fmt.Errorf("handshake: %w", x509.UnknownAuthorityError{}),
		"wrapped invalidity": fmt.Errorf("handshake: %w", x509.CertificateInvalidError{Reason: x509.Expired}),
	}
	for name, err := range permanent {
		assert.False(t, get(err).retryable(), name)
	}
}

func TestAPIErrorNamesTheStatusAndPath(t *testing.T) {
	err := &APIError{Status: 403, Path: "/scan-test/_apis/git/repositories", Message: "denied"}
	assert.Equal(t, "azure devops: HTTP 403 on /scan-test/_apis/git/repositories: denied", err.Error())
	assert.Equal(t, "azure devops: HTTP 404 on /x: Not Found", (&APIError{Status: 404, Path: "/x"}).Error())
}

func TestErrorsDoNotCarryTheCredential(t *testing.T) {
	const pat = "a-token-the-server-does-not-know"
	c, _, _ := newFakeClient(t, patAuth(t, pat))

	_, err := c.ConnectionData(context.Background())
	require.Error(t, err)

	basicValue := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	assert.NotContains(t, err.Error(), pat)
	assert.NotContains(t, err.Error(), basicValue)
}

// signInRedirectServer answers every request but its sign-in page with a 302
// to that page, as Azure DevOps answers a bad Bearer token. paths lists what
// was requested.
func signInRedirectServer(t *testing.T) (srv *httptest.Server, paths func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/_signin" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>Sign in to continue</body></html>"))
			return
		}
		w.Header().Set("Location", "/_signin")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestARedirectToTheSignInPageIsAnUnauthorizedError(t *testing.T) {
	const pat = "a-token-the-server-does-not-know"

	srv, paths := signInRedirectServer(t)
	sl := &sleeper{}
	c, err := NewClient("any-org", patAuth(t, pat), ClientOptions{Endpoint: srv.URL, Sleep: sl.Sleep})
	require.NoError(t, err)

	_, err = c.ConnectionData(context.Background())
	require.Error(t, err)
	assert.True(t, IsUnauthorized(err), "got %v", err)
	assert.True(t, IsNoAccess(err))
	assert.Empty(t, sl.waits, "a rejected credential is not retried")

	basicValue := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	assert.NotContains(t, err.Error(), pat)
	assert.NotContains(t, err.Error(), basicValue)
	assert.NotContains(t, err.Error(), "_signin", "the Location header stays out of the error")

	assert.Equal(t, []string{"/any-org/_apis/connectionData"}, paths(), "the sign-in page is never requested")
}

// Only the sign-in redirect (302, 303) means a rejected credential. A moved
// API answers 301, 307 or 308, which must keep its own status so the real
// cause shows instead of "check your credential".
func TestOtherRedirectsAreNotUnauthorized(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(code)
			}))
			t.Cleanup(srv.Close)
			c, err := NewClient("any-org", patAuth(t, "a-token"), ClientOptions{Endpoint: srv.URL, Sleep: (&sleeper{}).Sleep})
			require.NoError(t, err)

			_, err = c.ConnectionData(context.Background())
			require.Error(t, err)
			assert.False(t, IsUnauthorized(err), "got %v", err)
			var apiErr *APIError
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, code, apiErr.Status)
			assert.NotContains(t, err.Error(), "/elsewhere", "the Location header stays out of the error")
		})
	}
}

// A client the caller passes in follows redirects by default. The client must
// still read the 302 itself, and must not change the caller's client.
func TestACallersHTTPClientDoesNotFollowTheSignInRedirect(t *testing.T) {
	srv, paths := signInRedirectServer(t)
	own := &http.Client{Timeout: time.Minute}
	c, err := NewClient("any-org", patAuth(t, "a-token-the-server-does-not-know"), ClientOptions{
		Endpoint:   srv.URL,
		HTTPClient: own,
		Sleep:      (&sleeper{}).Sleep,
	})
	require.NoError(t, err)

	_, err = c.ConnectionData(context.Background())
	require.Error(t, err)
	assert.True(t, IsUnauthorized(err), "got %v", err)
	assert.Equal(t, []string{"/any-org/_apis/connectionData"}, paths(), "the sign-in page is never requested")
	assert.Nil(t, own.CheckRedirect, "the caller's client is left as it was")
	assert.Equal(t, time.Minute, own.Timeout)
}
