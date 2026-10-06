// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestEnumerateListsEveryProject(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err)

	// The server pages the projects, so all four prove the walk followed the
	// continuation token.
	var names []string
	for _, p := range listing.Projects {
		names = append(names, p.Project.Name)
	}
	assert.Equal(t, []string{"scan-test", "scan test", "locked-down", "legacy-apps"}, names)
}

func TestEnumerateKeepsAnUnreadableProjectWithoutFailing(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err, "one project the principal cannot read must not fail the organization")

	assert.Equal(t, []string{"locked-down"}, listing.Unreadable())
	for _, p := range listing.Projects {
		if p.Project.Name == "locked-down" {
			assert.Empty(t, p.Repos)
			assert.True(t, IsNoAccess(p.NoAccess), "the project records the answer Azure DevOps gave")
			continue
		}
		assert.NoError(t, p.NoAccess, p.Project.Name)
	}
	// The readable projects still produce repositories.
	assert.Len(t, listing.Repos(), 6)
}

func TestEnumerateFailsOnOtherErrors(t *testing.T) {
	// A bad token is not "a project the principal cannot read": it fails the
	// call on the first request, so a typo in a secret is not read as an empty
	// organization.
	c, _, _ := newFakeClient(t, entraAuth(t, "a-token-the-server-refuses"))

	_, err := c.Enumerate(context.Background())
	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}

func TestRepositoryStatus(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err)

	got := map[string]RepoStatus{}
	for _, r := range listing.Repos() {
		got[r.Repo.ID] = r.Repo.Status()
	}
	assert.Equal(t, RepoReady, got[fakeado.RepoIacID])
	assert.Equal(t, RepoReady, got[fakeado.RepoAppID])
	assert.Equal(t, RepoEmpty, got[fakeado.RepoEmptyID], "no default branch means no commits")
	assert.Equal(t, RepoDisabled, got[fakeado.RepoRetiredID])
	assert.Equal(t, RepoReady, got[fakeado.RepoDocsID])
}

func TestStatusDisabledWinsOverEmpty(t *testing.T) {
	assert.Equal(t, RepoDisabled, Repository{IsDisabled: true}.Status())
	assert.Equal(t, RepoEmpty, Repository{}.Status())
	assert.Equal(t, RepoReady, Repository{DefaultBranch: "refs/heads/main"}.Status())
}

func TestListingKeepsRepositoriesWithTheSameNameApart(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err)

	var same []ListedRepo
	for _, r := range listing.Repos() {
		if r.Repo.Name == "ado-scan-test-iac" {
			same = append(same, r)
		}
	}
	require.Len(t, same, 2, "the name is repeated in two projects")
	assert.NotEqual(t, same[0].Repo.ID, same[1].Repo.ID)
	assert.NotEqual(t, same[0].FullName(), same[1].FullName())

	// The platform ids differ too, which is what keeps the two assets apart.
	idA := NewRepoIdentifier(fakeado.Org, same[0].Project.Name, same[0].Repo.Name)
	idB := NewRepoIdentifier(fakeado.Org, same[1].Project.Name, same[1].Repo.Name)
	assert.NotEqual(t, idA, idB)
}

func TestFullName(t *testing.T) {
	l := ListedRepo{Project: Project{Name: "scan test"}, Repo: Repository{Name: "ado-scan-test-iac"}}
	assert.Equal(t, "scan test/ado-scan-test-iac", l.FullName())
}

func TestEnumerateKeepsAProjectThatAnswers404(t *testing.T) {
	// Azure DevOps often answers 404 (TF401019), not 403, for the repository
	// list of a project the principal cannot see. It is the same case as
	// locked-down, so it is reported and skipped, not an organization failure.
	c, srv, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	srv.HideRepositories("legacy-apps")

	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err, "a project that answers 404 must not fail the organization")

	assert.Equal(t, []string{"locked-down", "legacy-apps"}, listing.Unreadable())
	for _, p := range listing.Projects {
		if p.Project.Name != "legacy-apps" {
			continue
		}
		assert.Empty(t, p.Repos)
		assert.True(t, IsNotFound(p.NoAccess), "the project records the 404 Azure DevOps gave")
		assert.False(t, IsNoAccess(p.NoAccess), "a 404 stays outside IsNoAccess, which is 401 and 403 only")
	}
	// The other readable projects still produce their repositories: the six of
	// the fake organization less the one legacy-apps holds.
	assert.Len(t, listing.Repos(), 5)
}

// overrideRepoList serves the fake organization, except that the repository
// list of legacy-apps gets the given answer.
func overrideRepoList(t *testing.T, answer http.HandlerFunc) (*Client, *sleeper) {
	t.Helper()
	srv := fakeado.New(t)
	target, err := url.Parse(srv.URL)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(target)

	listPath := "/" + fakeado.Org + "/legacy-apps/_apis/git/repositories"
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == listPath {
			answer(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)

	sl := &sleeper{}
	c, err := NewClient(fakeado.Org, entraAuth(t, fakeado.BearerToken), ClientOptions{Endpoint: front.URL, Sleep: sl.Sleep})
	require.NoError(t, err)
	return c, sl
}

func TestEnumerateRepositoryListAnswers(t *testing.T) {
	cases := []struct {
		name   string
		answer http.HandlerFunc
		// failStatus is the status Enumerate fails with, or 0 when the project
		// is reported as unreadable instead.
		failStatus int
		waits      int
	}{
		{
			name:   "401",
			answer: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
		},
		{
			name: "203 sign-in page",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusNonAuthoritativeInfo)
				_, _ = io.WriteString(w, "<html><title>Sign in</title></html>")
			},
		},
		{
			name: "302 to the sign-in page",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "/_signin?realm=dev.azure.com")
				w.WriteHeader(http.StatusFound)
			},
		},
		{
			name: "429 that never ends",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
			},
			failStatus: http.StatusTooManyRequests,
			waits:      maxRetries,
		},
		{
			name: "500",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, `{"message":"internal error"}`)
			},
			failStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, sl := overrideRepoList(t, tc.answer)

			listing, err := c.Enumerate(context.Background())

			sl.mu.Lock()
			waits := append([]time.Duration(nil), sl.waits...)
			sl.mu.Unlock()
			require.Len(t, waits, tc.waits)
			for _, w := range waits {
				assert.Equal(t, time.Second, w, "the Retry-After is honored")
			}

			if tc.failStatus != 0 {
				require.Error(t, err)
				assert.Nil(t, listing, "a failed walk returns no partial listing")
				assert.Equal(t, tc.failStatus, apiStatus(err))
				return
			}
			require.NoError(t, err, "a rejected repository list marks the project unreadable")
			assert.Equal(t, []string{"locked-down", "legacy-apps"}, listing.Unreadable())
			for _, p := range listing.Projects {
				if p.Project.Name == "legacy-apps" {
					assert.True(t, IsUnauthorized(p.NoAccess), "the project records the rejection as a 401")
				}
			}
			assert.Len(t, listing.Repos(), 5)
		})
	}
}

// projectsServer answers a project list of n projects named p0, p1, ... and
// hands every repository list to repos.
func projectsServer(t *testing.T, n int, repos http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/_apis/projects"):
			var b strings.Builder
			fmt.Fprintf(&b, `{"count":%d,"value":[`, n)
			for i := range n {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"id":"00000000-0000-4000-8000-%012d","name":"p%d"}`, i, i)
			}
			b.WriteString("]}")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, b.String())
		case strings.HasSuffix(r.URL.Path, "/_apis/git/repositories"):
			repos(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnumerateListsAtMostFourProjectsAtOnce(t *testing.T) {
	var (
		mu       sync.Mutex
		inFlight int
		most     int
	)
	srv := projectsServer(t, 10, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inFlight++
		most = max(most, inFlight)
		mu.Unlock()
		// Holding each answer long enough for every request the walk is
		// willing to run to arrive shows its limit.
		select {
		case <-time.After(150 * time.Millisecond):
		case <-r.Context().Done():
		}
		mu.Lock()
		inFlight--
		mu.Unlock()
		_, _ = io.WriteString(w, `{"count":0,"value":[]}`)
	})

	c, err := NewClient("any-org", entraAuth(t, "any-token"), ClientOptions{Endpoint: srv.URL, Sleep: (&sleeper{}).Sleep})
	require.NoError(t, err)

	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err)
	assert.Len(t, listing.Projects, 10)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 4, most, "the walk lists four projects at once, no more and no fewer")
}

func TestEnumerateCancelledReturnsNoPartialListing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu      sync.Mutex
		waiting int
	)
	srv := projectsServer(t, 4, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/p0/") {
			_, _ = io.WriteString(w, `{"count":0,"value":[]}`)
			return
		}
		// The other three wait, and the last of them to arrive cancels the walk.
		mu.Lock()
		waiting++
		if waiting == 3 {
			cancel()
		}
		mu.Unlock()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})

	c, err := NewClient("any-org", entraAuth(t, "any-token"), ClientOptions{Endpoint: srv.URL, Sleep: (&sleeper{}).Sleep})
	require.NoError(t, err)

	listing, err := c.Enumerate(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "got %v", err)
	assert.Nil(t, listing, "a cancelled walk returns no partial listing")
}
