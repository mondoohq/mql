// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestClassifyIacTree(t *testing.T) {
	blob := func(path string) connection.Item {
		return connection.Item{Path: path, GitObjectType: "blob"}
	}
	tests := []struct {
		name  string
		items []connection.Item
		want  repoIac
	}{
		{"nothing", []connection.Item{blob("/README.md"), blob("/app.py")}, repoIac{}},
		{"terraform at the root", []connection.Item{blob("/main.tf")}, repoIac{hasTerraform: true}},
		{"terraform in a module", []connection.Item{blob("/modules/network/main.tf")}, repoIac{hasTerraform: true}},
		{"a tfvars file is not terraform", []connection.Item{blob("/prod.tfvars")}, repoIac{}},
		{"yaml", []connection.Item{blob("/k8s/pod.yaml")}, repoIac{hasKubernetes: true}},
		{"yml", []connection.Item{blob("/deploy.yml")}, repoIac{hasKubernetes: true}},
		{"a pipeline file counts, the k8s child sorts it out", []connection.Item{blob("/azure-pipelines.yml")}, repoIac{hasKubernetes: true}},
		{"mql.yaml is a policy file", []connection.Item{blob("/mql.yaml"), blob("/sub/mql.yml")}, repoIac{}},
		{"a name that only ends in mql.yaml is a manifest", []connection.Item{blob("/xmql.yaml")}, repoIac{hasKubernetes: true}},
		{"hidden directory", []connection.Item{blob("/.azure/ci.yml"), blob("/.github/workflows/ci.yml")}, repoIac{}},
		{"hidden terraform", []connection.Item{blob("/.terraform/main.tf")}, repoIac{}},
		{"a hidden file", []connection.Item{blob("/.drone.yml")}, repoIac{}},
		{"a folder named like a file is not a blob", []connection.Item{{Path: "/infra.tf", GitObjectType: "tree", IsFolder: true}}, repoIac{}},
		{"both", []connection.Item{blob("/main.tf"), blob("/k8s/pod.yaml")}, repoIac{hasTerraform: true, hasKubernetes: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, classifyIacTree(tc.items))
		})
	}
}

// reposNamed returns the listed repositories with the given full names, in the
// order of fullNames, so a test can hand walkIac an order the organization
// does not list them in.
func reposNamed(t *testing.T, listing *connection.Listing, fullNames ...string) []connection.ListedRepo {
	t.Helper()
	var out []connection.ListedRepo
	for _, name := range fullNames {
		for _, r := range listing.Repos() {
			if r.FullName() == name {
				out = append(out, r)
			}
		}
	}
	require.Len(t, out, len(fullNames))
	return out
}

func TestWalkIacClassifiesEachRepositoryInOrder(t *testing.T) {
	conn := connectionOf(newRuntime(t, nil))
	listing, err := conn.Listing(apiContext())
	require.NoError(t, err)
	// Not the listing order: the results follow the order walkIac was given.
	repos := reposNamed(t, listing, "legacy-apps/ado-scan-test-docs", "scan-test/ado-scan-test-iac", "scan-test/ado-scan-test-app")

	got := walkIac(apiContext(), conn.Client(), repos)

	require.Len(t, got, 3)
	for _, r := range got {
		assert.NoError(t, r.err)
	}
	assert.Equal(t, repoIac{}, got[0].iac)
	assert.Equal(t, repoIac{hasTerraform: true, hasKubernetes: true}, got[1].iac)
	assert.Equal(t, repoIac{hasKubernetes: true}, got[2].iac)
}

func TestWalkIacRecordsAFailureOnThatRepositoryOnly(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.DenyItems(fakeado.RepoIacID)
	conn := connectionOf(runtime)
	listing, err := conn.Listing(apiContext())
	require.NoError(t, err)
	repos := reposNamed(t, listing, "scan-test/ado-scan-test-iac", "scan-test/ado-scan-test-app")

	got := walkIac(apiContext(), conn.Client(), repos)

	require.Len(t, got, 2)
	var apiErr *connection.APIError
	require.ErrorAs(t, got[0].err, &apiErr, "the denied repository carries its error")
	assert.Equal(t, http.StatusForbidden, apiErr.Status)
	assert.Equal(t, repoIac{}, got[0].iac, "a denied tree reports no IaC")
	assert.NoError(t, got[1].err, "the other repository is read")
	assert.Equal(t, repoIac{hasKubernetes: true}, got[1].iac)
}

func TestWalkIacOfNoRepositoriesReadsNothing(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	conn := connectionOf(runtime)
	before := len(srv.Requests())

	got := walkIac(apiContext(), conn.Client(), nil)

	assert.Empty(t, got)
	assert.Len(t, srv.Requests(), before, "no tree is read")
}

// A throttled tree read waits out the server's Retry-After and then asks again.
// The walk budget of one repository has to cover both requests and the wait,
// or the repository loses its IaC children whenever the organization is
// throttled.
func TestTheWalkBudgetOutlastsAThrottledRequestAndItsRetry(t *testing.T) {
	assert.Greater(t, iacWalkTimeout, connection.MaxRetryAfter+connection.RequestTimeout)
	assert.GreaterOrEqual(t, iacWalkTimeout, connection.MaxRetryAfter+2*connection.RequestTimeout)
}

func TestWalkIacCancelledRecordsTheCancelOnEveryRepository(t *testing.T) {
	conn := connectionOf(newRuntime(t, nil))
	listing, err := conn.Listing(apiContext())
	require.NoError(t, err)
	repos := reposNamed(t, listing, "scan-test/ado-scan-test-iac", "scan-test/ado-scan-test-app")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := walkIac(ctx, conn.Client(), repos)

	require.Len(t, got, 2)
	for i, r := range got {
		assert.True(t, errors.Is(r.err, context.Canceled), "repository %d: %v", i, r.err)
		assert.Equal(t, repoIac{}, r.iac, "repository %d reports no IaC", i)
	}
}

func TestWalkIacReadsAtMostFourTreesAtOnce(t *testing.T) {
	var (
		mu       sync.Mutex
		inFlight int
		most     int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	t.Cleanup(srv.Close)

	auth, err := connection.NewAuthenticator(connection.AuthOptions{Credential: vault.NewPasswordCredential("", "any-token")})
	require.NoError(t, err)
	client, err := connection.NewClient("any-org", auth, connection.ClientOptions{Endpoint: srv.URL})
	require.NoError(t, err)

	var repos []connection.ListedRepo
	for i := range 10 {
		repos = append(repos, connection.ListedRepo{
			Project: connection.Project{Name: "p"},
			Repo:    connection.Repository{ID: fmt.Sprintf("2b000000-0000-4000-8000-%012d", 100+i)},
		})
	}

	got := walkIac(context.Background(), client, repos)
	require.Len(t, got, 10)
	for _, r := range got {
		require.NoError(t, r.err)
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 4, most, "the walk reads four trees at once, no more and no fewer")
}
