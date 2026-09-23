// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v92/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestAgentSecretIDCarriesItsStore(t *testing.T) {
	// The same secret name in two repositories, and in a repository and its
	// organization, must not share a cache key.
	repoA := agentSecretID(scopeRepository, "acme", "alpha", "REGISTRY_TOKEN")
	repoB := agentSecretID(scopeRepository, "acme", "beta", "REGISTRY_TOKEN")
	org := agentSecretID(scopeOrganization, "acme", "", "REGISTRY_TOKEN")

	assert.NotEqual(t, repoA, repoB)
	assert.NotEqual(t, repoA, org)
	assert.Equal(t, repoA, agentSecretID(scopeRepository, "acme", "alpha", "REGISTRY_TOKEN"))
	// An agent secret and a Dependabot secret of the same name are different
	// secrets in different stores.
	assert.NotEqual(t, org, dependabotSecretID(scopeOrganization, "acme", "", "REGISTRY_TOKEN"))
}

// agentSecretsServer answers the organization agent secrets listing with the
// given status, or with two pages of secrets when status is 200.
func agentSecretsServer(t *testing.T, status int, paths *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*paths = append(*paths, r.URL.Path+"?page="+r.URL.Query().Get("page"))
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"message": "refused"}`)
			return
		}
		switch r.URL.Query().Get("page") {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/v3/orgs/o/agents/secrets?per_page=100&page=2>; rel="next"`, serverURL(r)))
			fmt.Fprint(w, `{"total_count": 3, "secrets": [
				{"name": "A", "created_at": "2026-01-02T03:04:05Z", "updated_at": "2026-01-02T03:04:05Z", "visibility": "all"},
				{"name": "B", "visibility": "selected", "selected_repositories_url": "https://api.github.com/orgs/o/agents/secrets/B/repositories"}
			]}`)
		case "2":
			fmt.Fprint(w, `{"total_count": 3, "secrets": [{"name": "C", "visibility": "private"}]}`)
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	}))
}

func listOrgAgentSecrets(client *github.Client) ([]*github.Secret, error) {
	return collectPages(func(opts *github.ListOptions) ([]*github.Secret, *github.Response, error) {
		page, resp, err := client.Agents.ListOrgSecrets(context.Background(), "o", opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Secrets, resp, nil
	})
}

// Reading only the first page reports an organization that shares a secret
// with the agent as sharing fewer than it does.
func TestAgentSecretsWalkEveryPage(t *testing.T) {
	var paths []string
	server := agentSecretsServer(t, http.StatusOK, &paths)
	defer server.Close()

	secrets, err := listOrgAgentSecrets(newTestGithubClient(t, server))
	require.NoError(t, err)

	require.Len(t, secrets, 3, "every page must be collected, not just the first")
	assert.Equal(t, []string{"/api/v3/orgs/o/agents/secrets?page=", "/api/v3/orgs/o/agents/secrets?page=2"}, paths)
	assert.Equal(t, "selected", secrets[1].Visibility)
	assert.Nil(t, githubTimeValue(secrets[1].CreatedAt), "an omitted timestamp must not become year 1")
	require.NotNil(t, githubTimeValue(secrets[0].CreatedAt))
	assert.Equal(t, 2026, githubTimeValue(secrets[0].CreatedAt).Year())
}

func TestClassifyAgentSecretsError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		wantAbsent bool
		wantKind   llx.ErrorKind
		wantErr    bool
	}{
		{name: "refusal is access denied, not an empty store", status: http.StatusForbidden, wantKind: llx.ErrorKind_ERROR_KIND_FORBIDDEN, wantErr: true},
		{name: "store not available reads as absent", status: http.StatusNotFound, wantAbsent: true},
		{name: "conflict reads as absent", status: http.StatusConflict, wantAbsent: true},
		{name: "server error stays unclassified", status: http.StatusInternalServerError, wantKind: llx.ErrorKind_ERROR_KIND_UNSPECIFIED, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			server := agentSecretsServer(t, tc.status, &paths)
			defer server.Close()

			_, listErr := listOrgAgentSecrets(newTestGithubClient(t, server))
			require.Error(t, listErr)

			absent, err := classifyAgentSecretsError(listErr)
			assert.Equal(t, tc.wantAbsent, absent)
			if !tc.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.wantKind, llx.KindOf(err))
			var ghErr *github.ErrorResponse
			assert.True(t, errors.As(err, &ghErr), "the SDK error must stay reachable")
		})
	}
}
