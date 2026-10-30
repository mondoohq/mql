// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

// webhooksOf maps the service hooks of a repository by id.
func webhooksOf(t *testing.T, repo *mqlAzuredevopsRepository) map[string]*mqlAzuredevopsWebhook {
	t.Helper()
	list := repo.GetWebhooks()
	require.NoError(t, list.Error)
	require.False(t, list.IsNull())
	out := map[string]*mqlAzuredevopsWebhook{}
	for _, x := range list.Data {
		h := x.(*mqlAzuredevopsWebhook)
		out[h.Id.Data] = h
	}
	return out
}

func TestTheWeakRepositorySendsPushesOverPlainHTTP(t *testing.T) {
	repo := repositoriesOf(t, newOrganization(t, newRuntime(t, nil)))[fakeado.RepoIacID]
	hooks := webhooksOf(t, repo)

	require.ElementsMatch(t, []string{
		"7a000000-0000-4000-8000-000000000001",
		"7a000000-0000-4000-8000-000000000003",
		"7a000000-0000-4000-8000-000000000007",
	}, hookIDs(hooks), "work item hooks, hooks of another project, and hooks with no address are left out")

	push := hooks["7a000000-0000-4000-8000-000000000001"]
	assert.Equal(t, "git.push", push.EventType.Data)
	assert.Equal(t, "webHooks", push.ConsumerId.Data)
	assert.True(t, push.Active.Data)
	assert.Equal(t, "http", push.Scheme.Data)
	assert.Equal(t, "ci.example.invalid", push.Host.Data)
	assert.False(t, push.IsHttps.Data)

	old := hooks["7a000000-0000-4000-8000-000000000007"]
	assert.False(t, old.Active.Data)
	assert.Equal(t, "old.example.invalid:8443", old.Host.Data, "no user information")
	assert.True(t, old.IsHttps.Data)
}

func TestTheStrongRepositorySendsEveryEventOverHTTPS(t *testing.T) {
	repo := repositoriesOf(t, newOrganization(t, newRuntime(t, nil)))[fakeado.RepoAppID]
	hooks := webhooksOf(t, repo)

	require.ElementsMatch(t, []string{
		"7a000000-0000-4000-8000-000000000002",
		"7a000000-0000-4000-8000-000000000003",
	}, hookIDs(hooks), "the repository id is matched without regard to letter case")
	for id, h := range hooks {
		assert.True(t, h.IsHttps.Data, id)
	}
}

func TestARepositoryOfAProjectWithNoHooksHasAnEmptyList(t *testing.T) {
	repo := repositoriesOf(t, newOrganization(t, newRuntime(t, nil)))[fakeado.RepoIacSpace]
	assert.Empty(t, webhooksOf(t, repo))
}

func TestServiceHooksTheCredentialCannotReadAreForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.Deny("/_apis/hooks/subscriptions")
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID]

	list := repo.GetWebhooks()
	assert.ErrorIs(t, list.Error, llx.ErrForbidden)
}

// A Reader is the common case and gets no 403: Azure DevOps answers the
// subscription list with 200 and nothing. Only the permission check tells that
// apart from a project with no hooks, so the field must be forbidden, never [].
func TestServiceHooksAReaderCannotViewAreForbiddenNotEmpty(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.HideServiceHooks()
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID]

	list := repo.GetWebhooks()
	require.Error(t, list.Error, "an invisible hook list must not read as no hooks")
	assert.ErrorIs(t, list.Error, llx.ErrForbidden)
	assert.Contains(t, list.Error.Error(), "View subscriptions")
	// The portal has no page for this permission; the hint must be the CLI call.
	assert.Contains(t, list.Error.Error(), "--namespace-id "+connection.ServiceHooksNamespace+" --token PublisherSecurity/")
}

func hookIDs(m map[string]*mqlAzuredevopsWebhook) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
