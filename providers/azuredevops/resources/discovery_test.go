// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

const (
	orgID          = "//platformid.api.mondoo.app/runtime/azuredevops/organization/mondoo-ado-scan-test"
	iacRepoID      = orgID + "/project/scan-test/repository/ado-scan-test-iac"
	iacSpaceRepoID = orgID + "/project/scan%20test/repository/ado-scan-test-iac"
)

func discoverAssets(t *testing.T, extra map[string]string, targets []string) ([]*inventory.Asset, *fakeado.Server) {
	t.Helper()
	runtime, srv := newDiscoveryRuntime(t, extra, targets)
	in, err := Discover(runtime)
	require.NoError(t, err)
	return in.Spec.Assets, srv
}

// ofType keeps the assets whose first connection has the given type.
func ofType(assets []*inventory.Asset, connType string) []*inventory.Asset {
	var out []*inventory.Asset
	for _, a := range assets {
		if a.Connections[0].Type == connType {
			out = append(out, a)
		}
	}
	return out
}

func platformIDs(assets []*inventory.Asset) []string {
	var out []string
	for _, a := range assets {
		out = append(out, a.PlatformIds...)
	}
	return out
}

func names(assets []*inventory.Asset) []string {
	var out []string
	for _, a := range assets {
		out = append(out, a.Name)
	}
	return out
}

func TestHandleTargetsExpandsAll(t *testing.T) {
	assert.Equal(t,
		[]string{"organization", "repos", "terraform", "k8s-manifests"},
		handleTargets([]string{"all"}))
	assert.Equal(t, []string{"auto"}, handleTargets([]string{"auto"}))
	assert.Equal(t, []string{"repos", "terraform"}, handleTargets([]string{"repos", "terraform"}))
}

func TestSelectReposSetsAsideEmptyAndDisabled(t *testing.T) {
	runtime := newRuntime(t, nil)
	conn := connectionOf(runtime)
	listing, err := conn.Listing(apiContext())
	require.NoError(t, err)

	sel := selectRepos(listing, conn.Filter())

	var ready []string
	for _, r := range sel.ready {
		ready = append(ready, r.FullName())
	}
	assert.Equal(t, []string{
		"scan-test/ado-scan-test-iac",
		"scan-test/ado-scan-test-app",
		"scan test/ado-scan-test-iac",
		"legacy-apps/ado-scan-test-docs",
	}, ready)

	status := map[string]connection.RepoStatus{}
	for _, s := range sel.skipped {
		status[s.repo.FullName()] = s.status
	}
	assert.Equal(t, map[string]connection.RepoStatus{
		"scan-test/ado-scan-test-empty":   connection.RepoEmpty,
		"scan-test/ado-scan-test-retired": connection.RepoDisabled,
	}, status)
}

func TestDiscoverWithoutDiscoveryConfigReturnsNothing(t *testing.T) {
	assets, _ := discoverAssets(t, nil, nil)
	assert.Empty(t, assets)
}

func TestDiscoverOrganizationAuto(t *testing.T) {
	assets, srv := discoverAssets(t, nil, []string{"auto"})

	// the organization, and the four repositories that can be scanned
	assert.Len(t, assets, 5)
	assert.Equal(t, orgID, assets[0].PlatformIds[0])
	assert.Equal(t, fakeado.Org, assets[0].Name)
	assert.Equal(t, connection.PlatformOrg, assets[0].Platform.Name)

	repos := assets[1:]
	for _, a := range repos {
		assert.Equal(t, connection.PlatformRepo, a.Platform.Name)
	}
	assert.ElementsMatch(t, []string{
		"scan-test/ado-scan-test-iac",
		"scan-test/ado-scan-test-app",
		"scan test/ado-scan-test-iac",
		"legacy-apps/ado-scan-test-docs",
	}, names(repos))

	// auto does not read any tree
	for _, req := range srv.Requests() {
		assert.NotContains(t, req, "/items")
	}
}

func TestDiscoveredRepositoryAssetsConnectBack(t *testing.T) {
	assets, _ := discoverAssets(t, nil, []string{"auto"})

	var spaced *inventory.Asset
	for _, a := range assets {
		if a.Name == "scan test/ado-scan-test-iac" {
			spaced = a
		}
	}
	require.NotNil(t, spaced)

	cfg := spaced.Connections[0]
	assert.Equal(t, "scan test", cfg.Options[connection.OPTION_PROJECT])
	assert.Equal(t, "ado-scan-test-iac", cfg.Options[connection.OPTION_REPOSITORY])
	assert.Equal(t, fakeado.Org, cfg.Options[connection.OPTION_ORGANIZATION])
	assert.Empty(t, cfg.GetDiscover().GetTargets(), "a discovered asset does not discover again")
	assert.Equal(t, uint32(testConnectionID), cfg.ParentConnectionId)
	assert.Equal(t, []string{"saas", "azuredevops", "organization", fakeado.Org, "project", "scan test", "repository"},
		spaced.Platform.TechnologyUrlSegments)
}

func TestSameRepositoryNameInTwoProjectsGivesTwoAssetIDs(t *testing.T) {
	assets, _ := discoverAssets(t, nil, []string{"repos"})

	ids := platformIDs(assets)
	assert.ElementsMatch(t, []string{
		iacRepoID,
		iacSpaceRepoID,
		orgID + "/project/scan-test/repository/ado-scan-test-app",
		orgID + "/project/legacy-apps/repository/ado-scan-test-docs",
	}, ids)
	assert.Len(t, ids, len(assets), "every asset has an id")
}

func TestDiscoverSkipsAnUnreadableProject(t *testing.T) {
	assets, _ := discoverAssets(t, nil, []string{"all"})

	for _, a := range assets {
		assert.False(t, strings.HasPrefix(a.Name, "locked-down/"), "no asset for %q", a.Name)
	}
	assert.Contains(t, names(assets), "legacy-apps/ado-scan-test-docs", "the readable projects are still discovered")
}

func TestDiscoverAllAddsTheIacChildren(t *testing.T) {
	assets, _ := discoverAssets(t, nil, []string{"all"})

	// organization + 4 repositories + terraform for iac and "scan test"/iac +
	// k8s for iac and app
	assert.Len(t, assets, 9)

	terraform := ofType(assets, "terraform-hcl-git")
	assert.ElementsMatch(t, []string{
		"//platformid.api.mondoo.app/runtime/terraform/domain/dev.azure.com/org/mondoo-ado-scan-test/project/scan-test/repo/ado-scan-test-iac",
		"//platformid.api.mondoo.app/runtime/terraform/domain/dev.azure.com/org/mondoo-ado-scan-test/project/scan%20test/repo/ado-scan-test-iac",
	}, platformIDs(terraform))
	assert.ElementsMatch(t, []string{"scan-test/ado-scan-test-iac", "scan test/ado-scan-test-iac"}, names(terraform))

	k8s := ofType(assets, "k8s")
	assert.ElementsMatch(t, []string{"scan-test/ado-scan-test-iac", "scan-test/ado-scan-test-app"}, names(k8s))
	for _, a := range k8s {
		assert.Empty(t, a.PlatformIds, "the k8s child keeps the id of the k8s provider")
		require.NotNil(t, a.Connections[0].Discover)
		assert.Equal(t, []string{"auto"}, a.Connections[0].Discover.Targets)
	}
}

func TestIacChildrenCloneWithTheTokenAndNoUserInformation(t *testing.T) {
	assets, _ := discoverAssets(t, nil, []string{"all"})

	children := append(ofType(assets, "terraform-hcl-git"), ofType(assets, "k8s")...)
	wantURL := map[string]string{
		"terraform-hcl-git|scan-test/ado-scan-test-iac": "https://dev.azure.com/mondoo-ado-scan-test/scan-test/_git/ado-scan-test-iac",
		"terraform-hcl-git|scan test/ado-scan-test-iac": "https://dev.azure.com/mondoo-ado-scan-test/scan%20test/_git/ado-scan-test-iac",
		"k8s|scan-test/ado-scan-test-iac":               "https://dev.azure.com/mondoo-ado-scan-test/scan-test/_git/ado-scan-test-iac",
		"k8s|scan-test/ado-scan-test-app":               "https://dev.azure.com/mondoo-ado-scan-test/scan-test/_git/ado-scan-test-app",
	}
	require.Len(t, children, len(wantURL))
	for _, a := range children {
		cfg := a.Connections[0]
		assert.Equal(t, wantURL[cfg.Type+"|"+a.Name], cfg.Options["http-url"], "%s %s", cfg.Type, a.Name)
		assert.NotContains(t, cfg.Options["http-url"], "@", "the URL carries no user information")
		assert.NotEmpty(t, cfg.Options["ssh-url"], "the terraform detector reads ssh-url")
		assert.Equal(t, plugin.GitServerAzureDevOps, cfg.Options[plugin.GitServerOptionKey], "the clone adapts its upload-pack request to Azure DevOps")

		require.Len(t, cfg.Credentials, 1)
		assert.Equal(t, connection.GitCredentialUser, cfg.Credentials[0].User, "Azure DevOps rejects an empty user")
		assert.Equal(t, fakeado.PAT, string(cfg.Credentials[0].Secret))
	}

	// the children do not share one credential value
	assert.NotSame(t, children[0].Connections[0].Credentials[0], children[1].Connections[0].Credentials[0])
}

func TestDiscoverTerraformTargetEmitsOnlyTerraformChildren(t *testing.T) {
	assets, _ := discoverAssets(t, nil, []string{"terraform"})

	assert.Len(t, assets, 2)
	for _, a := range assets {
		assert.Equal(t, "terraform-hcl-git", a.Connections[0].Type)
	}
}

func TestDiscoverReadsEachTreeOnce(t *testing.T) {
	_, srv := discoverAssets(t, nil, []string{"all"})

	var trees int
	for _, req := range srv.Requests() {
		if strings.Contains(req, "/items") {
			trees++
		}
	}
	// four repositories can be scanned. The empty and the disabled one have no
	// tree to read.
	assert.Equal(t, 4, trees)
}

func TestDiscoverRepositoryFilter(t *testing.T) {
	assets, _ := discoverAssets(t, map[string]string{connection.OPTION_REPOS: "scan-test/*"}, []string{"auto"})

	// a filter means the user wants those repositories, not the organization
	assert.ElementsMatch(t, []string{"scan-test/ado-scan-test-iac", "scan-test/ado-scan-test-app"}, names(assets))
}

func TestDiscoverRepositoryExcludeFilter(t *testing.T) {
	assets, _ := discoverAssets(t, map[string]string{connection.OPTION_REPOS_EXCLUDE: "*/ado-scan-test-iac"}, []string{"repos"})

	assert.ElementsMatch(t, []string{"scan-test/ado-scan-test-app", "legacy-apps/ado-scan-test-docs"}, names(assets))
}

// captureLogs points the global logger at a buffer for the rest of the test.
// A test that uses it must not call t.Parallel.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&logs)
	t.Cleanup(func() { log.Logger = previous })
	return &logs
}

func TestDiscoverWarnsWhenTheIncludeFilterMatchesNothing(t *testing.T) {
	logs := captureLogs(t)

	// the pattern has no slash, so it can never match "project/repository"
	assets, _ := discoverAssets(t, map[string]string{connection.OPTION_REPOS: "ado-*"}, []string{"auto"})

	assert.Empty(t, assets, "nothing matches, so there is no repository asset and, with a filter, no organization asset")
	out := logs.String()
	assert.Contains(t, out, `"level":"warn"`)
	assert.Contains(t, out, "repository include filter matched no repositories")
	assert.Contains(t, out, "project/repository")
	assert.Contains(t, out, "scan-test/*")
}

func TestDiscoverStaysSilentWhenTheFilterMatches(t *testing.T) {
	cases := map[string]map[string]string{
		"an include filter that matches": {connection.OPTION_REPOS: "scan-test/*"},
		// without an include list every repository the exclude list leaves is
		// kept, so there is nothing to warn about
		"an exclude-only filter": {connection.OPTION_REPOS_EXCLUDE: "*/ado-scan-test-iac"},
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t)

			assets, _ := discoverAssets(t, options, []string{"repos"})

			assert.NotEmpty(t, assets)
			assert.NotContains(t, logs.String(), "matched no repositories")
		})
	}
}

func TestFailedTreeWalkKeepsTheRepositoryAsset(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, []string{"all"})
	srv.DenyItems(fakeado.RepoIacID)

	in, err := Discover(runtime)
	require.NoError(t, err, "one unreadable tree does not fail the organization")

	assert.Contains(t, names(ofType(in.Spec.Assets, "azuredevops")), "scan-test/ado-scan-test-iac")
	// the iac repository loses its two children and nothing else changes
	assert.Len(t, in.Spec.Assets, 7)
	assert.ElementsMatch(t, []string{"scan test/ado-scan-test-iac"}, names(ofType(in.Spec.Assets, "terraform-hcl-git")))
	assert.ElementsMatch(t, []string{"scan-test/ado-scan-test-app"}, names(ofType(in.Spec.Assets, "k8s")))
}

func TestDiscoverRepositoryConnection(t *testing.T) {
	assets, _ := discoverAssets(t, map[string]string{
		connection.OPTION_PROJECT:    "scan test",
		connection.OPTION_REPOSITORY: "ado-scan-test-iac",
	}, []string{"all"})

	// the repository, and a terraform child. Its only YAML file is under .azure,
	// a hidden directory.
	require.Len(t, assets, 2)
	assert.Equal(t, iacSpaceRepoID, assets[0].PlatformIds[0])
	assert.Equal(t, "scan test/ado-scan-test-iac", assets[0].Name)
	assert.Equal(t, "terraform-hcl-git", assets[1].Connections[0].Type)
}

func TestDiscoverEmptyRepositoryConnectionReadsNoTree(t *testing.T) {
	assets, srv := discoverAssets(t, map[string]string{
		connection.OPTION_PROJECT:    "scan-test",
		connection.OPTION_REPOSITORY: "ado-scan-test-empty",
	}, []string{"all"})

	// asked for by name, so the asset is there, but there is no tree to read
	require.Len(t, assets, 1)
	assert.Equal(t, "scan-test/ado-scan-test-empty", assets[0].Name)
	for _, req := range srv.Requests() {
		assert.NotContains(t, req, "/items")
	}
}

func TestDiscoverDisabledRepositoryConnectionReadsNoTree(t *testing.T) {
	assets, srv := discoverAssets(t, map[string]string{
		connection.OPTION_PROJECT:    "scan-test",
		connection.OPTION_REPOSITORY: "ado-scan-test-retired",
	}, []string{"all"})

	// asked for by name, so the asset is there, but a disabled repository's
	// tree is not read and it has no IaC children
	require.Len(t, assets, 1)
	assert.Equal(t, "scan-test/ado-scan-test-retired", assets[0].Name)
	for _, req := range srv.Requests() {
		assert.NotContains(t, req, "/items")
	}
}

// staticEntraToken is an Entra credential that always returns the fake bearer
// token the fake organization accepts.
type staticEntraToken struct{}

func (staticEntraToken) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: fakeado.BearerToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

const fakeClientSecret = "fake-client-secret"

func TestEntraRepositoryAssetsCarryTheSecretAndNeverAMintedToken(t *testing.T) {
	srv := fakeado.New(t)
	conf := &inventory.Config{
		Type: "azuredevops",
		Options: map[string]string{
			connection.OPTION_ORGANIZATION: fakeado.Org,
			connection.OPTION_API_ENDPOINT: srv.URL,
			connection.OPTION_TENANT_ID:    "11111111-2222-3333-4444-555555555555",
			connection.OPTION_CLIENT_ID:    "66666666-7777-8888-9999-000000000000",
		},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", fakeClientSecret)},
		Discover:    &inventory.Discovery{Targets: []string{"all"}},
	}
	auth, err := connection.NewAuthenticator(connection.AuthOptions{
		TenantID:        conf.Options[connection.OPTION_TENANT_ID],
		ClientID:        conf.Options[connection.OPTION_CLIENT_ID],
		TokenCredential: staticEntraToken{},
	})
	require.NoError(t, err)
	conn, err := connection.NewAzuredevopsConnection(testConnectionID, &inventory.Asset{Connections: []*inventory.Config{conf}}, connection.WithAuthenticator(auth))
	require.NoError(t, err)
	runtime := plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)

	in, err := Discover(runtime)
	require.NoError(t, err)

	var repos []*inventory.Asset
	for _, a := range in.Spec.Assets {
		if a.Platform.GetName() == connection.PlatformRepo {
			repos = append(repos, a)
		}
	}
	require.Len(t, repos, 4)
	for _, a := range repos {
		cfg := a.Connections[0]
		// A repository job signs in on its own, so its config holds what it
		// needs to mint a token at the start of the job, and not a token.
		assert.Equal(t, conf.Options[connection.OPTION_TENANT_ID], cfg.Options[connection.OPTION_TENANT_ID], a.Name)
		assert.Equal(t, conf.Options[connection.OPTION_CLIENT_ID], cfg.Options[connection.OPTION_CLIENT_ID], a.Name)
		require.Len(t, cfg.Credentials, 1, a.Name)
		assert.Equal(t, fakeClientSecret, string(cfg.Credentials[0].Secret), a.Name)
		assert.NotEqual(t, fakeado.BearerToken, string(cfg.Credentials[0].Secret), a.Name)
	}

	// An IaC child clones with a token minted at discovery time.
	children := append(ofType(in.Spec.Assets, "terraform-hcl-git"), ofType(in.Spec.Assets, "k8s")...)
	require.NotEmpty(t, children)
	for _, a := range children {
		require.Len(t, a.Connections[0].Credentials, 1, a.Name)
		assert.Equal(t, fakeado.BearerToken, string(a.Connections[0].Credentials[0].Secret), a.Name)
	}
}
