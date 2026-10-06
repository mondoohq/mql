// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

// testConnectionID is the id the test connection carries, so a test can tell a
// discovered asset's parent link from the zero value.
const testConnectionID = 7

// newRuntime is a runtime connected to the fake Azure DevOps organization. The
// extra options turn it into a repository connection or add a repository filter.
func newRuntime(t *testing.T, extra map[string]string) *plugin.Runtime {
	t.Helper()
	runtime, _ := newDiscoveryRuntime(t, extra, nil)
	return runtime
}

// newDiscoveryRuntime is newRuntime with discovery targets, and it returns the
// fake so a test can read the requests it served. A nil targets slice leaves
// discovery off.
func newDiscoveryRuntime(t *testing.T, extra map[string]string, targets []string) (*plugin.Runtime, *fakeado.Server) {
	t.Helper()
	srv := fakeado.New(t)

	opts := map[string]string{
		connection.OPTION_ORGANIZATION: fakeado.Org,
		connection.OPTION_API_ENDPOINT: srv.URL,
	}
	for k, v := range extra {
		opts[k] = v
	}
	conf := &inventory.Config{
		Type:        "azuredevops",
		Options:     opts,
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", fakeado.PAT)},
	}
	if targets != nil {
		conf.Discover = &inventory.Discovery{Targets: targets}
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewAzuredevopsConnection(testConnectionID, asset)
	require.NoError(t, err)
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil), srv
}

func newOrganization(t *testing.T, runtime *plugin.Runtime) *mqlAzuredevopsOrganization {
	t.Helper()
	res, err := NewResource(runtime, "azuredevops.organization", map[string]*llx.RawData{})
	require.NoError(t, err)
	return res.(*mqlAzuredevopsOrganization)
}

func repositoriesOf(t *testing.T, org *mqlAzuredevopsOrganization) map[string]*mqlAzuredevopsRepository {
	t.Helper()
	list := org.GetRepositories()
	require.NoError(t, list.Error)
	out := map[string]*mqlAzuredevopsRepository{}
	for _, r := range list.Data {
		repo := r.(*mqlAzuredevopsRepository)
		out[repo.Id.Data] = repo
	}
	return out
}
