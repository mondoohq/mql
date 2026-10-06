// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
// order the organization lists them.
func reposNamed(t *testing.T, listing *connection.Listing, fullNames ...string) []connection.ListedRepo {
	t.Helper()
	var out []connection.ListedRepo
	for _, r := range listing.Repos() {
		for _, name := range fullNames {
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
	repos := reposNamed(t, listing, "scan-test/ado-scan-test-iac", "scan-test/ado-scan-test-app", "legacy-apps/ado-scan-test-docs")

	got := walkIac(apiContext(), conn.Client(), repos)

	require.Len(t, got, 3)
	for _, r := range got {
		assert.NoError(t, r.err)
	}
	assert.Equal(t, repoIac{hasTerraform: true, hasKubernetes: true}, got[0].iac)
	assert.Equal(t, repoIac{hasKubernetes: true}, got[1].iac)
	assert.Equal(t, repoIac{}, got[2].iac)
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
	assert.Error(t, got[0].err, "the denied repository carries its error")
	assert.NoError(t, got[1].err, "the other repository is read")
	assert.Equal(t, repoIac{hasKubernetes: true}, got[1].iac)
}
