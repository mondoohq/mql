// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

// filesByPath maps a list of file resources by path.
func filesByPath(t *testing.T, list []any) map[string]*mqlAzuredevopsFile {
	t.Helper()
	out := map[string]*mqlAzuredevopsFile{}
	for _, x := range list {
		f := x.(*mqlAzuredevopsFile)
		out[f.Path.Data] = f
	}
	return out
}

// pathsOf lists the paths of a map of file resources.
func pathsOf(files map[string]*mqlAzuredevopsFile) []string {
	out := make([]string, 0, len(files))
	for p := range files {
		out = append(out, p)
	}
	return out
}

// itemRequests counts the requests of one repository's items route.
func itemRequests(srv *fakeado.Server, repoID string) int {
	n := 0
	for _, r := range srv.Requests() {
		if strings.Contains(r, "/"+repoID+"/items?") {
			n++
		}
	}
	return n
}

func TestTheWeakRepositoryHoldsABinary(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID]

	all := repo.GetAllFiles()
	require.NoError(t, all.Error)
	files := filesByPath(t, all.Data)
	assert.ElementsMatch(t, []string{
		"/README.md", "/main.tf", "/modules", "/modules/network", "/modules/network/main.tf",
		"/k8s", "/k8s/pod.yaml", "/secrets", "/secrets/.env", "/tools", "/tools/dummy.exe",
	}, pathsOf(files), "the root itself is not an entry")

	exe := files["/tools/dummy.exe"]
	assert.Equal(t, "file", exe.Type.Data)
	assert.Equal(t, "dummy.exe", exe.Name.Data)
	assert.True(t, exe.IsBinary.Data)
	assert.True(t, exe.Exists.Data)
	assert.Equal(t, "dir", files["/tools"].Type.Data)
	assert.False(t, files["/tools"].IsBinary.Data)
	assert.False(t, files["/main.tf"].IsBinary.Data)

	root := repo.GetFiles()
	require.NoError(t, root.Error)
	assert.ElementsMatch(t, []string{"/README.md", "/main.tf", "/modules", "/k8s", "/secrets", "/tools"},
		pathsOf(filesByPath(t, root.Data)))

	sub := files["/modules"].GetFiles()
	require.NoError(t, sub.Error)
	assert.ElementsMatch(t, []string{"/modules/network"}, pathsOf(filesByPath(t, sub.Data)))

	leaf := exe.GetFiles()
	require.NoError(t, leaf.Error)
	assert.Empty(t, leaf.Data)

	assert.Equal(t, 1, itemRequests(srv, fakeado.RepoIacID), "every lookup shares one read of the tree")
}

func TestTheWeakRepositoryHasNoSecurityPolicyAndNoPipeline(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID]

	sec := repo.GetSecurityFile()
	require.NoError(t, sec.Error)
	require.NotNil(t, sec.Data)
	assert.False(t, sec.Data.Exists.Data)
	assert.Equal(t, "/SECURITY.md", sec.Data.Path.Data)

	content := sec.Data.GetContent()
	require.NoError(t, content.Error)
	assert.True(t, content.IsNull(), "a file that does not exist has no content")

	pipes := repo.GetPipelineFiles()
	require.NoError(t, pipes.Error)
	require.False(t, pipes.IsNull())
	assert.Empty(t, pipes.Data)

	for _, r := range srv.Requests() {
		assert.NotContains(t, r, "includeContent", "no content is read")
	}
}

func TestTheStrongRepositoryHasASecurityPolicyAndAScanningPipeline(t *testing.T) {
	repo := repositoriesOf(t, newOrganization(t, newRuntime(t, nil)))[fakeado.RepoAppID]

	sec := repo.GetSecurityFile()
	require.NoError(t, sec.Error)
	assert.True(t, sec.Data.Exists.Data)
	assert.Equal(t, "/SECURITY.md", sec.Data.Path.Data)

	pipes := repo.GetPipelineFiles()
	require.NoError(t, pipes.Error)
	files := filesByPath(t, pipes.Data)
	require.ElementsMatch(t, []string{"/azure-pipelines.yml"}, pathsOf(files))

	content := files["/azure-pipelines.yml"].GetContent()
	require.NoError(t, content.Error)
	assert.Contains(t, content.Data, "AdvancedSecurity-Dependency-Scanning@")

	all := repo.GetAllFiles()
	require.NoError(t, all.Error)
	for _, x := range all.Data {
		assert.False(t, x.(*mqlAzuredevopsFile).IsBinary.Data)
	}
}

func TestASecurityPolicyOutsideTheRootIsFound(t *testing.T) {
	repo := repositoriesOf(t, newOrganization(t, newRuntime(t, nil)))[fakeado.RepoDocsID]

	sec := repo.GetSecurityFile()
	require.NoError(t, sec.Error)
	require.NotNil(t, sec.Data)
	assert.True(t, sec.Data.Exists.Data)
	assert.Equal(t, "/.github/SECURITY.md", sec.Data.Path.Data, "the path of the file that was found, not the root default")
}

func TestAnEmptyRepositoryHasNoFilesAndNoRequest(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoEmptyID]

	all := repo.GetAllFiles()
	require.NoError(t, all.Error)
	require.False(t, all.IsNull())
	assert.Empty(t, all.Data)

	sec := repo.GetSecurityFile()
	require.NoError(t, sec.Error)
	assert.False(t, sec.Data.Exists.Data)

	assert.Zero(t, itemRequests(srv, fakeado.RepoEmptyID))
}

func TestAnUnreadableTreeReportsTheFileFieldsForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.DenyItems(fakeado.RepoAppID)
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoAppID]

	files := repo.GetFiles()
	assert.ErrorIs(t, files.Error, llx.ErrForbidden)

	all := repo.GetAllFiles()
	assert.ErrorIs(t, all.Error, llx.ErrForbidden)

	sec := repo.GetSecurityFile()
	assert.ErrorIs(t, sec.Error, llx.ErrForbidden, "a refusal, not a missing policy")

	pipes := repo.GetPipelineFiles()
	assert.ErrorIs(t, pipes.Error, llx.ErrForbidden)
}

func TestAnUnreadableFileReportsItsContentForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoAppID]

	pipes := repo.GetPipelineFiles()
	require.NoError(t, pipes.Error)
	require.Len(t, pipes.Data, 1)

	srv.DenyItems(fakeado.RepoAppID)
	content := pipes.Data[0].(*mqlAzuredevopsFile).GetContent()
	assert.ErrorIs(t, content.Error, llx.ErrForbidden)
}

// A file the tree lists exists, so a content read that finds nothing is a plain
// error, not a forbidden error and not a null set without one: a null would
// read as an empty file and fail a check on a file that is there.
func TestAFileTheItemRouteCannotFindGivesAPlainErrorOnItsContent(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoAppID]

	pipes := repo.GetPipelineFiles()
	require.NoError(t, pipes.Error)
	require.Len(t, pipes.Data, 1)
	file := pipes.Data[0].(*mqlAzuredevopsFile)
	require.True(t, file.Exists.Data)

	srv.HideItem(fakeado.RepoAppID, "/azure-pipelines.yml")
	content := file.GetContent()
	require.Error(t, content.Error)
	assert.True(t, connection.IsNotFound(content.Error), "the 404 of the item route")
	assert.NotErrorIs(t, content.Error, llx.ErrForbidden, "a missing item is not a refusal")
	assert.Empty(t, content.Data)
}

func TestFileHelpers(t *testing.T) {
	blob := func(p string) connection.Item { return connection.Item{Path: p, GitObjectType: "blob"} }

	for _, p := range []string{"/azure-pipelines.yml", "/ci/Azure-Pipelines.YAML", "/.azure-pipelines/release.yml", "/.AzureDevOps/build.yaml"} {
		assert.True(t, isPipelineFile(blob(p)), p)
	}
	for _, p := range []string{"/azure-pipelines.json", "/.azure/ci.yml", "/docs/.azuredevops/x.yml", "/my-azure-pipelines.yml"} {
		assert.False(t, isPipelineFile(blob(p)), p)
	}
	assert.False(t, isPipelineFile(connection.Item{Path: "/azure-pipelines.yml", GitObjectType: "tree", IsFolder: true}))

	assert.True(t, isBinaryFile("file", "/v1.2/TOOL.EXE"))
	assert.False(t, isBinaryFile("file", "/v1.2/tool"))
	assert.False(t, isBinaryFile("dir", "/lib.so"))

	assert.Equal(t, "submodule", fileType(connection.Item{GitObjectType: "commit"}))
	assert.Equal(t, "dir", fileType(connection.Item{GitObjectType: "tree", IsFolder: true}))
}
