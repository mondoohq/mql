// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func ghFile(name, fileType string) *mqlGithubFile {
	return &mqlGithubFile{
		Name: plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
		Type: plugin.TValue[string]{Data: fileType, State: plugin.StateIsSet},
	}
}

func wantedFiles() (map[string]*plugin.TValue[*mqlGithubFile], *mqlGithubRepository) {
	repo := &mqlGithubRepository{}
	return map[string]*plugin.TValue[*mqlGithubFile]{
		"code_of_conduct.md": &repo.CodeOfConductFile,
		"support.md":         &repo.SupportFile,
		"security.md":        &repo.SecurityFile,
	}, repo
}

// GitHub accepts these files under any capitalization, so matching has to be
// case-insensitive -- mondoohq/.github ships them fully uppercased.
func TestClaimSpecialFilesIsCaseInsensitive(t *testing.T) {
	wanted, repo := wantedFiles()
	found := map[string]struct{}{}

	claimSpecialFiles([]any{
		ghFile("README.md", "file"),
		ghFile("SECURITY.md", "file"),
		ghFile("Code_Of_Conduct.md", "file"),
	}, wanted, found)

	require.NotNil(t, repo.SecurityFile.Data)
	assert.Equal(t, "SECURITY.md", repo.SecurityFile.Data.Name.Data)
	require.NotNil(t, repo.CodeOfConductFile.Data)
	assert.Equal(t, "Code_Of_Conduct.md", repo.CodeOfConductFile.Data.Name.Data)
	assert.Nil(t, repo.SupportFile.Data, "support.md is absent and must not be claimed")
}

// A directory named security.md would otherwise be reported as the security
// policy, and a file resource for a directory has no content to read.
func TestClaimSpecialFilesIgnoresDirectories(t *testing.T) {
	wanted, repo := wantedFiles()
	claimSpecialFiles([]any{ghFile("security.md", "dir")}, wanted, map[string]struct{}{})
	assert.Nil(t, repo.SecurityFile.Data)
}

// The root wins over .github: it is scanned first, and a file already claimed
// there must survive a second listing that also contains one.
func TestClaimSpecialFilesKeepsTheFirstMatch(t *testing.T) {
	wanted, repo := wantedFiles()
	found := map[string]struct{}{}

	claimSpecialFiles([]any{ghFile("SECURITY.md", "file")}, wanted, found)
	root := repo.SecurityFile.Data
	require.NotNil(t, root)

	// a later directory offering its own copy must not displace it
	claimSpecialFiles([]any{ghFile("security.md", "file")}, wanted, found)
	assert.Same(t, root, repo.SecurityFile.Data, "the root copy must win")
}

// Entries arrive as []any straight off a field, so a nil or foreign element
// must be skipped rather than panic the scan.
func TestClaimSpecialFilesToleratesBadEntries(t *testing.T) {
	wanted, repo := wantedFiles()
	assert.NotPanics(t, func() {
		claimSpecialFiles([]any{
			nil,
			"not a file resource",
			(*mqlGithubFile)(nil),
			&mqlGithubFile{Name: plugin.TValue[string]{Error: assert.AnError}},
			ghFile("SECURITY.md", "file"),
		}, wanted, map[string]struct{}{})
	})
	require.NotNil(t, repo.SecurityFile.Data)
}

// The descent only happens when the directory is really there; that is what
// replaces an unconditional request that answered 404 on most repositories.
func TestGithubDirEntry(t *testing.T) {
	entries := []any{
		ghFile("README.md", "file"),
		ghFile(".github", "dir"),
		ghFile("docs", "dir"),
	}
	got := githubDirEntry(entries, ".github")
	require.NotNil(t, got)
	assert.Equal(t, ".github", got.Name.Data)

	assert.Nil(t, githubDirEntry(entries, ".circleci"), "absent directory must not be descended into")
	// a *file* named .github is not a directory to walk
	assert.Nil(t, githubDirEntry([]any{ghFile(".github", "file")}, ".github"))
	assert.Nil(t, githubDirEntry(nil, ".github"))
}
