// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestSaEnabled(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	tests := []struct {
		name  string
		sa    *github.SecurityAndAnalysis
		field saField
		want  bool
	}{
		{
			name:  "nil SecurityAndAnalysis",
			sa:    nil,
			field: saAdvancedSecurity,
			want:  false,
		},
		{
			name:  "nil sub-field",
			sa:    &github.SecurityAndAnalysis{},
			field: saAdvancedSecurity,
			want:  false,
		},
		{
			name: "advanced security enabled",
			sa: &github.SecurityAndAnalysis{
				AdvancedSecurity: &github.AdvancedSecurity{Status: strPtr("enabled")},
			},
			field: saAdvancedSecurity,
			want:  true,
		},
		{
			name: "secret scanning disabled",
			sa: &github.SecurityAndAnalysis{
				SecretScanning: &github.SecretScanning{Status: strPtr("disabled")},
			},
			field: saSecretScanning,
			want:  false,
		},
		{
			name: "secret scanning push protection",
			sa: &github.SecurityAndAnalysis{
				SecretScanningPushProtection: &github.SecretScanningPushProtection{Status: strPtr("enabled")},
			},
			field: saSecretScanningPushProtection,
			want:  true,
		},
		{
			name: "dependabot security updates",
			sa: &github.SecurityAndAnalysis{
				DependabotSecurityUpdates: &github.DependabotSecurityUpdates{Status: strPtr("disabled")},
			},
			field: saDependabotSecurityUpdates,
			want:  false,
		},
		{
			name: "secret scanning validity checks",
			sa: &github.SecurityAndAnalysis{
				SecretScanningValidityChecks: &github.SecretScanningValidityChecks{Status: strPtr("enabled")},
			},
			field: saSecretScanningValidityChecks,
			want:  true,
		},
		{
			name: "querying one field ignores others",
			sa: &github.SecurityAndAnalysis{
				AdvancedSecurity: &github.AdvancedSecurity{Status: strPtr("enabled")},
				SecretScanning:   &github.SecretScanning{Status: strPtr("disabled")},
			},
			field: saSecretScanning,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := saEnabled(tt.sa, tt.field)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPermissionsFromUser(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name string
		user *github.User
		want []string
	}{
		{
			name: "nil permissions",
			user: &github.User{},
			want: []string{},
		},
		{
			name: "admin only",
			user: &github.User{
				Permissions: &github.RepositoryPermissions{
					Admin: boolPtr(true),
					Push:  boolPtr(false),
					Pull:  boolPtr(false),
				},
			},
			want: []string{"admin"},
		},
		{
			name: "all permissions",
			user: &github.User{
				Permissions: &github.RepositoryPermissions{
					Admin:    boolPtr(true),
					Maintain: boolPtr(true),
					Push:     boolPtr(true),
					Triage:   boolPtr(true),
					Pull:     boolPtr(true),
				},
			},
			want: []string{"admin", "maintain", "push", "triage", "pull"},
		},
		{
			name: "push and pull only",
			user: &github.User{
				Permissions: &github.RepositoryPermissions{
					Admin:    boolPtr(false),
					Maintain: boolPtr(false),
					Push:     boolPtr(true),
					Triage:   boolPtr(false),
					Pull:     boolPtr(true),
				},
			},
			want: []string{"push", "pull"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := permissionsFromUser(tt.user)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGithubResponseStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "not found", err: ghErrorResponse(404), want: 404},
		{name: "forbidden", err: ghErrorResponse(403), want: 403},
		{name: "ok", err: ghErrorResponse(200), want: 200},
		{name: "plain error has no status", err: errors.New("boom"), want: 0},
		{name: "wrapped github error", err: errors.Join(errors.New("ctx"), ghErrorResponse(404)), want: 404},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, githubResponseStatus(tc.err))
		})
	}
}

func TestGitTreeEntryType(t *testing.T) {
	tests := []struct {
		objectType string
		want       string
	}{
		{objectType: "blob", want: "file"},
		{objectType: "tree", want: "dir"},
		{objectType: "commit", want: "submodule"},
		{objectType: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.objectType, func(t *testing.T) {
			assert.Equal(t, tt.want, gitTreeEntryType(tt.objectType))
		})
	}
}

func TestIsBinaryFileFromTreeEntry(t *testing.T) {
	// Tree entries carry a full path, so the extension has to be read off the
	// last segment rather than by splitting the whole path on ".".
	assert.True(t, isBinaryFile("file", "tools/vendor/bin/helper.so"))
	assert.True(t, isBinaryFile("file", "build/my.app.exe"))
	assert.False(t, isBinaryFile("file", "docs/readme.md"))
	assert.False(t, isBinaryFile("dir", "tools/vendor/bin"))
	assert.False(t, isBinaryFile("submodule", "third_party/dep"))
}

func TestSecretScanningAlertMetadata(t *testing.T) {
	t.Run("pairs become a map", func(t *testing.T) {
		got := secretScanningAlertMetadata([]*github.SecretScanningAlertMetadata{
			{Key: "owner_email", Value: "dev@example.com"},
			{Key: "environment", Value: "production"},
		})
		assert.Equal(t, map[string]any{
			"owner_email": "dev@example.com",
			"environment": "production",
		}, got)
	})

	t.Run("nil entries and entries without a key are dropped", func(t *testing.T) {
		got := secretScanningAlertMetadata([]*github.SecretScanningAlertMetadata{
			nil,
			{Value: "orphan"},
			{Key: "", Value: "orphan"},
			{Key: "kept"},
		})
		assert.Equal(t, map[string]any{"kept": ""}, got)
	})

	t.Run("no metadata is an empty map", func(t *testing.T) {
		assert.Empty(t, secretScanningAlertMetadata(nil))
	})
}

func TestAlertUserAbsent(t *testing.T) {
	u, err := alertUser(nil, nil)
	assert.NoError(t, err)
	assert.Nil(t, u)
}

// Synthetic: a commit location and a pull request comment location as the
// secret scanning alert list documents them.
func TestSecretLocationData(t *testing.T) {
	assert.Equal(t, llx.NilData, secretLocationData(nil))

	commit := secretLocationData(&github.SecretScanningAlertLocationDetails{
		Path:      github.Ptr("config/prod.env"),
		Startline: github.Ptr(4),
		EndLine:   github.Ptr(4),
		CommitSHA: github.Ptr("f00d"),
		BlobSHA:   github.Ptr("beef"),
	})
	got := commit.Value.(map[string]any)
	assert.Equal(t, "config/prod.env", got["path"])
	assert.Equal(t, int64(4), got["startLine"])
	assert.Equal(t, int64(4), got["endLine"])
	assert.Equal(t, "f00d", got["commitSha"])
	assert.Equal(t, "beef", got["blobSha"])
	assert.Nil(t, got["startColumn"], "an unreported column is null, not 0")
	assert.Nil(t, got["pullRequestCommentUrl"])

	comment := secretLocationData(&github.SecretScanningAlertLocationDetails{
		PullRequestCommentURL: github.Ptr("https://api.github.com/repos/acme/app/issues/comments/1"),
	})
	got = comment.Value.(map[string]any)
	assert.Equal(t, "https://api.github.com/repos/acme/app/issues/comments/1", got["pullRequestCommentUrl"])
	assert.Contains(t, got, "path")
	assert.Nil(t, got["path"])
}

// Synthetic: asset ids are global; an id-less asset falls back to its release
// and position.
func TestReleaseAssetID(t *testing.T) {
	assert.Equal(t, "github.releaseAsset/42",
		releaseAssetID(&github.ReleaseAsset{ID: github.Ptr(int64(42))}, "https://github.com/acme/app/releases/tag/v1", 0))
	assert.Equal(t, "github.releaseAsset/https://github.com/acme/app/releases/tag/v1/2",
		releaseAssetID(&github.ReleaseAsset{}, "https://github.com/acme/app/releases/tag/v1", 2))
}

// Synthetic: assets map from the release listing; absent values read null.
func TestReleaseAssetsToMql(t *testing.T) {
	runtime := prefetchRuntime()
	res, err := releaseAssetsToMql(runtime, "https://github.com/acme/app/releases/tag/v1", []*github.ReleaseAsset{
		nil,
		{
			ID:            github.Ptr(int64(1)),
			Name:          github.Ptr("app-linux-amd64.tar.gz"),
			State:         github.Ptr("uploaded"),
			Size:          github.Ptr(1024),
			DownloadCount: github.Ptr(7),
			Digest:        github.Ptr("sha256:abc"),
		},
		{ID: github.Ptr(int64(2)), Name: github.Ptr("old.zip")},
	})
	require.NoError(t, err)
	require.Len(t, res, 2)

	a := res[0].(*mqlGithubReleaseAsset)
	assert.Equal(t, "app-linux-amd64.tar.gz", a.Name.Data)
	assert.Equal(t, int64(1024), a.Size.Data)
	assert.Equal(t, int64(7), a.DownloadCount.Data)
	assert.Equal(t, "sha256:abc", a.Digest.Data)

	b := res[1].(*mqlGithubReleaseAsset)
	assert.True(t, b.Digest.IsNull(), "an asset without a recorded digest reads null")
	assert.True(t, b.Size.IsNull())
}

// Synthetic: a repository built from Repositories.Get answers the fork,
// template and merge-setting fields from that response. The bare runtime has
// no connection, so a second Get fails the test.
func TestRepositoryDetailFromGet(t *testing.T) {
	runtime := prefetchRuntime()
	upstream := &github.Repository{ID: github.Ptr(int64(100)), Name: github.Ptr("upstream"), FullName: github.Ptr("other/upstream")}
	repo, err := newMqlGithubRepositoryFromGet(runtime, &github.Repository{
		ID:                  github.Ptr(int64(200)),
		Name:                github.Ptr("fork"),
		Parent:              upstream,
		Source:              upstream,
		DeleteBranchOnMerge: github.Ptr(true),
	})
	require.NoError(t, err)

	parent, err := repo.parent()
	require.NoError(t, err)
	require.NotNil(t, parent)
	assert.Equal(t, int64(100), parent.Id.Data)

	tmpl, err := repo.templateRepository()
	require.NoError(t, err)
	assert.Nil(t, tmpl)
	assert.True(t, repo.TemplateRepository.IsNull())

	del, err := repo.deleteBranchOnMerge()
	require.NoError(t, err)
	assert.True(t, del)

	_, err = repo.allowUpdateBranch()
	require.NoError(t, err)
	assert.True(t, repo.AllowUpdateBranch.IsNull(), "a merge setting GitHub withheld reads null")
}
