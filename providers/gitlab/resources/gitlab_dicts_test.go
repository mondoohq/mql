// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

// assertDictSerializable mirrors llx's dict2primitive allow-list. Values placed
// in a `dict` or `[]dict` field are serialized by that function, which errors
// on anything outside this set — so a *time.Time or an int32 in a dict fails
// the whole field at query time rather than at compile time. Note a typed nil
// pointer is *not* caught by a `== nil` check inside dict2primitive either,
// because the interface itself is non-nil.
func assertDictSerializable(t *testing.T, value any, path string) {
	t.Helper()
	switch v := value.(type) {
	case nil, bool, int64, float64, string:
		// JSON-native, fine
	case []any:
		for i := range v {
			assertDictSerializable(t, v[i], path+"[]")
		}
	case map[string]any:
		for k, item := range v {
			assertDictSerializable(t, item, path+"."+k)
		}
	default:
		t.Fatalf("%s: %T is not a JSON-native dict value (llx dict2primitive accepts only nil/bool/int64/float64/string/[]any/map[string]any)", path, value)
	}
}

func TestReleaseDictsAreSerializable(t *testing.T) {
	authored := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	committed := time.Date(2026, 3, 2, 11, 30, 0, 0, time.UTC)
	collected := time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC)

	t.Run("commit with timestamps", func(t *testing.T) {
		got := releaseCommitToDict(gitlab.Commit{
			ID:            "abc123",
			ShortID:       "abc",
			Title:         "ship it",
			AuthorName:    "Ada",
			AuthoredDate:  &authored,
			CommittedDate: &committed,
			WebURL:        "https://gitlab.com/acme/api/-/commit/abc123",
		})
		assertDictSerializable(t, got, "commit")

		m, ok := got.(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "2026-03-01T10:00:00Z", m["authoredDate"])
		assert.Equal(t, "2026-03-02T11:30:00Z", m["committedDate"])
	})

	t.Run("commit with nil timestamps", func(t *testing.T) {
		// A nil *time.Time must become an untyped nil, not a typed nil that
		// slips past dict2primitive's nil check and hits its error branch.
		got := releaseCommitToDict(gitlab.Commit{ID: "abc123"})
		assertDictSerializable(t, got, "commit")

		m, ok := got.(map[string]any)
		require.True(t, ok)
		assert.Nil(t, m["authoredDate"])
		assert.Nil(t, m["committedDate"])
	})

	t.Run("empty commit is dropped", func(t *testing.T) {
		assert.Nil(t, releaseCommitToDict(gitlab.Commit{}))
	})

	t.Run("evidences", func(t *testing.T) {
		got := releaseEvidencesToDicts([]*gitlab.ReleaseEvidence{
			{SHA: "sha1", Filepath: "https://example.com/e.json", CollectedAt: &collected},
			nil, // nil entries are skipped, not mapped to a zero dict
			{SHA: "sha2"},
		})
		assertDictSerializable(t, []any(got), "evidences")
		require.Len(t, got, 2)

		first := got[0].(map[string]any)
		assert.Equal(t, "2026-03-03T12:00:00Z", first["collectedAt"])
		assert.Nil(t, got[1].(map[string]any)["collectedAt"])
	})

	t.Run("assets", func(t *testing.T) {
		got := releaseAssetsToDict(gitlab.ReleaseAssets{
			Count:   2,
			Sources: []gitlab.ReleaseAssetsSource{{Format: "zip", URL: "https://example.com/a.zip"}},
			Links: []*gitlab.ReleaseLink{
				{ID: 7, Name: "binary", URL: "https://example.com/bin", LinkType: gitlab.PackageLinkType, External: true},
				nil,
			},
		})
		assertDictSerializable(t, got, "assets")

		m := got.(map[string]any)
		assert.Len(t, m["links"], 1)
	})
}

func TestOtherDictConvertersAreSerializable(t *testing.T) {
	accessLevel := gitlab.AccessLevelValue(40)

	cases := map[string]any{
		"sharedWithGroups": []any(projectSharedGroupsToDicts([]gitlab.ProjectSharedWithGroup{
			{GroupID: 3, GroupName: "platform", GroupFullPath: "acme/platform", GroupAccessLevel: 30},
		})),
		"groups": []any(groupsToDicts([]*gitlab.Group{
			{ID: 7, Name: "platform", FullPath: "acme/platform", Visibility: gitlab.PrivateVisibility},
			nil,
		})),
		"deployAccessLevels": []any(envDeployAccessLevelsToDicts([]*gitlab.EnvironmentAccessDescription{
			{AccessLevel: 40, AccessLevelDescription: "Maintainers", UserID: 1, GroupID: 2},
			nil,
		})),
		"envApprovalRules": []any(envApprovalRulesToDicts([]*gitlab.EnvironmentApprovalRule{
			{ID: 1, AccessLevel: 30, RequiredApprovalCount: 2},
			nil,
		})),
		"groupSharedGroups": []any(groupSharedGroupsToDicts([]gitlab.SharedWithGroup{
			{GroupID: 9, GroupName: "sec", GroupFullPath: "acme/sec", GroupAccessLevel: 50},
		})),
		"ldapGroupLinks": []any(ldapGroupLinksToDicts([]*gitlab.LDAPGroupLink{
			{CN: "devs", Filter: "", Provider: "ldapmain", GroupAccess: 30},
			nil,
		})),
		"branchProtectionDefaults": branchProtectionDefaultsToDict(&gitlab.BranchProtectionDefaults{
			AllowForcePush: true,
			AllowedToPush:  []*gitlab.GroupAccessLevel{{AccessLevel: &accessLevel}, nil, {}},
		}),
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			assertDictSerializable(t, value, name)
		})
	}

	t.Run("nil branch protection defaults", func(t *testing.T) {
		assert.Nil(t, branchProtectionDefaultsToDict(nil))
	})
}

func TestDictTime(t *testing.T) {
	assert.Nil(t, dictTime(nil), "a nil timestamp must be an untyped nil")

	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	assert.Equal(t, "2026-01-02T03:04:05Z", dictTime(&ts))
}
