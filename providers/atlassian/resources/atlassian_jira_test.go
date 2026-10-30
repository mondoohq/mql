// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/ctreminiom/go-atlassian/v2/pkg/infra/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJiraPriorityName(t *testing.T) {
	assert.Equal(t, "", jiraPriorityName(nil))
	assert.Equal(t, "High", jiraPriorityName(&models.PriorityScheme{Name: "High"}))
	assert.Equal(t, "", jiraPriorityName(&models.PriorityScheme{}))
}

func TestJiraResolutionName(t *testing.T) {
	assert.Equal(t, "", jiraResolutionName(nil))
	assert.Equal(t, "Won't Do", jiraResolutionName(&models.ResolutionScheme{Name: "Won't Do"}))
	assert.Equal(t, "", jiraResolutionName(&models.ResolutionScheme{}))
}

func TestJiraFieldPointerHelpers(t *testing.T) {
	// These guard the issues() mapping against nil Project/Status/IssueType
	// pointers (all omitempty in the SDK), which would otherwise panic and
	// crash the whole scan.
	assert.Equal(t, "", jiraProjectName(nil))
	assert.Equal(t, "Platform", jiraProjectName(&models.ProjectScheme{Name: "Platform"}))

	assert.Equal(t, "", jiraProjectKey(nil))
	assert.Equal(t, "PLAT", jiraProjectKey(&models.ProjectScheme{Key: "PLAT"}))

	assert.Equal(t, "", jiraStatusName(nil))
	assert.Equal(t, "Done", jiraStatusName(&models.StatusScheme{Name: "Done"}))

	assert.Equal(t, "", jiraIssueTypeName(nil))
	assert.Equal(t, "Bug", jiraIssueTypeName(&models.IssueTypeScheme{Name: "Bug"}))
}

func TestJiraDateTime(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		assert.Nil(t, jiraDateTime(nil))
	})

	t.Run("converts to UTC", func(t *testing.T) {
		ny, err := time.LoadLocation("America/New_York")
		require.NoError(t, err)

		// 2026-04-27 12:00:00 EDT == 2026-04-27 16:00:00 UTC
		local := time.Date(2026, 4, 27, 12, 0, 0, 0, ny)
		scheme := models.DateTimeScheme(local)

		got := jiraDateTime(&scheme)
		require.NotNil(t, got)
		assert.Equal(t, time.UTC, got.Location())
		assert.Equal(t, 16, got.Hour())
		assert.True(t, got.Equal(local), "UTC conversion must preserve the instant")
	})
}

func TestJiraDate(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		assert.Nil(t, jiraDate(nil))
	})

	t.Run("converts to UTC", func(t *testing.T) {
		ny, err := time.LoadLocation("America/New_York")
		require.NoError(t, err)

		local := time.Date(2026, 4, 27, 12, 0, 0, 0, ny)
		scheme := models.DateScheme(local)

		got := jiraDate(&scheme)
		require.NotNil(t, got)
		assert.Equal(t, time.UTC, got.Location())
		assert.True(t, got.Equal(local), "UTC conversion must preserve the instant")
	})
}

func TestStringsToAny(t *testing.T) {
	assert.Equal(t, []any{}, stringsToAny(nil))
	assert.Equal(t, []any{}, stringsToAny([]string{}))
	assert.Equal(t, []any{"a", "b", "c"}, stringsToAny([]string{"a", "b", "c"}))
}

func TestJiraUserAvatar(t *testing.T) {
	assert.Equal(t, "", jiraUserAvatar(nil))
	assert.Equal(t, "", jiraUserAvatar(&models.UserScheme{}))
	assert.Equal(t,
		"https://example.com/16.png",
		jiraUserAvatar(&models.UserScheme{
			AvatarURLs: &models.AvatarURLScheme{One6X16: "https://example.com/16.png"},
		}),
	)
}

func TestJiraWatcherAndVoteCounts(t *testing.T) {
	assert.Equal(t, 0, jiraWatcherCount(nil))
	assert.Equal(t, 7, jiraWatcherCount(&models.IssueWatcherScheme{WatchCount: 7}))
	assert.Equal(t, 0, jiraVoteCount(nil))
	assert.Equal(t, 3, jiraVoteCount(&models.IssueVoteScheme{Votes: 3}))
}

func TestJiraIssueSecurity(t *testing.T) {
	assert.Nil(t, jiraIssueSecurity(nil))

	got := jiraIssueSecurity(&models.SecurityScheme{ID: "10000", Name: "Public", Description: "anyone"})
	want := map[string]any{
		"id":          "10000",
		"name":        "Public",
		"description": "anyone",
	}
	assert.Equal(t, want, got)
}

func TestJiraIssueComponentsAndVersionsSkipNil(t *testing.T) {
	t.Run("components skips nil entries", func(t *testing.T) {
		got := jiraIssueComponents([]*models.ComponentScheme{
			nil,
			{ID: "1", Name: "auth"},
			nil,
			{ID: "2", Name: "billing"},
		})
		assert.Len(t, got, 2)
	})

	t.Run("versions skips nil entries", func(t *testing.T) {
		got := jiraIssueVersions([]*models.VersionScheme{
			nil,
			{ID: "10", Name: "1.0.0"},
		})
		assert.Len(t, got, 1)
	})
}

func TestJiraIssueComments(t *testing.T) {
	t.Run("nil page returns empty", func(t *testing.T) {
		assert.Equal(t, []any{}, jiraIssueComments(nil))
	})

	t.Run("nil comment entries are skipped", func(t *testing.T) {
		got := jiraIssueComments(&models.IssueCommentPageSchemeV2{
			Comments: []*models.IssueCommentSchemeV2{
				nil,
				{ID: "1", Body: "ok"},
			},
		})
		assert.Len(t, got, 1)
	})

	t.Run("nil author and nil visibility do not panic", func(t *testing.T) {
		got := jiraIssueComments(&models.IssueCommentPageSchemeV2{
			Comments: []*models.IssueCommentSchemeV2{
				{ID: "1", Body: "anon", Author: nil, Visibility: nil},
			},
		})
		require.Len(t, got, 1)
		row := got[0].(map[string]any)
		assert.Equal(t, "", row["author"])
		assert.Equal(t, "", row["authorName"])
		assert.Nil(t, row["visibility"])
	})

	t.Run("populated visibility surfaces as dict", func(t *testing.T) {
		got := jiraIssueComments(&models.IssueCommentPageSchemeV2{
			Comments: []*models.IssueCommentSchemeV2{
				{
					ID:         "1",
					Body:       "restricted",
					Visibility: &models.CommentVisibilityScheme{Type: "role", Value: "Administrators"},
				},
			},
		})
		require.Len(t, got, 1)
		vis := got[0].(map[string]any)["visibility"].(map[string]any)
		assert.Equal(t, "role", vis["type"])
		assert.Equal(t, "Administrators", vis["value"])
	})
}
