// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// squadDatasetBody is a live entry from
// GET /api/datasets?author=rajpurkar&expand[]=... for rajpurkar/squad, with the
// long description truncated. The two download counters differ by two orders of
// magnitude, which is what makes a swapped struct tag visible.
const squadDatasetBody = `{
  "_id":"621ffdd236468d709f181f95",
  "id":"rajpurkar/squad",
  "author":"rajpurkar",
  "disabled":false,
  "gated":false,
  "lastModified":"2024-03-04T13:54:37.000Z",
  "likes":984,
  "private":false,
  "sha":"7b6d24c440a36b6815f21b70d25016731768db1f",
  "description":"Dataset Card for SQuAD",
  "downloads":254152,
  "downloadsAllTime":7965198,
  "tags":["task_categories:question-answering","language:en"],
  "createdAt":"2022-03-02T23:29:22.000Z"
}`

// Every widened dataset field has to decode under its real key. The two
// download counters are the trap: swapping the downloads and downloadsAllTime
// tags compiles and reports plausible numbers on the wrong fields.
func TestDatasetDecode(t *testing.T) {
	var ds Dataset
	require.NoError(t, json.Unmarshal([]byte(squadDatasetBody), &ds))

	assert.Equal(t, "rajpurkar/squad", ds.ID)
	assert.Equal(t, "rajpurkar", ds.Author)
	assert.Equal(t, 254152, ds.Downloads, "downloads counts the last 30 days")
	assert.Equal(t, 7965198, ds.DownloadsAllTime, "downloadsAllTime counts since creation")
	assert.Equal(t, 984, ds.Likes)
	assert.False(t, ds.Private)
	assert.False(t, ds.Disabled)
	assert.Equal(t, "7b6d24c440a36b6815f21b70d25016731768db1f", ds.Sha)
	assert.Equal(t, "2022-03-02T23:29:22.000Z", ds.CreatedAt)
	assert.Equal(t, "2024-03-04T13:54:37.000Z", ds.LastModified)
	assert.Len(t, ds.Tags, 2)

	assert.False(t, ds.Gated.IsGated)
	assert.Equal(t, "false", ds.Gated.Mode)
}

// Datasets carry the same three-state gated field models do, verified live
// across 300 of the most downloaded datasets: false, "auto" and "manual" all
// occur. The shipped bool collapses the last two, so Mode has to survive.
func TestDatasetGatedDiscriminator(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		isGated bool
		mode    string
	}{
		{"ungated", `{"id":"a/b","gated":false}`, false, "false"},
		{"auto grants on acceptance", `{"id":"a/b","gated":"auto"}`, true, "auto"},
		{"manual waits for approval", `{"id":"a/b","gated":"manual"}`, true, "manual"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ds Dataset
			require.NoError(t, json.Unmarshal([]byte(tt.body), &ds))
			assert.Equal(t, tt.isGated, ds.Gated.IsGated)
			assert.Equal(t, tt.mode, ds.Gated.Mode)
		})
	}
}

// A response that never mentions gated must leave Mode empty, which the
// resource layer turns into a null gatedMode. Defaulting it to "false" would
// state that a repository nobody read is ungated.
func TestDatasetGatedAbsent(t *testing.T) {
	var ds Dataset
	require.NoError(t, json.Unmarshal([]byte(`{"id":"a/b"}`), &ds))
	assert.Empty(t, ds.Gated.Mode, "an unreported gated field must not decode to a mode")
	assert.False(t, ds.Gated.IsGated)
}
