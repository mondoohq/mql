// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	notebooksv2 "google.golang.org/api/notebooks/v2"
)

func TestWorkbenchBindingsToIampb(t *testing.T) {
	// Synthetic: a plain binding, a conditional binding and a nil entry.
	got := workbenchBindingsToIampb([]*notebooksv2.Binding{
		{Role: "roles/notebooks.runner", Members: []string{"user:a@example.com", "allUsers"}},
		nil,
		{Role: "roles/notebooks.admin", Members: []string{"group:ml@example.com"}, Condition: &notebooksv2.Expr{
			Title: "until 2027", Expression: `request.time < timestamp("2027-01-01T00:00:00Z")`, Description: "temporary",
		}},
	})
	require.Len(t, got, 2)
	assert.Equal(t, "roles/notebooks.runner", got[0].Role)
	assert.Equal(t, []string{"user:a@example.com", "allUsers"}, got[0].Members)
	assert.Nil(t, got[0].Condition)
	assert.Equal(t, "roles/notebooks.admin", got[1].Role)
	require.NotNil(t, got[1].Condition)
	assert.Equal(t, "until 2027", got[1].Condition.Title)
	assert.Equal(t, `request.time < timestamp("2027-01-01T00:00:00Z")`, got[1].Condition.Expression)
	assert.Equal(t, "temporary", got[1].Condition.Description)

	assert.Empty(t, workbenchBindingsToIampb(nil))
}
