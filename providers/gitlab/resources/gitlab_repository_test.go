// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

func TestStatusCheckBranchNames(t *testing.T) {
	// Synthetic: protected_branches entries as the external status checks API
	// documents them.
	names := statusCheckBranchNames([]gitlab.StatusCheckProtectedBranch{
		{ID: 1, Name: "main"},
		{ID: 2, Name: ""},
		{ID: 3, Name: "release/*"},
	})
	assert.Equal(t, []string{"main", "release/*"}, names)

	assert.Empty(t, statusCheckBranchNames(nil), "a check without branches applies to all of them")
}

func TestFilterByName(t *testing.T) {
	// Synthetic: the filter is plain logic over names.
	type named struct{ name string }
	resources := []any{named{"main"}, named{"develop"}, "not a resource", named{"release/*"}}
	name := func(r any) (string, bool) {
		n, ok := r.(named)
		return n.name, ok
	}

	got := filterByName(resources, []string{"release/*", "main", "missing"}, name)
	assert.Equal(t, []any{named{"main"}, named{"release/*"}}, got, "keeps the resource order and skips names with no resource")

	assert.Empty(t, filterByName(resources, nil, name))
	assert.NotNil(t, filterByName(resources, nil, name), "no match is an empty list, not null")
}
