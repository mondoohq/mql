// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectRepositories(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))

	byName := map[string]*mqlAzuredevopsProject{}
	for _, p := range org.GetProjects().Data {
		project := p.(*mqlAzuredevopsProject)
		byName[project.Name.Data] = project
	}

	readable := byName["scan-test"].GetRepositories()
	require.NoError(t, readable.Error)
	assert.Len(t, readable.Data, 4)

	locked := byName["locked-down"].GetRepositories()
	require.Error(t, locked.Error, "asking for the repositories of an unreadable project is an error")
	assert.Contains(t, locked.Error.Error(), `"locked-down"`)
}
