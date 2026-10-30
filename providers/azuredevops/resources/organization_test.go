// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestOrganizationInitReadsTheConnection(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))

	assert.Equal(t, fakeado.Org, org.GetName().Data)
	assert.Equal(t, "5e000000-0000-4000-8000-000000000001", org.GetId().Data)
	assert.Equal(t, "hosted", org.GetDeploymentType().Data)
}

func TestOrganizationProjects(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))

	list := org.GetProjects()
	require.NoError(t, list.Error)

	var names []string
	for _, p := range list.Data {
		names = append(names, p.(*mqlAzuredevopsProject).Name.Data)
	}
	// four projects arrive over two pages
	assert.ElementsMatch(t, []string{"scan-test", "scan test", "locked-down", "legacy-apps"}, names)
}

func TestOrganizationRepositoriesSkipAnUnreadableProject(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))

	repos := repositoriesOf(t, org)
	assert.Len(t, repos, 6, "the readable projects still list their repositories")

	unreadable := org.GetUnreadableProjects()
	require.NoError(t, unreadable.Error)
	assert.Equal(t, []any{"locked-down"}, unreadable.Data)
}
