// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestRefsListsOnlyBranches(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	refs, err := c.Refs(context.Background(), "scan-test", fakeado.RepoIacID)
	require.NoError(t, err)

	var names []string
	for _, r := range refs {
		names = append(names, r.Name)
	}
	assert.Equal(t, []string{"refs/heads/main", "refs/heads/release/1.0"}, names)
	assert.Equal(t, "3c000000-0000-4000-8000-000000000321", refs[0].ObjectID)

	var sent string
	for _, r := range srv.Requests() {
		if strings.Contains(r, "/refs?") {
			sent = r
		}
	}
	assert.Contains(t, sent, "filter=heads%2F")
}

func TestRefsOfAProjectTheCredentialCannotReadIsForbidden(t *testing.T) {
	c, _, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	_, err := c.Refs(context.Background(), "locked-down", fakeado.RepoIacID)
	require.Error(t, err)
	assert.True(t, IsForbidden(err))
}
