// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestTheTreeIsReadOncePerRepository(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	for range 3 {
		items, err := c.Tree(context.Background(), "scan-test", fakeado.RepoAppID)
		require.NoError(t, err)
		require.Len(t, items, 6)
	}
	_, err := c.Tree(context.Background(), "scan-test", fakeado.RepoIacID)
	require.NoError(t, err)

	reqs := srv.Requests()
	require.Len(t, reqs, 2)
	assert.Contains(t, reqs[0], "/"+fakeado.RepoAppID+"/items?")
	assert.Contains(t, reqs[0], "recursionLevel=Full")
	assert.Contains(t, reqs[1], "/"+fakeado.RepoIacID+"/items?")
}

func TestTheTreeOfAnEmptyRepositoryIsRecognized(t *testing.T) {
	c, _, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	_, err := c.Tree(context.Background(), "scan-test", fakeado.RepoEmptyID)
	require.Error(t, err)
	assert.True(t, IsEmptyRepoError(err), "got %v", err)
}

func TestItemContentReadsOneFileWithItsContent(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	item, err := c.ItemContent(context.Background(), "scan-test", fakeado.RepoAppID, "/azure-pipelines.yml")
	require.NoError(t, err)
	assert.Equal(t, "/azure-pipelines.yml", item.Path)
	assert.True(t, item.IsBlob())
	assert.Contains(t, item.Content, "AdvancedSecurity-Dependency-Scanning@1")

	reqs := srv.Requests()
	require.Len(t, reqs, 1)
	assert.Contains(t, reqs[0], "path=%2Fazure-pipelines.yml")
	assert.Contains(t, reqs[0], "includeContent=true")
	assert.Contains(t, reqs[0], "%24format=json")
	assert.Contains(t, reqs[0], "api-version="+DefaultAPIVersion)
}

func TestItemContentOfAMissingPathIsNotFound(t *testing.T) {
	c, _, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	_, err := c.ItemContent(context.Background(), "scan-test", fakeado.RepoAppID, "/no-such-file.txt")
	require.Error(t, err)
	assert.True(t, IsNotFound(err), "got %v", err)
}

func TestItemContentOfAFileWithoutRecordedContentIsEmpty(t *testing.T) {
	c, _, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	item, err := c.ItemContent(context.Background(), "scan-test", fakeado.RepoAppID, "/README.md")
	require.NoError(t, err)
	assert.Equal(t, "/README.md", item.Path)
	assert.Empty(t, item.Content)
}
