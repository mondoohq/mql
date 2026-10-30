// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/url"
)

// Tree lists the whole tree of a repository's default branch, read once per
// client. Every file lookup of a repository shares it. Discovery calls Items
// instead, so its reads stay independent of the resource cache.
func (c *Client) Tree(ctx context.Context, project, repoID string) ([]Item, error) {
	return c.trees.get(project+"/"+repoID, func() ([]Item, error) {
		return c.Items(ctx, project, repoID)
	})
}

// ItemContent reads one file of the default branch with its content. A path
// that the branch does not have answers 404.
func (c *Client) ItemContent(ctx context.Context, project, repoID, filePath string) (*Item, error) {
	out := &Item{}
	if _, err := c.getJSON(ctx, request{
		segments: []string{project, "_apis", "git", "repositories", repoID, "items"},
		query: url.Values{
			"path":           {filePath},
			"includeContent": {"true"},
			"$format":        {"json"},
		},
	}, out); err != nil {
		return nil, err
	}
	return out, nil
}
