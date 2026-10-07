// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/url"
)

// Refs lists the branches of a repository. The heads/ filter leaves tags and
// other refs out, so every entry is a refs/heads/ ref.
func (c *Client) Refs(ctx context.Context, project, repoID string) ([]Ref, error) {
	return listAll[Ref](ctx, c, request{
		segments: []string{project, "_apis", "git", "repositories", repoID, "refs"},
		query:    url.Values{"filter": {"heads/"}},
	}, 0)
}
