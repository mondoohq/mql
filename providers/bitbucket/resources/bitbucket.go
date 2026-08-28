// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/providers/bitbucket/connection"
)

func (r *mqlBitbucket) id() (string, error) {
	return "bitbucket", nil
}

// conn returns the Bitbucket connection backing this runtime.
func (r *mqlBitbucket) conn() *connection.BitbucketConnection {
	return r.MqlRuntime.Connection.(*connection.BitbucketConnection)
}

// workspaces lists every workspace the authenticated identity can access.
func (r *mqlBitbucket) workspaces() ([]any, error) {
	conn := r.conn()
	list, err := conn.Client().ListWorkspaces(context.Background())
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for i := range list {
		res, err := newMqlBitbucketWorkspace(r.MqlRuntime, &list[i])
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}
