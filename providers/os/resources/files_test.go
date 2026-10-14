// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// files.find(depth: 0) searches from alone; sharing an ID with the search of
// no depth would answer one with the other's cached list.
func TestFilesFindIDKeepsDepthZero(t *testing.T) {
	unbounded := &mqlFilesFind{From: plugin.TValue[string]{Data: `C:\mqltest`, State: plugin.StateIsSet}}
	depth0 := &mqlFilesFind{
		From:  plugin.TValue[string]{Data: `C:\mqltest`, State: plugin.StateIsSet},
		Depth: plugin.TValue[int64]{Data: 0, State: plugin.StateIsSet},
	}
	depth1 := &mqlFilesFind{
		From:  plugin.TValue[string]{Data: `C:\mqltest`, State: plugin.StateIsSet},
		Depth: plugin.TValue[int64]{Data: 1, State: plugin.StateIsSet},
	}

	ids := map[string]bool{}
	for _, f := range []*mqlFilesFind{unbounded, depth0, depth1} {
		id, err := f.id()
		require.NoError(t, err)
		ids[id] = true
	}
	assert.Len(t, ids, 3)
}
