// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lsfilt -v4 on AIX 7.3 TL4 SP2 after a deny rule for tcp port 47999 was
// added; the table holds the default rules and the IKE placement marker.
func TestParseLsfilt(t *testing.T) {
	out, err := os.ReadFile("testdata/lsfilt_v4_aix73.txt")
	require.NoError(t, err)
	filters := ParseLsfilt(string(out), 4)

	ids := []int{}
	for _, f := range filters {
		ids = append(ids, f.ID)
	}
	assert.Equal(t, []int{1, 3, 0}, ids, "the dynamic placement rule 2 is left out")

	deny := filters[1]
	assert.Equal(t, 4, deny.Version)
	assert.Equal(t, "deny", deny.Attrs["Rule action"])
	assert.Equal(t, "tcp", deny.Attrs["Protocol"])
	assert.Equal(t, "eq 47999", deny.Attrs["Destination Port"], "runs of spaces collapse")
	assert.Equal(t, "mql test deny", deny.Attrs["Description"])

	assert.Equal(t, "permit", filters[2].Attrs["Rule action"])
}
