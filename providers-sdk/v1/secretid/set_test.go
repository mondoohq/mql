// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package secretid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// All cases are synthetic.

func TestSet(t *testing.T) {
	k1 := testKey(t, "k1", 0)
	k2 := testKey(t, "k2", 0x20)
	honey, err := ID(k1, "honeytoken-value")
	require.NoError(t, err)
	other, err := ID(k1, "ordinary-value")
	require.NoError(t, err)

	s := NewSet(honey, "")
	assert.Equal(t, 1, s.Len(), "an empty id is not a member")
	assert.True(t, s.Contains(honey))
	assert.False(t, s.Contains(other))
	assert.False(t, s.Contains(""))

	// During a rotation window the set holds ids under the previous key; a
	// value found now matches through its previous id.
	ids, err := IDs([]*Key{k2, k1}, "honeytoken-value")
	require.NoError(t, err)
	assert.False(t, s.Contains(ids[0]))
	assert.True(t, s.ContainsAny(ids))
	assert.False(t, s.ContainsAny([]string{other}))
	assert.False(t, s.ContainsAny(nil))

	// Exact comparison: the hex without its version prefix is not a member.
	assert.False(t, s.Contains(honey[len("v1:"):]))

	var nilSet *Set
	assert.False(t, nilSet.Contains(honey))
	assert.Equal(t, 0, nilSet.Len())
}
