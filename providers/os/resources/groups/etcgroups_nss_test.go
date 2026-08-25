// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getent group emits the same colon separated format as /etc/group, which is
// why the existing parser handles it unchanged. This pins that, because the
// NSS fallback depends on it.
func TestParseEtcGroupHandlesGetentOutput(t *testing.T) {
	// verbatim shape of `getent group` on a host whose groups come from an NSS
	// module rather than /etc/group
	out := `root:x:0:
daemon:x:1:
sudo:x:27:core
docker:x:233:core
nobody:x:65534:
portage:x:250:core
`
	groups, err := ParseEtcGroup(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, groups, 6)

	byName := map[string]*Group{}
	for _, g := range groups {
		byName[g.Name] = g
	}

	// the entries that only NSS knows about must parse identically
	assert.Contains(t, byName, "nobody", "an NSS-only group must parse")
	assert.Equal(t, int64(65534), byName["nobody"].Gid)

	require.Contains(t, byName, "portage")
	assert.Equal(t, int64(250), byName["portage"].Gid)
	assert.Equal(t, []string{"core"}, byName["portage"].Members)

	assert.Equal(t, int64(0), byName["root"].Gid)
	assert.Empty(t, byName["root"].Members)
}

// A group line with no members must not invent one.
func TestParseEtcGroupEmptyMembers(t *testing.T) {
	groups, err := ParseEtcGroup(strings.NewReader("wheel:x:10:\n"))
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Empty(t, groups[0].Members)
}
