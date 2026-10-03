// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// glibc reads /etc/group with no line limit. A group with thousands of
// members is one line well over 64 KiB, and the groups after it must still be
// reported.
func TestParseEtcGroupKeepsGroupsAfterLongLine(t *testing.T) {
	members := make([]string, 7000)
	for i := range members {
		members[i] = fmt.Sprintf("mqlhuge%05d", i)
	}
	group := "root:x:0:\n" +
		"mqlg_huge:x:5000:" + strings.Join(members, ",") + "\n" +
		"mqlg_after:x:5001:alice\n"
	require.Greater(t, len(group), 64*1024)

	m, err := ParseEtcGroup(strings.NewReader(group))
	require.NoError(t, err)
	require.Len(t, m, 3)
	assert.Equal(t, "mqlg_huge", m[1].Name)
	assert.Len(t, m[1].Members, 7000)
	assert.Equal(t, "mqlg_after", m[2].Name)
	assert.Equal(t, int64(5001), m[2].Gid)
}

// glibc ignores a group line whose gid is not a number (getent group <name>
// finds nothing). Reporting it with gid 0 invents a second root group.
func TestParseEtcGroupSkipsNonNumericGid(t *testing.T) {
	group := "root:x:0:\nmqlg_badgid:x:abc:alice\nwheel:x:10:alice\n"

	m, err := ParseEtcGroup(strings.NewReader(group))
	require.NoError(t, err)
	require.Len(t, m, 2)
	assert.Equal(t, "root", m[0].Name)
	assert.Equal(t, "wheel", m[1].Name)
}

// A read error must fail the parse rather than return a partial list.
func TestParseEtcGroupReturnsReadError(t *testing.T) {
	r := io.MultiReader(strings.NewReader("root:x:0:\n"), iotest.ErrReader(errors.New("read failed")))
	_, err := ParseEtcGroup(r)
	require.Error(t, err)
}
