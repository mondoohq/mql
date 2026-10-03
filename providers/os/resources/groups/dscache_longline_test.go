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

// dscacheutil prints a group's members on one line. A directory group with
// thousands of members is longer than 64 KiB, and the groups after it must
// still be reported.
func TestParseDscacheutilResultKeepsGroupsAfterLongMemberList(t *testing.T) {
	members := make([]string, 7000)
	for i := range members {
		members[i] = fmt.Sprintf("member%05d", i)
	}
	out := "name: staff\npassword: *\ngid: 20\nusers: " + strings.Join(members, " ") + "\n\n" +
		"name: admin\npassword: *\ngid: 80\nusers: root alice\n\n"

	groups, err := ParseDscacheutilResult(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, groups, 2)
	byName := map[string]*Group{}
	for _, g := range groups {
		byName[g.Name] = g
	}
	require.Contains(t, byName, "admin")
	assert.Equal(t, []string{"root", "alice"}, byName["admin"].Members)
	require.Contains(t, byName, "staff")
	assert.Len(t, byName["staff"].Members, 7000)
}

func TestParseDscacheutilResultReturnsReadError(t *testing.T) {
	_, err := ParseDscacheutilResult(io.MultiReader(strings.NewReader("name: staff\ngid: 20\n"), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
}
