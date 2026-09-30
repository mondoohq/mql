// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package netapi

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The structs are read straight out of netapi32's buffers, so their layout has
// to match lmaccess.h for the architecture.
func TestStructLayout(t *testing.T) {
	ptr := unsafe.Sizeof(uintptr(0))

	assert.Equal(t, 3*ptr+8, unsafe.Sizeof(userInfo20{}))
	assert.Equal(t, 3*ptr, unsafe.Offsetof(userInfo20{}.Flags))
	assert.Equal(t, 3*ptr+4, unsafe.Offsetof(userInfo20{}.UserID))

	assert.Equal(t, 2*ptr, unsafe.Sizeof(localGroupInfo1{}))
	assert.Equal(t, ptr, unsafe.Offsetof(localGroupInfo1{}.Comment))

	assert.Equal(t, ptr, unsafe.Offsetof(localGroupMembersInfo2{}.SidUsage))
	assert.Equal(t, 2*ptr, unsafe.Offsetof(localGroupMembersInfo2{}.DomainAndName))
	assert.Equal(t, 3*ptr, unsafe.Sizeof(localGroupMembersInfo2{}))
}

func TestLiveEnumeration(t *testing.T) {
	users, err := Users()
	require.NoError(t, err)
	require.NotEmpty(t, users)

	machine, err := MachineSid()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(machine, "S-1-5-21-"), machine)

	groups, err := Groups()
	require.NoError(t, err)
	var admins string
	for _, g := range groups {
		sid, err := AccountSid(g.Name)
		require.NoError(t, err)
		if sid == "S-1-5-32-544" {
			admins = g.Name
		}
	}
	require.NotEmpty(t, admins, "BUILTIN\\Administrators by SID")

	members, err := Members(admins)
	require.NoError(t, err)
	require.NotEmpty(t, members)
	for _, m := range members {
		assert.True(t, strings.HasPrefix(m.Sid, "S-1-"), m.Sid)
	}
}
