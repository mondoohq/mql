// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/groups"
)

func TestParseWindowsLocalGroupsSingleObject(t *testing.T) {
	gs, err := groups.ParseWindowsLocalGroups(strings.NewReader(`{"Name":"Administrators","Description":"","PrincipalSource":1,"SID":{"BinaryLength":16,"AccountDomainSid":null,"Value":"S-1-5-32-544"},"ObjectClass":"Group"}`))
	require.NoError(t, err)
	require.Len(t, gs, 1)
	assert.Equal(t, "S-1-5-32-544", gs[0].SID.Value)
}
