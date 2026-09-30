// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/users"
)

func TestParseWindowsLocalUsersSingleObject(t *testing.T) {
	us, err := users.ParseWindowsLocalUsers(strings.NewReader(`{"Name":"Administrator","Description":"","PrincipalSource":1,"SID":{"BinaryLength":28,"AccountDomainSid":null,"Value":"S-1-5-21-1-2-3-500"},"ObjectClass":"User","Enabled":true}`))
	require.NoError(t, err)
	require.Len(t, us, 1)
	assert.Equal(t, "Administrator", us[0].Name)
}
