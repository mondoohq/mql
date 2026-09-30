// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/services"
)

// Get-Service | ConvertTo-Json emits a bare object for a single service.
func TestParseWindowsServiceSingleObject(t *testing.T) {
	srvs, err := services.ParseWindowsService(strings.NewReader(`{"Status":4,"Name":"WinRM","DisplayName":"Windows Remote Management (WS-Management)","StartType":2}`))
	require.NoError(t, err)
	require.Len(t, srvs, 1)
	assert.Equal(t, "WinRM", srvs[0].Name)
	assert.True(t, srvs[0].Running)
}

func TestParseWindowsServiceNoOutput(t *testing.T) {
	_, err := services.ParseWindowsService(strings.NewReader(""))
	assert.Error(t, err, "no output is a failed query, not a host without services")
}
