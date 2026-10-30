// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/services"
	"go.mondoo.com/mql/utils/syncx"
)

// A setting the running systemd does not have is null on systemd.unit, while
// the settings it has keep their values.
func TestCreateSystemdUnitResourceNullsUnsupportedSettings(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	unit := &services.SystemdUnit{
		Name:                    "g04-hard.service",
		LoadState:               "loaded",
		ProtectKernelModules:    true,
		RestrictAddressFamilies: "[unprintable]",
		Unsupported: map[string]bool{
			"ProtectClock":            true,
			"ProtectProc":             true,
			"RestrictAddressFamilies": true,
		},
	}
	raw, err := createSystemdUnitResource(runtime, unit)
	require.NoError(t, err)
	u := raw.(*mqlSystemdUnit)

	assert.True(t, u.ProtectKernelModules.Data)
	assert.False(t, u.ProtectKernelModules.IsNull())
	assert.True(t, u.ProtectClock.IsNull())
	assert.True(t, u.ProtectProc.IsNull())
	assert.True(t, u.RestrictAddressFamilies.IsNull())
	assert.False(t, u.ProtectHostname.IsNull())
}
