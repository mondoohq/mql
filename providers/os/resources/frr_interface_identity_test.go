// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/frr"
	"go.mondoo.com/mql/utils/syncx"
)

func TestFrrInterfacesDistinctAcrossVRFs(t *testing.T) {
	cfg, err := frr.Parse("frr.conf", strings.NewReader("interface eth0 vrf RED\n description red\nexit\ninterface eth0 vrf BLUE\n description blue\nexit\n"))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	config := &mqlFrrConfig{MqlRuntime: runtime, __id: "frr.conf"}
	config.cfg = cfg
	interfaces, err := config.interfaces(nil)
	require.NoError(t, err)
	require.Len(t, interfaces, 2)
	red := interfaces[0].(*mqlFrrConfigInterface)
	blue := interfaces[1].(*mqlFrrConfigInterface)
	assert.NotEqual(t, red.MqlID(), blue.MqlID())
	assert.Equal(t, "RED", red.GetVrf().Data)
	assert.Equal(t, "BLUE", blue.GetVrf().Data)
	assert.Equal(t, "red", red.GetDescription().Data)
	assert.Equal(t, "blue", blue.GetDescription().Data)
}
