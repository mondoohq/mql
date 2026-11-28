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

func TestFrrISISDistinctAcrossVRFs(t *testing.T) {
	cfg, err := frr.Parse("frr.conf", strings.NewReader("router isis FABRIC vrf RED\n net 49.0001.0000.0000.0001.00\nexit\nrouter isis FABRIC vrf BLUE\n net 49.0002.0000.0000.0002.00\nexit\n"))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	config := &mqlFrrConfig{MqlRuntime: runtime, __id: "frr.conf"}
	config.cfg = cfg
	instances, err := config.isis(nil)
	require.NoError(t, err)
	require.Len(t, instances, 2)
	red := instances[0].(*mqlFrrConfigIsisInstance)
	blue := instances[1].(*mqlFrrConfigIsisInstance)
	assert.NotEqual(t, red.MqlID(), blue.MqlID())
	assert.Equal(t, "RED", red.GetVrf().Data)
	assert.Equal(t, "BLUE", blue.GetVrf().Data)
	assert.NotEqual(t, red.GetNet().Data, blue.GetNet().Data)
}
