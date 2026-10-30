// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector/crowdstrike"
	"go.mondoo.com/mql/providers/os/detector/defender"
	"go.mondoo.com/mql/providers/os/resources/edr"
	"go.mondoo.com/mql/utils/syncx"
)

func TestDefenderMode(t *testing.T) {
	// The strings are the values Get-MpComputerStatus reports for
	// AMRunningMode. Passive and EDR-block both leave amServiceEnabled and
	// antivirusEnabled reading true while Defender remediates little or
	// nothing, which is the distinction this mapping exists to preserve.
	tests := []struct {
		amRunningMode string
		want          string
	}{
		{"Normal", "active"},
		{"Passive Mode", "passive"},
		{"SxS Passive Mode", "passive"},
		{"EDR Block Mode", "blockOnly"},
		{"Not running", ""},
		{"", ""},
		{"normal", ""},
	}

	for _, tc := range tests {
		t.Run(tc.amRunningMode, func(t *testing.T) {
			assert.Equal(t, tc.want, defenderMode(tc.amRunningMode))
		})
	}
}

func TestPickResources(t *testing.T) {
	all := []any{"a", "b", "c"}

	assert.Equal(t, []any{"a", "c"}, pickResources(all, []int{0, 2}))
	assert.Equal(t, []any{}, pickResources(all, nil))
	assert.Equal(t, []any{}, pickResources(nil, []int{0, 1}),
		"an index into a list that could not be read must not panic")
	assert.Equal(t, []any{"b"}, pickResources(all, []int{-1, 1, 99}),
		"out-of-range indices are dropped rather than crashing the scan")
}

func TestCatalogOnlyCostsWhatThePlatformNeeds(t *testing.T) {
	// Listing processes and reading the system extension database are not
	// free, so they are only fetched where a catalog entry reads them. These
	// assertions fail if a future entry adds that cost to a platform that
	// cannot use it.
	assert.False(t, catalogNeedsProcesses(edr.PlatformWindows),
		"no Windows agent is recognized by a process, so no scan should list them")
	assert.False(t, catalogNeedsProcesses(edr.PlatformLinux))
	assert.True(t, catalogNeedsProcesses(edr.PlatformMacOS),
		"Malwarebytes on macOS is recognized by its process")

	assert.False(t, catalogNeedsSystemExtensions(edr.PlatformWindows),
		"system extensions exist only on macOS")
	assert.False(t, catalogNeedsSystemExtensions(edr.PlatformLinux))
	assert.True(t, catalogNeedsSystemExtensions(edr.PlatformMacOS))

	assert.False(t, catalogNeedsProcesses("freebsd"))
	assert.False(t, catalogNeedsSystemExtensions("freebsd"))
}

func TestEnrichFalconIdentity(t *testing.T) {
	newEdr := func(t *testing.T, labels map[string]string) *mqlEdr {
		conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{Name: "ubuntu", Labels: labels}})
		require.NoError(t, err)
		return &mqlEdr{MqlRuntime: &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}}
	}
	falcon := edr.Detection{Product: edr.Product{ID: "crowdstrike-falcon"}}

	t.Run("falcon reports agent and customer IDs from the platform", func(t *testing.T) {
		args := map[string]*llx.RawData{}
		newEdr(t, map[string]string{
			crowdstrike.LabelAID: "0123456789abcdef0123456789abcdef",
			crowdstrike.LabelCID: "fedcba9876543210fedcba9876543210",
		}).enrich(falcon, args)
		assert.Equal(t, "0123456789abcdef0123456789abcdef", args["agentId"].Value)
		assert.Equal(t, "fedcba9876543210fedcba9876543210", args["tenantId"].Value)
	})

	t.Run("falcon that is not registered yet reports only its customer ID", func(t *testing.T) {
		args := map[string]*llx.RawData{}
		newEdr(t, map[string]string{crowdstrike.LabelCID: "fedcba9876543210fedcba9876543210"}).enrich(falcon, args)
		assert.Nil(t, args["agentId"].Value)
		assert.Equal(t, "fedcba9876543210fedcba9876543210", args["tenantId"].Value)
	})

	t.Run("falcon reads the sensor when the platform carries no labels", func(t *testing.T) {
		falconctl := "/opt/CrowdStrike/falconctl"
		conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"debian", "linux", "unix", "os"},
		}}, mock.WithData(&mock.TomlData{
			Files: map[string]*mock.MockFileData{falconctl: {Path: falconctl, StatData: mock.FileInfo{Mode: 0o750}}},
			Commands: map[string]*mock.Command{
				falconctl + " -g --aid --cid": {Stdout: `cid="0123456789ABCDEF0123456789ABCDEF-E2", aid="4d7f5b8b9e0b4c2a8d1e2f3a4b5c6d7e".` + "\n"},
			},
		}))
		require.NoError(t, err)
		e := &mqlEdr{MqlRuntime: &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}}
		args := map[string]*llx.RawData{}
		e.enrich(falcon, args)
		assert.Equal(t, "4d7f5b8b9e0b4c2a8d1e2f3a4b5c6d7e", args["agentId"].Value)
		assert.Equal(t, "0123456789abcdef0123456789abcdef", args["tenantId"].Value, "lowercase, checksum suffix stripped")
	})

	t.Run("falcon without detected IDs is null", func(t *testing.T) {
		args := map[string]*llx.RawData{}
		newEdr(t, nil).enrich(falcon, args)
		assert.Nil(t, args["agentId"].Value)
		assert.Nil(t, args["tenantId"].Value)
	})

	t.Run("other agents are null", func(t *testing.T) {
		args := map[string]*llx.RawData{}
		newEdr(t, map[string]string{crowdstrike.LabelAID: "0123456789abcdef0123456789abcdef"}).
			enrich(edr.Detection{Product: edr.Product{ID: "sentinelone"}}, args)
		assert.Nil(t, args["agentId"].Value)
		assert.Nil(t, args["tenantId"].Value)
	})
}

func TestApplyDefenderIdentity(t *testing.T) {
	t.Run("onboarded sensor reports machine and organization IDs", func(t *testing.T) {
		args := map[string]*llx.RawData{"agentId": llx.NilData, "tenantId": llx.NilData}
		applyDefenderIdentity(&defender.Identity{
			MachineID: "0123456789abcdef0123456789abcdef01234567",
			OrgID:     "01234567-89ab-cdef-0123-456789abcdef",
		}, args)
		assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", args["agentId"].Value)
		assert.Equal(t, "01234567-89ab-cdef-0123-456789abcdef", args["tenantId"].Value)
	})

	t.Run("no organization leaves tenantId null", func(t *testing.T) {
		args := map[string]*llx.RawData{"agentId": llx.NilData, "tenantId": llx.NilData}
		applyDefenderIdentity(&defender.Identity{MachineID: "0123456789abcdef0123456789abcdef01234567"}, args)
		assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", args["agentId"].Value)
		assert.Nil(t, args["tenantId"].Value)
	})

	t.Run("not onboarded leaves both null", func(t *testing.T) {
		args := map[string]*llx.RawData{"agentId": llx.NilData, "tenantId": llx.NilData}
		applyDefenderIdentity(nil, args)
		assert.Nil(t, args["agentId"].Value)
		assert.Nil(t, args["tenantId"].Value)
	})
}
