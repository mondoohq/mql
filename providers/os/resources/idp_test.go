// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	detwin "go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/utils/syncx"
)

// Membership per device kind is asserted alongside mdm in
// TestMdmAndIdp_DeviceKinds. What follows is idp on its own.

// joined must distinguish "detection ran and found no membership" from "no
// detection ran here". Only the first is a fact; a false for the second claims
// the device belongs to no identity provider on the strength of a lookup that
// never happened, and a check reading it would clear an Entra-joined device.
func TestIdpResultSet_UndetectedIsNull(t *testing.T) {
	null := plugin.StateIsSet | plugin.StateIsNull
	newIdp := func() *mqlIdp {
		return &mqlIdp{MqlRuntime: &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}}
	}

	t.Run("no detection ran", func(t *testing.T) {
		i := newIdp()
		require.NoError(t, idpResult{}.set(i))
		assert.Equal(t, null, i.Joined.State, "joined is null, not false")
		assert.Equal(t, null, i.Entra.State)
	})

	t.Run("detection ran and found nothing", func(t *testing.T) {
		i := newIdp()
		require.NoError(t, idpResult{detected: true}.set(i))
		assert.Equal(t, plugin.StateIsSet, i.Joined.State, "joined is a measured false")
		assert.False(t, i.Joined.Data)
		assert.Equal(t, null, i.Entra.State)
	})
}

// populate must not report a measured non-membership on a platform whose
// identity is never read. Windows Server is the case that matters: it can be
// Entra-joined, but only client editions are asked for their device
// certificates, so the absent labels there say nothing.
func TestIdpPopulate_PlatformsWithoutDetection(t *testing.T) {
	null := plugin.StateIsSet | plugin.StateIsNull
	// Made-up identifiers.
	labels := map[string]string{
		detwin.LabelEntraDeviceID: "c0ffee00-1234-4abc-8def-0123456789ab",
		detwin.LabelEntraTenantID: "11223344-5566-7788-99aa-bbccddeeff00",
	}

	newIdp := func(t *testing.T, pf *inventory.Platform) *mqlIdp {
		t.Helper()
		conn, err := mock.New(0, &inventory.Asset{Platform: pf})
		require.NoError(t, err)
		return &mqlIdp{MqlRuntime: &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}}
	}
	windows := func(productType, title string, l map[string]string) *inventory.Platform {
		pf := &inventory.Platform{
			Name:   "windows",
			Title:  title,
			Family: []string{"windows"},
			Labels: map[string]string{"windows.mondoo.com/product-type": productType},
		}
		for k, v := range l {
			pf.Labels[k] = v
		}
		return pf
	}

	t.Run("Windows Server is null, not false", func(t *testing.T) {
		i := newIdp(t, windows("3", "Windows Server 2022 Datacenter", labels))
		require.NoError(t, i.populate())
		assert.Equal(t, null, i.Joined.State)
		assert.Equal(t, null, i.Entra.State)
	})

	t.Run("Linux is null, not false", func(t *testing.T) {
		i := newIdp(t, &inventory.Platform{Name: "ubuntu", Family: []string{"linux", "unix", "os"}})
		require.NoError(t, i.populate())
		assert.Equal(t, null, i.Joined.State)
		assert.Equal(t, null, i.Entra.State)
	})

	t.Run("a workstation reports its membership", func(t *testing.T) {
		i := newIdp(t, windows("1", "Windows 11 Enterprise", labels))
		require.NoError(t, i.populate())
		assert.Equal(t, plugin.StateIsSet, i.Joined.State)
		assert.True(t, i.Joined.Data)
		require.NotNil(t, i.Entra.Data)
		assert.Equal(t, labels[detwin.LabelEntraDeviceID], i.Entra.Data.DeviceId.Data)
		assert.Equal(t, labels[detwin.LabelEntraTenantID], i.Entra.Data.TenantId.Data)
	})

	t.Run("a workstation with no identity reports a measured false", func(t *testing.T) {
		i := newIdp(t, windows("1", "Windows 11 Enterprise", nil))
		require.NoError(t, i.populate())
		assert.Equal(t, plugin.StateIsSet, i.Joined.State)
		assert.False(t, i.Joined.Data)
		assert.Equal(t, null, i.Entra.State)
	})
}
