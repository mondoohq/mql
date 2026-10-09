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
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/utils/syncx"
	"google.golang.org/api/dns/v1"
)

func TestManagedZoneDnssecNonExistence(t *testing.T) {
	t.Run("nil config returns empty", func(t *testing.T) {
		assert.Equal(t, "", managedZoneDnssecNonExistence(nil))
	})
	t.Run("value is returned", func(t *testing.T) {
		assert.Equal(t, "nsec3", managedZoneDnssecNonExistence(&dns.ManagedZoneDnsSecConfig{NonExistence: "nsec3"}))
	})
}

// runtimeWithManagedZones is a runtime for an asset with these platform ids,
// whose project's DNS service has already listed two zones: "testzone" (id
// 1111) and "otherzone" (id 2222).
func runtimeWithManagedZones(t *testing.T, platformIds ...string) (*plugin.Runtime, []any) {
	t.Helper()
	conn, err := connection.NewGcpConnection(1, &inventory.Asset{PlatformIds: platformIds}, &inventory.Config{
		Type:    "gcp",
		Options: map[string]string{"project-id": testProjectId},
	})
	require.NoError(t, err)
	runtime := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &testCallbacks{},
	}

	svcRes, err := CreateResource(runtime, "gcp.project.dnsService", map[string]*llx.RawData{
		"projectId": llx.StringData(testProjectId),
	})
	require.NoError(t, err)
	zones := []any{}
	for _, z := range []struct{ id, name string }{{"1111", "testzone"}, {"2222", "otherzone"}} {
		zone, err := CreateResource(runtime, "gcp.project.dnsService.managedzone", map[string]*llx.RawData{
			"id":        llx.StringData(z.id),
			"name":      llx.StringData(z.name),
			"projectId": llx.StringData(testProjectId),
		})
		require.NoError(t, err)
		zones = append(zones, zone)
	}
	svcRes.(*mqlGcpProjectDnsService).ManagedZones = plugin.TValue[[]any]{Data: zones, State: plugin.StateIsSet}
	return runtime, zones
}

func TestInitManagedZone(t *testing.T) {
	// Discovery ends a zone asset's platform id with the zone's numeric id.
	t.Run("discovered zone asset resolves by its platform id", func(t *testing.T) {
		runtime, zones := runtimeWithManagedZones(t,
			connection.NewResourcePlatformID("cloud-dns", testProjectId, "global", "zone", "2222"))

		_, res, err := initGcpProjectDnsServiceManagedzone(runtime, map[string]*llx.RawData{})
		require.NoError(t, err)
		assert.Same(t, zones[1], res)
	})

	t.Run("explicit name resolves by name", func(t *testing.T) {
		runtime, zones := runtimeWithManagedZones(t)

		_, res, err := initGcpProjectDnsServiceManagedzone(runtime, map[string]*llx.RawData{
			"name":      llx.StringData("otherzone"),
			"projectId": llx.StringData(testProjectId),
		})
		require.NoError(t, err)
		assert.Same(t, zones[1], res)
	})

	t.Run("unknown zone is an error", func(t *testing.T) {
		runtime, _ := runtimeWithManagedZones(t,
			connection.NewResourcePlatformID("cloud-dns", testProjectId, "global", "zone", "9999"))

		_, res, err := initGcpProjectDnsServiceManagedzone(runtime, map[string]*llx.RawData{})
		require.Error(t, err)
		assert.Nil(t, res)
	})
}
