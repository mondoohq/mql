// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevices(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/devices", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("devices"))
	})

	result, err := one.devices()
	require.NoError(t, err)
	require.Len(t, result, 1)

	device := result[0].(*mqlCloudflareOneDevice)
	assert.Equal(t, "device-001", device.Id.Data)
	assert.Equal(t, "John's MacBook", device.Name.Data)
	assert.Equal(t, "desktop", device.DeviceType.Data)
	assert.Equal(t, "MacBookPro18,1", device.Model.Data)
	assert.Equal(t, "Apple", device.Manufacturer.Data)
	assert.Equal(t, "C02X12345", device.SerialNumber.Data)
	assert.Equal(t, "14.3.1", device.OsVersion.Data)
	assert.Equal(t, "macOS", device.OsDistroName.Data)
	assert.False(t, device.Deleted.Data)
	assert.False(t, device.LastSeen.Data.IsZero())
	assert.False(t, device.Created.Data.IsZero())
	assert.False(t, device.Updated.Data.IsZero())
}

func TestDevicePostureRules(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/devices/posture", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("device_posture_rules"))
	})

	result, err := one.devicePostureRules()
	require.NoError(t, err)
	require.Len(t, result, 1)

	rule := result[0].(*mqlCloudflareOneDevicePostureRule)
	assert.Equal(t, "posture-001", rule.Id.Data)
	assert.Equal(t, "Require Disk Encryption", rule.Name.Data)
	assert.Equal(t, "disk_encryption", rule.Type.Data)
	assert.Equal(t, "1h", rule.Schedule.Data)
}

func TestDevicePostureIntegrations(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/devices/posture/integration", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("device_posture_integrations"))
	})

	result, err := one.devicePostureIntegrations()
	require.NoError(t, err)
	require.Len(t, result, 1)

	integ := result[0].(*mqlCloudflareOneDevicePostureIntegration)
	assert.Equal(t, "integ-001", integ.Id.Data)
	assert.Equal(t, "CrowdStrike Integration", integ.Name.Data)
	assert.Equal(t, "crowdstrike_s2s", integ.Type.Data)
	assert.Equal(t, "10m", integ.Interval.Data)
}

// TestDevicesPagination asserts the new paginateRaw helper walks every page
// for the Teams Devices endpoint (previously single-page only).
func TestDevicesPagination(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	const totalPages = 4
	var calls atomic.Int32

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/devices", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		body := fmt.Sprintf(`{
			"success": true, "errors": [], "messages": [],
			"result": [{"id": "device-p%d", "name": "Device P%d", "device_type": "desktop", "model": "", "manufacturer": "", "serial_number": "", "mac_address": "", "ip": "", "os_version": "", "os_distro_name": "", "os_distro_revision": "", "version": "", "deleted": false, "created": "2024-01-01T00:00:00Z", "updated": "2024-01-01T00:00:00Z", "last_seen": "2024-01-01T00:00:00Z", "revoked_at": ""}],
			"result_info": {"page": %d, "per_page": 1, "total_pages": %d, "count": 1, "total_count": %d}
		}`, page, page, page, totalPages, totalPages)
		jsonResponse(w, body)
	})

	result, err := one.devices()
	require.NoError(t, err)
	require.Len(t, result, totalPages)
	require.Equal(t, int32(totalPages), calls.Load())

	ids := make([]string, len(result))
	for i, r := range result {
		ids[i] = r.(*mqlCloudflareOneDevice).Id.Data
	}
	assert.Equal(t, []string{"device-p1", "device-p2", "device-p3", "device-p4"}, ids)
}
