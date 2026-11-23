// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub/v2"
	"github.com/stretchr/testify/assert"
)

func TestIotHubAccessRights(t *testing.T) {
	// Synthetic: ARM's comma-separated rights enum, with and without spaces.
	assert.Equal(t, []any{}, iotHubAccessRights(nil))
	assert.Equal(t, []any{"RegistryRead"}, iotHubAccessRights(ptr(armiothub.AccessRightsRegistryRead)))
	assert.Equal(t,
		[]any{"RegistryWrite", "ServiceConnect", "DeviceConnect"},
		iotHubAccessRights(ptr(armiothub.AccessRightsRegistryWriteServiceConnectDeviceConnect)))
	assert.Equal(t, []any{"RegistryRead", "ServiceConnect"}, iotHubAccessRights(ptr(armiothub.AccessRights("RegistryRead,ServiceConnect,"))))
}

func TestIotHubIPFilterRuleID(t *testing.T) {
	// Synthetic: hub ID and rule names shaped like the IoT Hub ARM API returns them.
	hub := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Devices/IotHubs/hub1"
	named := "allow-office"
	empty := ""
	assert.Equal(t, hub+"/ipFilterRules/allow-office", iotHubIPFilterRuleID(hub, 3, &named))
	// The ID does not move when the rule's position changes.
	assert.Equal(t, iotHubIPFilterRuleID(hub, 0, &named), iotHubIPFilterRuleID(hub, 5, &named))
	assert.Equal(t, hub+"/ipFilterRules/#2", iotHubIPFilterRuleID(hub, 2, nil))
	assert.Equal(t, hub+"/ipFilterRules/#1", iotHubIPFilterRuleID(hub, 1, &empty))
}
