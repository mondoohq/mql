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
