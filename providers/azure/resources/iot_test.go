// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
