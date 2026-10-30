// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The OCI SDK's CrossConnectMapping carries a BgpMd5AuthKey secret. Our
// crossConnectMapping projection must never surface it into the dict we expose,
// so this guards against a field being added back by accident.
func TestCrossConnectMappingOmitsSecret(t *testing.T) {
	vlan := 42
	m := crossConnectMapping{
		CrossConnectOrCrossConnectGroupId: "ocid1.crossconnect.oc1.iad.aaaa",
		Vlan:                              &vlan,
		CustomerBgpPeeringIp:              "10.0.0.1/30",
		OracleBgpPeeringIp:                "10.0.0.2/30",
	}

	raw, err := json.Marshal(m)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))

	for key := range decoded {
		assert.NotContains(t, strings.ToLower(key), "md5", "secret field leaked into cross-connect mapping dict")
		assert.NotContains(t, strings.ToLower(key), "authkey", "secret field leaked into cross-connect mapping dict")
	}

	// The safe, attack-path-relevant fields are still present.
	assert.Contains(t, decoded, "crossConnectOrCrossConnectGroupId")
	assert.Contains(t, decoded, "vlan")
	assert.Contains(t, decoded, "oracleBgpPeeringIp")
}
