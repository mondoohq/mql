// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/arista/resources/eos"
	"go.mondoo.com/mql/types"
)

// TestPowerSupplyDictsSerialize pins the leaf types of the power-supply dict
// rows. llx converts a dict only from JSON-native leaves, and array conversion
// aborts on the first element that fails, so one Go int in a sensor row makes
// the whole tempSensors (or fans) field error out for every power supply. The
// list itself still resolves, so the failure reads as a bad query rather than
// a provider bug.
func TestPowerSupplyDictsSerialize(t *testing.T) {
	ps := eos.PowerSupply{State: "ok", ModelName: "PWR-500AC"}
	ps.TempSensors = map[string]struct {
		Status      string `json:"status"`
		Temperature int    `json:"temperature"`
	}{
		"TempSensor1": {Status: "ok", Temperature: 32},
	}
	ps.Fans = map[string]struct {
		Status string `json:"status"`
		Speed  int    `json:"speed"`
	}{
		"PS1/1": {Status: "ok", Speed: 33},
	}

	for _, tc := range []struct {
		field string
		rows  []any
	}{
		{"tempSensors", powerSupplyTempSensors(ps)},
		{"fans", powerSupplyFans(ps)},
	} {
		res := llx.ArrayData(tc.rows, types.Dict).Result()
		if res.Error != "" {
			t.Errorf("%s does not serialize: %s", tc.field, res.Error)
		}
	}
}
