// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// data decodes a JSON-RPC error's data the way the eAPI client does.
func data(t *testing.T, s string) any {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(s), &v))
	return v
}

func TestCommandMessages_JSON(t *testing.T) {
	// The `enable` that precedes the command succeeds; the command fails.
	d := data(t, `[{}, {"errors": ["There seem to be no power supplies connected."]}]`)
	assert.Equal(t, []string{"There seem to be no power supplies connected."}, commandMessages(d))
}

func TestCommandMessages_Text(t *testing.T) {
	d := data(t, `[{"output": ""}, {"output": "% Error displaying flash:/startup-config (No such file or directory)\n"}]`)
	assert.Equal(t, []string{"% Error displaying flash:/startup-config (No such file or directory)"}, commandMessages(d))
}

func TestCommandMessages_NoData(t *testing.T) {
	assert.Empty(t, commandMessages(nil))
	assert.Empty(t, commandMessages("not a list"))
}

// result parses a command result the way the eAPI client does, numbers as float64.
func result(t *testing.T, s string) map[string]any {
	t.Helper()
	var v map[string]any
	require.NoError(t, json.Unmarshal([]byte(s), &v))
	return v
}

func TestDecodeResult(t *testing.T) {
	// Synthetic: field names from the EOS eAPI schema for `show vrrp all`; no target showed these values.
	res := result(t, `{"virtualRouters": [{"interface": "Vlan10", "groupId": 10, "priority": 110,
		"preempt": true, "groupState": "master", "advertisementInterval": 1.0, "skewTime": 0.57,
		"virtualIps": ["10.0.10.1"]}]}`)
	var out showVrrp
	require.NoError(t, decodeResult("show vrrp all", res, &out))
	require.Len(t, out.VirtualRouters, 1)
	g := out.VirtualRouters[0]
	assert.Equal(t, "Vlan10", g.Interface)
	assert.Equal(t, int64(10), g.GroupId)
	assert.Equal(t, int64(110), g.Priority)
	assert.True(t, g.Preempt)
	assert.Equal(t, "master", g.State)
	assert.Equal(t, 0.57, g.SkewTime)
	assert.Equal(t, []string{"10.0.10.1"}, g.VirtualIps)

	// Synthetic: nested maps of structs, as in `show system environment power`.
	res = result(t, `{"powerSupplies": {"1": {"state": "ok", "capacity": 500,
		"fans": {"FanP1/1": {"status": "ok", "speed": 30}}}}}`)
	var power showEnvironmentPower
	require.NoError(t, decodeResult("show system environment power", res, &power))
	assert.Equal(t, 500, power.PowerSupplies["1"].Capacity)
	assert.Equal(t, 30, power.PowerSupplies["1"].Fans["FanP1/1"].Speed)
}

func TestDecodeResult_WrongType(t *testing.T) {
	// Synthetic: a string where the schema has a list.
	var out showVrrp
	assert.Error(t, decodeResult("show vrrp all", result(t, `{"virtualRouters": "none"}`), &out))
}

func TestCommandError(t *testing.T) {
	base := errors.New("JSON Error(1000): CLI command 2 of 2 'show vrrp all' failed: invalid command")
	e := &CommandError{
		Command:  "show vrrp all",
		Messages: []string{"% Unavailable command (not supported on this hardware platform)"},
		Err:      base,
	}
	assert.True(t, e.HasMessage("Unavailable command"))
	assert.False(t, e.HasMessage("BGP inactive"))
	assert.ErrorIs(t, e, base)
	assert.Contains(t, e.Error(), "not supported on this hardware platform")

	var target *CommandError
	assert.True(t, errors.As(error(e), &target))
}
