// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// stormControlConfig reproduces the statement shapes printed in Arista's EOS
// user guide: `storm-control broadcast level 1` from the
// `show running-config interface` example, the `level 50` / `level 65` pair
// from the `show active` example, and the `level pps` and `cpu level pps`
// forms from the storm-control configuration examples.
const stormControlConfig = `!
interface Ethernet1
   switchport access vlan 33
   storm-control broadcast level 1
   spanning-tree portfast
!
interface Ethernet20
   storm-control broadcast level 50
   storm-control multicast level 65
!
interface Ethernet21
   storm-control unknown-unicast level pps 5000000
   storm-control broadcast cpu level pps 1000
!
interface Ethernet22
   storm-control all level 75.25
!
interface Ethernet23
   description no storm control here
!
`

func TestParseStormControl(t *testing.T) {
	got := ParseStormControl(stormControlConfig)
	assert.Len(t, got, 6)

	assert.Equal(t, StormControlSetting{
		Interface: "Ethernet1", TrafficClass: "broadcast", Level: 1, Unit: "percent",
	}, got[0])

	assert.Equal(t, StormControlSetting{
		Interface: "Ethernet20", TrafficClass: "broadcast", Level: 50, Unit: "percent",
	}, got[1])
	assert.Equal(t, StormControlSetting{
		Interface: "Ethernet20", TrafficClass: "multicast", Level: 65, Unit: "percent",
	}, got[2])

	// A packet-per-second ceiling is a count, not a percentage. Reading the
	// unit keyword as part of the number, or ignoring it, would report
	// 5000000 percent.
	assert.Equal(t, StormControlSetting{
		Interface: "Ethernet21", TrafficClass: "unknown-unicast", Level: 5000000, Unit: "pps",
	}, got[3])

	// The `cpu` qualifier sits between the class and `level`, and bounds
	// what reaches the control plane rather than the port.
	assert.Equal(t, StormControlSetting{
		Interface: "Ethernet21", TrafficClass: "broadcast", Level: 1000, Unit: "pps", Cpu: true,
	}, got[4])

	// EOS accepts two decimal places on a percentage; truncating to an int
	// would round a threshold up or down silently.
	assert.Equal(t, StormControlSetting{
		Interface: "Ethernet22", TrafficClass: "all", Level: 75.25, Unit: "percent",
	}, got[5])
}

// The absent case. EOS has no implicit ceiling, so an interface with no
// statement must be absent from the result rather than reported at 100,
// which would read as a configured limit.
func TestParseStormControl_UnconfiguredInterfaceIsAbsent(t *testing.T) {
	got := ParseStormControl(stormControlConfig)
	for _, s := range got {
		assert.NotEqual(t, "Ethernet23", s.Interface)
	}
}

func TestParseStormControl_NegatedStatementIsNotACeiling(t *testing.T) {
	cfg := `interface Ethernet2
   no storm-control multicast
   default storm-control broadcast
!
`
	assert.Empty(t, ParseStormControl(cfg))
}

func TestParseStormControl_NoInterfaces(t *testing.T) {
	assert.Empty(t, ParseStormControl("hostname switch\n!\n"))
}

func TestParseStormControl_MalformedStatementIsSkipped(t *testing.T) {
	cfg := `interface Ethernet3
   storm-control broadcast level
   storm-control bogusclass level 5
   storm-control multicast level abc
   storm-control broadcast level 25
!
`
	got := ParseStormControl(cfg)
	assert.Len(t, got, 1)
	assert.Equal(t, "broadcast", got[0].TrafficClass)
	assert.Equal(t, float64(25), got[0].Level)
}
