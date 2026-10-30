// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"strconv"
	"strings"
)

// StormControlSetting is one `storm-control` statement on one interface: a
// ceiling on inbound flooded traffic of a given class.
//
//	interface Ethernet1
//	   storm-control broadcast level 1
//	   storm-control multicast level 65
//	   storm-control unknown-unicast level pps 5000000
//
// Storm control is the only per-port rate control against a broadcast or
// flood denial of service that originates inside the Layer 2 domain, where
// no routed control can see it.
//
// An interface may carry one statement per class. EOS documents that an
// `all` statement overrides the broadcast and multicast thresholds on the
// same interface.
type StormControlSetting struct {
	// Interface is the parent interface name, for example "Ethernet1".
	Interface string
	// TrafficClass is the class the ceiling applies to: "broadcast",
	// "multicast", "unknown-unicast", or "all".
	TrafficClass string
	// Level is the threshold. It is a percentage of port capacity when Unit
	// is "percent" (EOS accepts two decimal places), and a packet count
	// when Unit is "pps".
	Level float64
	// Unit is "percent" or "pps". A statement written without a unit
	// keyword is a percentage, which is the form EOS documents first.
	Unit string
	// Cpu is true for the `storm-control <class> cpu level ...` form, which
	// bounds what reaches the control plane rather than what crosses the
	// port.
	Cpu bool
}

// stormControlClasses is the closed set of traffic classes the interface-level
// command accepts. Matching against it keeps an unrelated `storm-control`
// form from being read as a class.
var stormControlClasses = map[string]bool{
	"all":             true,
	"broadcast":       true,
	"multicast":       true,
	"unknown-unicast": true,
}

// ParseStormControl returns every `storm-control` statement configured on an
// interface.
//
// Interfaces with no storm-control statement are absent from the result
// rather than being reported at some default ceiling: EOS has no implicit
// threshold, and `no storm-control` removes the statement from the
// running-config entirely, so an unconfigured port has no limit at all. A
// synthesized default of 100 would read as a configured ceiling and hide
// exactly the ports worth finding.
func ParseStormControl(runningConfig string) []StormControlSetting {
	res := []StormControlSetting{}

	eachInterfaceBlock(runningConfig, func(ifaceName, block string) {
		scanner := bufio.NewScanner(strings.NewReader(block))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "!" || line == "end" {
				break
			}
			// A negated statement removes the ceiling, so it must not
			// register as one.
			if strings.HasPrefix(line, "no ") || strings.HasPrefix(line, "default ") {
				continue
			}
			rest, ok := strings.CutPrefix(line, "storm-control ")
			if !ok {
				continue
			}
			if s, ok := parseStormControlStatement(ifaceName, strings.Fields(rest)); ok {
				res = append(res, s)
			}
		}
	})

	return res
}

// parseStormControlStatement reads the tokens after `storm-control` on an
// interface line: the traffic class, an optional `cpu` qualifier, then
// `level` with an optional unit keyword ahead of the number.
func parseStormControlStatement(iface string, fields []string) (StormControlSetting, bool) {
	if len(fields) < 3 || !stormControlClasses[fields[0]] {
		return StormControlSetting{}, false
	}
	s := StormControlSetting{
		Interface:    iface,
		TrafficClass: fields[0],
		Unit:         "percent",
	}
	i := 1

	if fields[i] == "cpu" {
		s.Cpu = true
		i++
	}

	if i >= len(fields) || fields[i] != "level" {
		return StormControlSetting{}, false
	}
	i++

	if i < len(fields) && (fields[i] == "pps" || fields[i] == "percent") {
		s.Unit = fields[i]
		i++
	}

	if i >= len(fields) {
		return StormControlSetting{}, false
	}
	level, err := strconv.ParseFloat(fields[i], 64)
	if err != nil {
		return StormControlSetting{}, false
	}
	s.Level = level

	return s, true
}
