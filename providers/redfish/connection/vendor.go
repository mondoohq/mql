// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strings"
)

// Vendor identifies the hardware vendor behind a Redfish service and the
// platform name we report for it. Standard Redfish resources are vendor
// neutral; vendor-specific OEM data is surfaced under vendor-namespaced
// resources (redfish.hpe.*, redfish.dell.*).
type Vendor struct {
	// Name is the human-readable vendor name (e.g. "HPE iLO", "Dell iDRAC").
	Name string
	// Platform is the mql platform name (e.g. "bmc-hpe-ilo", "bmc-dell-idrac").
	Platform string
	// match holds lowercase substrings tested against the reported manufacturer.
	match []string
}

// vendors is the detection registry. Adding support for a new vendor is a
// single entry here plus a vendor-namespaced OEM resource; existing entries
// are never modified.
var vendors = []Vendor{
	{Name: "HPE iLO", Platform: "bmc-hpe-ilo", match: []string{"hpe", "hewlett"}},
	{Name: "Dell iDRAC", Platform: "bmc-dell-idrac", match: []string{"dell"}},
	{Name: "Supermicro BMC", Platform: "bmc-supermicro", match: []string{"supermicro", "super micro"}},
}

// genericVendor is the fallback for any Redfish service we don't specifically
// recognize. The full standard schema still works against it.
var genericVendor = Vendor{Name: "Redfish BMC", Platform: "bmc-redfish"}

// DetectVendor matches a reported manufacturer string against the registry.
func DetectVendor(manufacturer string) Vendor {
	m := strings.ToLower(manufacturer)
	for _, v := range vendors {
		for _, sub := range v.match {
			if strings.Contains(m, sub) {
				return v
			}
		}
	}
	return genericVendor
}

// detectVendorFromService inspects the managers and systems of a connected
// service to determine the hardware vendor.
func detectVendorFromService(c *RedfishConnection) Vendor {
	if managers, err := c.Managers(); err == nil {
		for _, m := range managers {
			if m.Manufacturer != "" {
				return DetectVendor(m.Manufacturer)
			}
		}
	}

	if systems, err := c.Systems(); err == nil {
		for _, s := range systems {
			if s.Manufacturer != "" {
				return DetectVendor(s.Manufacturer)
			}
		}
	}

	return genericVendor
}
