// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDrgCompartment(t *testing.T) {
	drg := &mqlOciNetworkDrg{}
	assert.Equal(t, "ocid1.tenancy.oc1..root", drg.drgCompartment("ocid1.tenancy.oc1..root"),
		"a DRG with no recorded compartment falls back to the tenancy")
	drg.setCompartmentID("ocid1.compartment.oc1..child")
	assert.Equal(t, "ocid1.compartment.oc1..child", drg.drgCompartment("ocid1.tenancy.oc1..root"),
		"attachments live in the DRG's compartment, not the tenancy root")
}
