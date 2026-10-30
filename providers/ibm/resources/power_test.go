// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
)

func TestPowerInstanceArgs(t *testing.T) {
	id, name, procs := "pvm-1", "aix-1", 0.5
	args := powerInstanceArgs(&models.PVMInstanceReference{
		PvmInstanceID: &id,
		ServerName:    &name,
		Crn:           "crn:v1:bluemix:public:power-iaas:wdc06:a/acc:ws::pvm-instance:pvm-1",
		Processors:    &procs,
		Networks: []*models.PVMInstanceNetwork{
			{IPAddress: "10.0.0.5", ExternalIP: "203.0.113.9", NetworkID: "n-1"},
			{IPAddress: "10.1.0.5", NetworkID: "n-2"},
			nil,
		},
	})
	assert.Equal(t, []any{"10.0.0.5", "10.1.0.5"}, args["ipAddresses"].Value)
	assert.Equal(t, []any{"203.0.113.9"}, args["externalIps"].Value)
	assert.Equal(t, 0.5, args["processors"].Value)
	// A zero creation date is absent, not year 1.
	assert.Nil(t, args["createdAt"].Value)
}

func TestPowerTime(t *testing.T) {
	assert.Nil(t, powerTime(strfmt.DateTime{}).Value)
}
