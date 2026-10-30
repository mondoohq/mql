// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vmware/govmomi/simulator/esx"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/vsphere/connection/vsimulator"
)

func newTestService() (*vsimulator.VsphereSimulator, *Service, *plugin.ConnectRes) {
	vs, err := vsimulator.New()
	if err != nil {
		panic(err)
	}

	port, err := strconv.Atoi(vs.Server.URL.Port())
	if err != nil {
		panic(err)
	}

	srv := &Service{
		Service: plugin.NewService(),
	}

	resp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type:     "vsphere",
					Host:     vs.Server.URL.Hostname(),
					Port:     int32(port),
					Insecure: true, // allows self-signed certificates
					Credentials: []*vault.Credential{
						{
							Type:   vault.CredentialType_password,
							User:   vsimulator.Username,
							Secret: []byte(vsimulator.Password),
						},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		panic(err)
	}
	return vs, srv, resp
}

func TestResource_Vsphere(t *testing.T) {
	vs, srv, connRes := newTestService()
	defer vs.Close()

	// check that we get the data via the resources
	t.Run("simulate vsphere.datacenters[0].hosts[0].name", func(t *testing.T) {
		// simulate "vsphere.datacenters[0].hosts[0].name" where we expect "DC0_H0" as result

		// create vsphere resource
		dataResp, err := srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "vsphere",
		})
		require.NoError(t, err)
		resourceId := string(dataResp.Data.Value)

		// fetch datacenters
		dataResp, err = srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "vsphere",
			ResourceId: resourceId,
			Field:      "datacenters",
		})
		require.NoError(t, err)

		// simulator has one datacenter /DC0
		assert.Equal(t, 1, len(dataResp.Data.Array))

		// get datacenter details
		datacenterResourceID := string(dataResp.Data.Array[0].Value)
		dataResp, err = srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "vsphere.datacenter",
			ResourceId: datacenterResourceID,
			Field:      "name",
		})
		require.NoError(t, err)
		assert.Equal(t, "DC0", string(dataResp.Data.Value))

		// get list of hosts
		dataResp, err = srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "vsphere.datacenter",
			ResourceId: datacenterResourceID,
			Field:      "hosts",
		})
		require.NoError(t, err)
		assert.Equal(t, 4, len(dataResp.Data.Array))

		// we pick the first host on the first datacenter /DC0/host/DC0_H0/DC0_H0
		hostResourceID := string(dataResp.Data.Array[0].Value)
		dataResp, err = srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "vsphere.host",
			ResourceId: hostResourceID,
			Field:      "name",
		})
		require.NoError(t, err)
		assert.Equal(t, "DC0_H0", string(dataResp.Data.Value))
	})
}

// TestVmAndDvsHardeningFields resolves the VM and distributed switch hardening
// fields through the runtime, proving each value lands on the field of the
// same name. Synthetic (vcsim): the expected values are the simulator's
// defaults.
func TestVmAndDvsHardeningFields(t *testing.T) {
	vs, srv, connRes := newTestService()
	defer vs.Close()

	dcs := rootField(t, srv, connRes.Id, "datacenters")
	require.NotEmpty(t, dcs.Data.Array)
	dcID := string(dcs.Data.Array[0].Value)

	vms := field(t, srv, connRes.Id, "vsphere.datacenter", dcID, "vms")
	require.NotEmpty(t, vms.Data.Array)
	vmID := string(vms.Data.Array[0].Value)
	// vcsim creates every VM at its default hardware version.
	assert.Equal(t, esx.HardwareVersion, string(field(t, srv, connRes.Id, "vsphere.vm", vmID, "hardwareVersion").Data.Value))
	// vcsim VMs carry no serial ports, so the list resolves empty, not null.
	serial := field(t, srv, connRes.Id, "vsphere.vm", vmID, "serialPorts")
	require.NotNil(t, serial.Data)
	assert.Empty(t, serial.Data.Array)

	// vcsim creates an uplink port group per switch, bound early and trunking
	// every VLAN.
	pgs := field(t, srv, connRes.Id, "vsphere.datacenter", dcID, "distributedPortGroups")
	var trunks [][]string
	for _, pg := range pgs.Data.Array {
		id := string(pg.Value)
		if string(field(t, srv, connRes.Id, "vsphere.vswitch.portgroup", id, "portBinding").Data.Value) != "earlyBinding" {
			continue
		}
		ranges := []string{}
		for _, r := range field(t, srv, connRes.Id, "vsphere.vswitch.portgroup", id, "vlanTrunkRanges").Data.Array {
			ranges = append(ranges, string(r.Value))
		}
		trunks = append(trunks, ranges)
	}
	assert.Contains(t, trunks, []string{"0-4094"})

	switches := field(t, srv, connRes.Id, "vsphere.datacenter", dcID, "distributedSwitches")
	require.NotEmpty(t, switches.Data.Array)
	dvsID := string(switches.Data.Array[0].Value)
	// vcsim keeps no health check configuration, so the switch reports false.
	hc := field(t, srv, connRes.Id, "vsphere.vswitch.dvs", dvsID, "healthCheckEnabled")
	require.NotNil(t, hc.Data)
	assert.Equal(t, []byte{0}, hc.Data.Value)
}

func TestVsphereDiscovery(t *testing.T) {
	vs, err := vsimulator.New()
	require.NoError(t, err)

	port, err := strconv.Atoi(vs.Server.URL.Port())
	require.NoError(t, err)

	srv := &Service{
		Service: plugin.NewService(),
	}

	resp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type:     "vsphere",
					Host:     vs.Server.URL.Hostname(),
					Port:     int32(port),
					Insecure: true, // allows self-signed certificates
					Discover: &inventory.Discovery{
						Targets: []string{"api"},
					},
					Credentials: []*vault.Credential{
						{
							Type:   vault.CredentialType_password,
							User:   vsimulator.Username,
							Secret: []byte(vsimulator.Password),
						},
					},
				},
			},
		},
	}, nil)
	require.NoError(t, err)
	assert.NotNil(t, resp.Asset)
	// assert.Equal(t, 8, len(resp.Inventory.Spec.Assets)) // api + esx + vm
}
