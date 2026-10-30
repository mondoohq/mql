// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resourceclient

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmware/govmomi"
	"go.mondoo.com/mql/providers/vsphere/connection/vsimulator"
)

func newClient(host string, user string, password string) (*Client, error) {
	u, err := url.Parse("https://" + host + "/sdk")
	if err != nil {
		return nil, err
	}
	u.User = url.UserPassword(user, password)

	ctx := context.Background()
	vc, err := govmomi.NewClient(ctx, u, true)
	if err != nil {
		return nil, err
	}

	return New(vc), nil
}

func TestVSphere(t *testing.T) {
	vs, err := vsimulator.New()
	require.NoError(t, err)
	defer vs.Close()

	client, err := newClient(vs.Server.URL.Hostname()+":"+vs.Server.URL.Port(), vsimulator.Username, vsimulator.Password)
	require.NoError(t, err)

	// fetch datacenters
	dcs, err := client.ListDatacenters()
	require.NoError(t, err)
	assert.Equal(t, 1, len(dcs))

	// fetch license
	lcs, err := client.ListLicenses()
	require.NoError(t, err)
	assert.Equal(t, 1, len(lcs))

	for _, dc := range dcs {
		// list hosts
		hosts, err := client.ListHosts(dc, nil)
		require.NoError(t, err)
		assert.Equal(t, 4, len(hosts))

		// list vms
		vms, err := client.ListVirtualMachines(dc)
		require.NoError(t, err)
		assert.Equal(t, 4, len(vms))

		// fetch cluster
		clusters, err := client.ListClusters(dc)
		require.NoError(t, err)
		assert.Equal(t, 1, len(clusters))

		cluster := clusters[0]
		props, err := client.ClusterProperties(cluster)
		require.NoError(t, err)
		fmt.Printf("%v\n", props)

		hosts, err = client.ListHosts(dc, cluster)
		require.NoError(t, err)
		assert.Equal(t, 3, len(hosts))
	}
}

//// TODO: we need to figure out how we can test ESXi via the simulator
//func TestESXi(t *testing.T) {
//	vs, err := vsimulator.New()
//	require.NoError(t, err)
//	defer vs.Close()
//
//	client, err := newClient(vs.Server.URL.Hostname()+":"+vs.Server.URL.Port(), vsimulator.Username, vsimulator.Password)
//	require.NoError(t, err)
//
//	// fetch datacenters
//	dcs, err := client.ListDatacenters()
//	require.NoError(t, err)
//	assert.Equal(t, 1, len(dcs))
//
//	// fetch cluster
//	clusters, err := client.ListClusters(dcs[0])
//	require.NoError(t, err)
//	assert.Equal(t, 1, len(clusters))
//
//	// list hosts
//	hosts, err := client.ListHosts(dcs[0], nil)
//	require.NoError(t, err)
//	assert.Equal(t, 4, len(hosts))
//
//	// test the first host
//	// e := Esxi{c: client.Client, host: hosts[0]}
//
//	// nics, err := e.Vmknics()
//	// require.NoError(t, err)
//	// assert.Equal(t, 1, len(nics))
//
//	// adapters, err := e.Adapters()
//	// require.NoError(t, err)
//	// assert.Equal(t, 1, len(adapters))
//
//	// pauseParams, err := e.ListNicPauseParams()
//	// require.NoError(t, err)
//	// assert.Equal(t, 1, len(pauseParams))
//
//	// nicDetails, err := e.ListNicDetails("vmnic0")
//	// require.NoError(t, err)
//	// assert.Equal(t, 1, len(nicDetails))
//
//	// list packages
//	// vibs, err := e.Vibs()
//	// require.NoError(t, err)
//	// assert.Equal(t, 136, len(vibs))
//
//	// 	// package acceptance level
//	// 	acceptance, err := e.SoftwareAcceptance()
//	// 	require.NoError(t, err)
//	// 	assert.Equal(t, "PartnerSupported", acceptance)
//
//	// 	// list kernel modules
//	// 	modules, err := e.KernelModules()
//	// 	require.NoError(t, err)
//	// 	assert.Equal(t, 98, len(modules))
//
//	// 	// list advanced settings
//	// 	settings, err := e.AdvancedSettings()
//	// 	require.NoError(t, err)
//	// 	// TODO: the ui displays 1043, we need to find the difference
//	// 	assert.Equal(t, 1069, len(settings))
//
//	// 	// all host options (overlaps with the advanced settings)
//	// 	hostoptions, err := HostOptions(hosts[0])
//	// 	require.NoError(t, err)
//	// 	assert.Equal(t, 1045, len(hostoptions))
//
//	// 	// get snmp settings
//	// 	snmpSettings, err := e.Snmp()
//	// 	require.NoError(t, err)
//	// 	assert.Equal(t, 10, len(snmpSettings))
//}
