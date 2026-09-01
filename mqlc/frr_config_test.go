// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// The FRR resources exist to answer three questions about a routing node:
// does a BGP session accept routes without a filter, are tenant VRFs
// separated, and do route targets leak between VRFs. These pin one read of
// every field plus those queries, so a rename in os.lr fails here rather
// than in a downstream policy.
func TestFrrConfigQueriesCompile(t *testing.T) {
	schema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "core"}).
		Add(testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "os"}))

	queries := []string{
		// the posture questions these resources exist to answer
		`frr.config.bgp.all(neighbors.all(isPeerGroup || prefixListsIn.length > 0 || routeMapsIn.length > 0))`,
		`frr.config.vrfs.where(name == /^t-/).all(importedVrfs == [])`,
		`frr.config.vrfs.all(routeTargetsImport == routeTargetsExport)`,
		`frr.config.bgp.where(vrf == "").all(ebgpRequiresPolicy == true)`,

		// root resource and file discovery
		`frr.version`,
		`frr.config.file.path`,
		`frr.config { hostname version defaults integratedVtyshConfig }`,
		`frr.config("/etc/cra/frr.conf").hostname`,

		// bgp
		`frr.config.bgp { asn vrf routerId clusterId ebgpRequiresPolicy defaultIpv4Unicast params file startLine raw }`,
		`frr.config.bgp { neighbors { name isInterface isPeerGroup peerGroup remoteAs remoteAsn localAsn } }`,
		`frr.config.bgp { neighbors { description updateSource listenRange bfd shutdown passwordSet } }`,
		`frr.config.bgp { neighbors { ttlSecurityHops keepaliveTime holdTime params file line } }`,
		`frr.config.bgp { neighbors { activatedAddressFamilies routeMapsIn routeMapsOut prefixListsIn prefixListsOut filterListsIn filterListsOut } }`,
		`frr.config.bgp { neighbors { addressFamilies { afi safi activate routeMapIn routeMapOut prefixListIn prefixListOut } } }`,
		`frr.config.bgp { neighbors { addressFamilies { filterListIn filterListOut maximumPrefix routeReflectorClient allowasIn nextHopSelf softReconfiguration defaultOriginate removePrivateAs } } }`,
		`frr.config.bgp { addressFamilies { afi safi networks redistribute importVrfs importVrfRouteMap } }`,
		`frr.config.bgp { addressFamilies { routeTargetsImport routeTargetsExport advertise advertiseAllVni vnis params file startLine raw } }`,

		// vrfs, interfaces, filters
		`frr.config.vrfs { name vni staticRoutes routerAsn routeTargetsImport routeTargetsExport importedVrfs params file startLine raw }`,
		`frr.config.interfaces { name vrf description ipAddresses ipv6Addresses shutdown pbrPolicy params file startLine raw }`,
		`frr.config.prefixLists { name afi entries file line }`,
		`frr.config.routeMaps { name file line entries { name action sequence match set call onMatch file startLine raw } }`,

		// raw views
		`frr.config.blocks { type name args file startLine endLine directives raw }`,
		`frr.config.blocks { blocks { type name } }`,
		`frr.config.directives`,

		// vtysh
		`frr.vtysh.config { hostname integratedConfig users directives params }`,
		`frr.vtysh.config("/etc/frr/vtysh.conf").integratedConfig`,
	}

	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			_, err := mqlc.Compile(query, nil, mqlc.NewConfig(schema, features))
			require.NoError(t, err, "query %q should compile", query)
		})
	}
}

// The runtime resources read the router as it is running, so a policy over
// them tests the moment of the scan. These pin one read of every field plus
// the questions the resources exist to answer.
func TestFrrRuntimeQueriesCompile(t *testing.T) {
	schema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "core"}).
		Add(testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "os"}))

	queries := []string{
		// the posture questions these resources exist to answer
		`frr.bgpNeighbors.all(established)`,
		`frr.bgpNeighbors.all(addressFamilies.all(prefixesFilteredKnown && prefixesFiltered == 0))`,
		`frr.vrfs.all(inFrr && inKernel)`,
		`frr.vrfs.where(name == /^t-/).all(up)`,
		`frr.evpnVnis.where(type == "L3").all(state == "Up")`,
		`frr.routingRules.where(l3mdev == false && tableId > 1000).length == 0`,
		`frr.routeTable("t-blue").truncated == false`,
		`frr.routeTable("t-blue").entries.where(protocol == "bgp").length > 0`,

		// vrfs
		`frr.vrfs { name id tableId tableName ifindex mtu operState up inFrr inKernel }`,
		`frr.vrfs { rules { priority table } }`,
		`frr.vrfs { bgpNeighbors { name state } }`,
		`frr.vrfs { routes { vrf afi limit total truncated } }`,

		// routes
		`frr.routeTable { vrf afi limit total truncated }`,
		`frr.routeTable("cluster", "ipv6") { total }`,
		`frr.routeTable("cluster", "ipv4", 100) { total }`,
		`frr.routeTable.entries { prefix prefixLength protocol vrf table selected installed distance metric uptime nexthops }`,

		// bgp sessions
		`frr.bgpNeighbors { name vrf remoteAsn localAsn hostname state established uptimeMsec }`,
		`frr.bgpNeighbors { messagesReceived messagesSent connectionsEstablished connectionsDropped idType }`,
		`frr.bgpNeighbors { addressFamilies { afi safi prefixesReceived prefixesSent prefixesAccepted } }`,
		`frr.bgpNeighbors { addressFamilies { prefixesFiltered prefixesFilteredKnown routeMapIn routeMapOut prefixListIn prefixListOut details } }`,

		// evpn
		`frr.evpnVnis { vni type vrf vxlanInterface sviInterface routerMac state macCount arpNdCount remoteVtepCount remoteVteps details }`,

		// policy routing
		`frr.routingRules { priority source dest table tableId inputInterface outputInterface }`,
		`frr.routingRules { l3mdev action protocol fwmark invert suppressPrefixLength }`,

		// the kernel route view keeps its own resource, now with the fields
		// that a VRF host needs
		`network.routes.where(table == "main") { destination gateway protocol scope metric source type device }`,
	}

	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			_, err := mqlc.Compile(query, nil, mqlc.NewConfig(schema, features))
			require.NoError(t, err, "query %q should compile", query)
		})
	}
}
