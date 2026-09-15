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
