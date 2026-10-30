// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// The cluster infrastructure resources cover how a Proxmox deployment talks to
// the outside world: who gets notified, where metrics are shipped, which DNS
// provider can issue its certificates, and what corosync membership looks
// like. These pin one read of every new field plus the audit queries the
// resources exist to answer, so a rename in proxmox.lr fails here rather than
// in a downstream policy.
func TestProxmoxClusterInfraQueriesCompile(t *testing.T) {
	schema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "core"}).
		Add(testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "proxmox"}))

	queries := []string{
		// the posture questions these resources exist to answer
		`proxmox.notificationTargets.where(disabled == false).length > 0`,
		`proxmox.webhookEndpoints.all(url == /^https:/)`,
		`proxmox.gotifyEndpoints.all(server == /^https:/)`,
		`proxmox.smtpEndpoints.all(mode != "insecure")`,
		`proxmox.corosync.nodes.all(ring1Address != "")`,

		// notifications
		`proxmox.notificationTargets { name type origin disabled comment }`,
		`proxmox.notificationMatchers { name mode matchSeverity matchField matchCalendar invertMatch targets origin disabled comment }`,
		`proxmox.smtpEndpoints { name server port mode fromAddress author username mailto mailtoUser origin disabled comment }`,
		`proxmox.sendmailEndpoints { name fromAddress author mailto mailtoUser origin disabled comment }`,
		`proxmox.gotifyEndpoints { name server origin disabled comment }`,
		`proxmox.webhookEndpoints { name url method headerNames secretNames origin disabled comment }`,

		// metrics and ACME
		`proxmox.metricServers { id type server port disabled }`,
		`proxmox.acmeAccounts { name }`,
		`proxmox.acmePlugins { plugin type api nodes disabled validationDelay }`,

		// corosync
		`proxmox.corosync { preferredNode totem configDigest qdevice }`,
		`proxmox.corosync.nodes { name nodeId quorumVotes ring0Address ring1Address apiAddress certificateFingerprint }`,

		// device mappings
		`proxmox.pciMappings { id description entries }`,
		`proxmox.usbMappings { id description entries }`,

		// SDN
		`proxmox.sdnControllers { controller type node nodes state asn peers ebgp ebgpMultihop bgpMode loopback isisDomain isisNet isisIfaces }`,
		`proxmox.sdnIpams { ipam type }`,
		`proxmox.sdnDnsServers { dns type }`,

		// the examples printed in providers/proxmox/README.md
		`proxmox.webhookEndpoints.where(url != /^https:/) { name url }`,
		`proxmox.metricServers.where(disabled == false) { id type server port }`,
		`proxmox.corosync.nodes.where(ring1Address == "") { name ring0Address }`,
	}

	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			_, err := mqlc.Compile(query, nil, mqlc.NewConfig(schema, features))
			require.NoError(t, err, "query %q should compile", query)
		})
	}
}
