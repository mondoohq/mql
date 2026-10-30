// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// The Ceph resources are the only part of the proxmox provider that reports a
// subsystem which may not exist at all, so its queries carry an availability
// gate that has to keep compiling alongside the data fields. These pin one
// read of every field plus the audit queries the resources exist to answer,
// so a rename in proxmox.lr fails here rather than in a downstream policy.
func TestProxmoxCephQueriesCompile(t *testing.T) {
	proxmoxSchema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "proxmox"})

	queries := []string{
		// the posture questions these resources exist to answer
		`proxmox.ceph.available == true`,
		`proxmox.ceph.healthStatus == "HEALTH_OK"`,
		`proxmox.ceph.pools.where(type == "replicated").all(minSize >= 2)`,
		`proxmox.ceph.pools.where(type == "replicated").all(size >= 3)`,
		`proxmox.ceph.osds.all(status == "up")`,
		`proxmox.ceph.config.none(name == /^auth_(cluster|service|client)_required$/ && value == "none")`,

		// every field on the root and its collections
		`proxmox.ceph { available healthStatus healthChecks status nodeVersions crushRules }`,
		`proxmox.ceph.monitors { name host addr quorum rank state service directoryExists cephVersion cephVersionShort }`,
		`proxmox.ceph.managers { name host addr state service directoryExists cephVersion cephVersionShort }`,
		`proxmox.ceph.metadataServers { name host addr state rank fsName standbyReplay service directoryExists cephVersion cephVersionShort }`,
		`proxmox.ceph.osds { id name host up inCluster status deviceClass crushWeight reweight totalSpace bytesUsed percentUsed objectStore devices deviceIds devicePaths frontAddress backAddress dataPath cephVersion cephVersionShort cephRelease }`,
		`proxmox.ceph.pools { name poolId type size minSize pgNum pgNumFinal pgNumMin pgAutoscaleMode crushRuleId crushRuleName bytesUsed percentUsed applications }`,
		`proxmox.ceph.fileSystems { name metadataPool dataPools }`,
		`proxmox.ceph.config { name section value mask level canUpdateAtRuntime }`,

		// the edge from a metadata server to the file system it serves
		`proxmox.ceph.metadataServers { fileSystem { name metadataPool dataPools } }`,
	}

	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			_, err := mqlc.Compile(query, nil, mqlc.NewConfig(proxmoxSchema, features))
			require.NoError(t, err, "query %q should compile", query)
		})
	}
}
