// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// Storage volumes are what turn a scheduled backup job into evidence that a
// guest was actually captured, so the queries that answer "when was this last
// backed up" are pinned here along with one read of every new field.
func TestProxmoxStorageVolumeQueriesCompile(t *testing.T) {
	// The recency queries reach for the core `time` resource, so the proxmox
	// schema alone is not enough to compile them.
	schema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "core"}).
		Add(testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "proxmox"}))

	queries := []string{
		// the posture questions these resources exist to answer
		`proxmox.vms.where(template == false).all(backups.length > 0)`,
		`proxmox.containers.all(backups.length > 0)`,
		`proxmox.vms.where(template == false).all(lastBackupAt > time.now() - 7 * time.day)`,

		// every field on the new resource
		`proxmox.storages { volumes { volid storage node contentType format size used createdAt vmid encrypted encryptionFingerprint protected verification notes parent } }`,
		`proxmox.storages { id nodes backups { volid createdAt protected encrypted } }`,

		// the guest-side accessors and their typed edges
		`proxmox.vms { name backups { volid createdAt } lastBackupAt }`,
		`proxmox.containers { name backups { volid createdAt } lastBackupAt }`,
		`proxmox.storages { backups { vm { id name } container { id name } } }`,

		// the shapes an operator would actually write
		`proxmox.storages.where(id == "pbs") { backups.where(protected == false) { volid createdAt } }`,
		`proxmox.vms.where(lastBackupAt == null) { id name }`,

		// the examples printed in providers/proxmox/README.md
		`proxmox.vms.where(backups.length == 0) { id name }`,
		`proxmox.vms { name lastBackupAt }`,
		`proxmox.storages { backups.where(protected == false) { volid createdAt } }`,
		`proxmox.storages { backups.where(verification['state'] != "ok") { volid createdAt } }`,
	}

	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			_, err := mqlc.Compile(query, nil, mqlc.NewConfig(schema, features))
			require.NoError(t, err, "query %q should compile", query)
		})
	}
}
