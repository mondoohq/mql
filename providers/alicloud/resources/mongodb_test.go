// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMongodbAccountID(t *testing.T) {
	// Synthetic: a sharded cluster reports root once per account type; no target showed this.
	cs := mongodbAccountID("dds-1", "cs", "admin", "root")
	db := mongodbAccountID("dds-1", "db", "admin", "root")
	assert.NotEqual(t, cs, db)

	// Synthetic: one user name in two authentication databases.
	assert.NotEqual(t,
		mongodbAccountID("dds-1", "normal", "admin", "app"),
		mongodbAccountID("dds-1", "normal", "orders", "app"))

	// Synthetic: the same account on two instances.
	assert.NotEqual(t,
		mongodbAccountID("dds-1", "normal", "admin", "root"),
		mongodbAccountID("dds-2", "normal", "admin", "root"))
}

func TestMongodbRoleID(t *testing.T) {
	// Synthetic: read on admin and read on a user database are different roles.
	assert.NotEqual(t, mongodbRoleID("dds-1", "admin", "read"), mongodbRoleID("dds-1", "orders", "read"))
	assert.NotEqual(t, mongodbRoleID("dds-1", "admin", "read"), mongodbRoleID("dds-2", "admin", "read"))
	assert.Equal(t, "dds-1/role/admin/readWrite", mongodbRoleID("dds-1", "admin", "readWrite"))
}
