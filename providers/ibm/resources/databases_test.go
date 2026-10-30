// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/IBM/cloud-databases-go-sdk/clouddatabasesv5"
	"github.com/stretchr/testify/assert"
)

func TestIsDatabaseService(t *testing.T) {
	assert.True(t, isDatabaseService("databases-for-postgresql"))
	assert.True(t, isDatabaseService("databases-for-mongodb"))
	assert.True(t, isDatabaseService("messages-for-rabbitmq"))
	assert.False(t, isDatabaseService("cloud-object-storage"))
	assert.False(t, isDatabaseService("databases"))
}

func TestPlatformKey(t *testing.T) {
	d := &clouddatabasesv5.Deployment{PlatformOptions: map[string]any{
		"disk_encryption_key_crn": "crn:key:1",
	}}
	assert.Equal(t, "crn:key:1", platformKey(d, "disk_encryption_key_crn"))
	assert.Equal(t, "", platformKey(d, "backup_encryption_key_crn"), "an IBM-managed key has no CRN")
	assert.Equal(t, "", platformKey(nil, "disk_encryption_key_crn"))
}
