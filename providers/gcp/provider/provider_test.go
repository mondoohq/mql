// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

func TestParseCLI_InstanceRequiresProjectAndZone(t *testing.T) {
	_, err := (&Service{}).ParseCLI(&plugin.ParseCLIReq{
		Connector: "gcp",
		Args:      []string{"instance", "my-vm"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "--project-id")
	assert.Contains(t, err.Error(), "--zone")
}

func TestParseCLI_SnapshotRequiresProject(t *testing.T) {
	_, err := (&Service{}).ParseCLI(&plugin.ParseCLIReq{
		Connector: "gcp",
		Args:      []string{"snapshot", "my-snapshot"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "--project-id")
}

func TestValidateInstanceTarget(t *testing.T) {
	assert.Error(t, validateInstanceTarget("", ""))
	assert.Error(t, validateInstanceTarget("my-project", ""))
	assert.Error(t, validateInstanceTarget("", "us-central1-a"))
	assert.NoError(t, validateInstanceTarget("my-project", "us-central1-a"))
}

func TestValidateSnapshotTarget(t *testing.T) {
	assert.Error(t, validateSnapshotTarget(""))
	assert.NoError(t, validateSnapshotTarget("my-project"))
}
