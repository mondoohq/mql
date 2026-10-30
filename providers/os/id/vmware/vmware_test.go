// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package vmware_test

import (
	"testing"

	subject "go.mondoo.com/mql/providers/os/id/vmware"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestDetectLinuxInstance(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instance_linux.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, relatedIdentifiers := subject.Detect(conn, platform)

	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/vmware/uuid/5c4c1142-a38a-b604-dfde-60730c109bac",
		identifier,
	)
	assert.Equal(t, "", name)
	require.Len(t, relatedIdentifiers, 1)
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/vcenter/moid/vm-6143",
		relatedIdentifiers[0],
	)
}
func TestDetectLinuxInstanceWithoutVmtoolsd(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instance_linux_no_vmtoolsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, relatedIdentifiers := subject.Detect(conn, platform)

	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/vmware/uuid/5c4c1142-a38a-b604-dfde-60730c109bac",
		identifier,
	)
	assert.Equal(t, "", name)
	require.Len(t, relatedIdentifiers, 0)
}

func TestDetectWindowsInstance(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instance_windows.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, relatedIdentifiers := subject.Detect(conn, platform)

	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/vmware/uuid/5c4c1142-a38a-b604-dfde-60730c109bab",
		identifier,
	)
	assert.Equal(t, "", name)
	require.Len(t, relatedIdentifiers, 1)
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/vcenter/moid/vm-6143",
		relatedIdentifiers[0],
	)
}

func TestDetectWindowsInstanceWithoutVmtoolsd(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instance_windows_no_vmtoolsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, relatedIdentifiers := subject.Detect(conn, platform)

	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/vmware/uuid/5c4c1142-a38a-b604-dfde-60730c109bab",
		identifier,
	)
	assert.Equal(t, "", name)
	require.Len(t, relatedIdentifiers, 0)
}

func TestNoMatch(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/no_vmware_instance.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, relatedIdentifiers := subject.Detect(conn, platform)

	assert.Empty(t, identifier)
	assert.Empty(t, name)
	assert.Empty(t, relatedIdentifiers)
}
