// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package vmtoolsd_test

import (
	"encoding/json"
	"testing"

	subject "go.mondoo.com/mql/providers/os/id/vmware/vmtoolsd"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestDetectLinuxInstance(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("../testdata/instance_linux.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	vmtoolsSvc, err := subject.Resolve(conn, platform)
	require.NoError(t, err)

	t.Run("identity", func(t *testing.T) {
		identt, err := vmtoolsSvc.Identify()
		require.NoError(t, err)

		assert.Equal(t,
			"//platformid.api.mondoo.app/runtime/vmware/uuid/5c4c1142-a38a-b604-dfde-60730c109bac",
			identt.UUID,
		)
		assert.Equal(t,
			"//platformid.api.mondoo.app/runtime/vcenter/moid/vm-6143",
			identt.VCenterMOID,
		)
		assert.Empty(t, identt.VSphereMOID)
	})

	t.Run("raw metadata", func(t *testing.T) {
		raw, err := vmtoolsSvc.RawMetadata()
		require.NoError(t, err)

		// Convert to JSON for readability
		jsonData, _ := json.MarshalIndent(raw, "", "  ")
		expected := `{
  "hostname": "linux-123.localdomain",
	"ipv4": "192.168.1.5",
  "ovf": {
    "esxID": "",
    "vCenterID": "vm-6143",
    "id": "",
    "platformSection": {
      "kind": "VMware ESXi",
      "locale": "en",
      "vendor": "VMware, Inc.",
      "version": "8.0.0"
    },
    "propertySection": {
      "property": [
        {
          "key": "dns",
          "value": "test-mondoo.com"
        },
        {
          "key": "foo"
        },
        {
          "key": "gateway",
          "value": "192.168.1.1"
        },
        {
          "key": "hostname",
          "value": "linux-123.localdomain"
        },
        {
          "key": "ipv4",
          "value": "192.168.1.5"
        }
      ]
    },
    "xmlName": {
      "Local": "Environment",
      "Space": "http://schemas.dmtf.org/ovf/environment/1"
    }
  }
}`

		// Compare actual vs expected JSON output
		assert.JSONEq(t, expected, string(jsonData))
	})
}

func TestDetectLinuxInstanceWithoutVmtoolsd(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("../testdata/instance_linux_no_vmtoolsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	vmtoolsSvc, err := subject.Resolve(conn, platform)
	require.NoError(t, err)

	t.Run("identity", func(t *testing.T) {
		identt, err := vmtoolsSvc.Identify()
		require.NoError(t, err)

		assert.Equal(t,
			"//platformid.api.mondoo.app/runtime/vmware/uuid/5c4c1142-a38a-b604-dfde-60730c109bac",
			identt.UUID,
		)
		assert.Empty(t, identt.VCenterMOID)
	})

	t.Run("raw metadata", func(t *testing.T) {
		raw, err := vmtoolsSvc.RawMetadata()
		require.NoError(t, err)

		// Convert to JSON for readability
		jsonData, _ := json.MarshalIndent(raw, "", "  ")
		expected := `{
  "hostname": "linux-123.localdomain"
}`

		// Compare actual vs expected JSON output
		assert.JSONEq(t, expected, string(jsonData))
	})
}

func TestDetectWindowsInstance(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("../testdata/instance_windows.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	vmtoolsSvc, err := subject.Resolve(conn, platform)
	require.NoError(t, err)

	t.Run("identity", func(t *testing.T) {
		identt, err := vmtoolsSvc.Identify()
		require.NoError(t, err)

		assert.Equal(t,
			"//platformid.api.mondoo.app/runtime/vmware/uuid/5c4c1142-a38a-b604-dfde-60730c109bab",
			identt.UUID,
		)
		assert.Equal(t,
			"//platformid.api.mondoo.app/runtime/vcenter/moid/vm-6143",
			identt.VCenterMOID,
		)
		assert.Empty(t, identt.VSphereMOID)
	})

	t.Run("raw metadata", func(t *testing.T) {
		raw, err := vmtoolsSvc.RawMetadata()
		require.NoError(t, err)

		// Convert to JSON for readability
		jsonData, _ := json.MarshalIndent(raw, "", "  ")
		expected := `{
  "hostname": "win-1",
	"ipv4": "192.168.1.6",
  "ovf": {
    "esxID": "",
    "vCenterID": "vm-6143",
    "id": "",
    "platformSection": {
      "kind": "VMware ESXi",
      "locale": "en",
      "vendor": "VMware, Inc.",
      "version": "8.0.0"
    },
    "propertySection": {
      "property": [
        {
          "key": "dns",
          "value": "test-mondoo.com"
        },
        {
          "key": "foo"
        },
        {
          "key": "gateway",
          "value": "192.168.1.1"
        },
        {
          "key": "hostname",
          "value": "win-1"
        },
        {
          "key": "ipv4",
          "value": "192.168.1.6"
        }
      ]
    },
    "xmlName": {
      "Local": "Environment",
      "Space": "http://schemas.dmtf.org/ovf/environment/1"
    }
  }

}`

		// Compare actual vs expected JSON output
		assert.JSONEq(t, expected, string(jsonData))
	})
}

func TestDetectWindowsInstanceWithoutVmtoolsd(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("../testdata/instance_windows_no_vmtoolsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	vmtoolsSvc, err := subject.Resolve(conn, platform)
	require.NoError(t, err)

	t.Run("identity", func(t *testing.T) {
		identt, err := vmtoolsSvc.Identify()
		require.NoError(t, err)

		assert.Equal(t,
			"//platformid.api.mondoo.app/runtime/vmware/uuid/5c4c1142-a38a-b604-dfde-60730c109bab",
			identt.UUID,
		)
		assert.Empty(t, identt.VCenterMOID)
		assert.Empty(t, identt.VSphereMOID)
	})

	t.Run("raw metadata", func(t *testing.T) {
		raw, err := vmtoolsSvc.RawMetadata()
		require.NoError(t, err)

		// Convert to JSON for readability
		jsonData, _ := json.MarshalIndent(raw, "", "  ")
		expected := `{
  "hostname": "win-1"
}`

		// Compare actual vs expected JSON output
		assert.JSONEq(t, expected, string(jsonData))
	})
}

func TestNoMatch(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("../testdata/no_vmware_instance.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	vmtoolsSvc, err := subject.Resolve(conn, platform)
	require.NoError(t, err)

	t.Run("identity", func(t *testing.T) {
		identt, err := vmtoolsSvc.Identify()
		require.Error(t, err)
		assert.Empty(t, identt.UUID)
		assert.Empty(t, identt.VCenterMOID)
		assert.Empty(t, identt.VSphereMOID)
	})

	t.Run("raw metadata", func(t *testing.T) {
		_, err := vmtoolsSvc.RawMetadata()
		require.Error(t, err)
	})
}
