// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"os"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

func detectRhel9(t *testing.T, extraFiles map[string]string) *inventory.Asset {
	t.Helper()
	raw, err := os.ReadFile("../detector/testdata/detect-rhel-9.toml")
	require.NoError(t, err)
	data := &mock.TomlData{}
	_, err = toml.Decode(string(raw), data)
	require.NoError(t, err)
	if data.Files == nil {
		data.Files = map[string]*mock.MockFileData{}
	}
	// Docker sets the container's hostname to its short id
	data.Files["/etc/hostname"] = &mock.MockFileData{Path: "/etc/hostname", Content: "4f1c2e9a7b3d\n"}
	for path, content := range extraFiles {
		data.Files[path] = &mock.MockFileData{Path: path, Content: content}
	}

	// connect defaults the kind to baremetal before detection runs
	asset := &inventory.Asset{
		Connections: []*inventory.Config{{Type: "local"}},
		Platform:    &inventory.Platform{Kind: inventory.AssetKindBaremetal},
	}
	conn, err := mock.New(0, asset, mock.WithData(data))
	require.NoError(t, err)
	require.NoError(t, (&Service{}).detect(asset, conn))
	return asset
}

// A local scan inside a container (ubi9 on Docker Desktop: /.dockerenv present)
// reported kind baremetal, titled "Bare metal system".
func TestDetectLocalScanInsideContainer(t *testing.T) {
	asset := detectRhel9(t, map[string]string{"/.dockerenv": ""})
	assert.Equal(t, "container", asset.Platform.Kind)
	assert.Equal(t, detector.DeviceTypeContainer, asset.Platform.Metadata[detector.MetadataDeviceType])
	assert.Contains(t, asset.Platform.PrettyTitle(), "Container")
	// seen from the inside, nothing else gives the container a platform id
	assert.Equal(t, []string{"4f1c2e9a7b3d"}, asset.PlatformIds)

	host := detectRhel9(t, nil)
	assert.Equal(t, inventory.AssetKindBaremetal, host.Platform.Kind)
	assert.NotEqual(t, detector.DeviceTypeContainer, host.Platform.Metadata[detector.MetadataDeviceType])
}
