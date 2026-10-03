// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package id

import (
	"os"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/id/ids"
)

func identifyRhel9(t *testing.T, extraFiles map[string]string) (*PlatformFingerprint, *inventory.Platform) {
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

	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(data))
	require.NoError(t, err)
	fp, pf, err := IdentifyPlatform(conn, &plugin.ConnectReq{}, nil, []string{ids.IdDetector_Hostname})
	require.NoError(t, err)
	return fp, pf
}

// A local scan inside a container (ubi9 on Docker Desktop: /.dockerenv
// present) reported kind baremetal, titled "Bare metal system".
func TestIdentifyPlatformInsideContainer(t *testing.T) {
	fp, pf := identifyRhel9(t, map[string]string{"/.dockerenv": ""})
	assert.Equal(t, "container", pf.Kind)
	assert.Equal(t, detector.DeviceTypeContainer, pf.Metadata[detector.MetadataDeviceType])
	assert.Equal(t, "Red Hat Enterprise Linux 9.0 (Plow), Container", pf.PrettyTitle())
	// the container keeps its hostname platform id
	assert.Equal(t, []string{"//platformid.api.mondoo.app/hostname/4f1c2e9a7b3d"}, fp.PlatformIDs)

	_, host := identifyRhel9(t, nil)
	assert.Equal(t, "", host.Kind, "connect defaults it to baremetal")
	assert.NotEqual(t, detector.DeviceTypeContainer, host.Metadata[detector.MetadataDeviceType])
}
