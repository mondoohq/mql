// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/moby/moby/api/types/volume"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// volume-list.json is GET /v1.51/volumes from Docker Engine 29.8 (Docker
// Desktop), trimmed to a named volume with a label, a tmpfs volume with
// driver options, and the anonymous volume `docker run -v /data` created.
func loadDockerVolumes(t *testing.T) map[string]volume.Volume {
	t.Helper()
	raw, err := os.ReadFile("testdata/docker/volume-list.json")
	require.NoError(t, err)
	var list struct {
		Volumes []volume.Volume
	}
	require.NoError(t, json.Unmarshal(raw, &list))
	res := map[string]volume.Volume{}
	for _, v := range list.Volumes {
		res[v.Name] = v
	}
	return res
}

const dockerAnonymousVolumeFixture = "dadacadc2c28b1e7891769f6ef274b10f64e1ebdddbacceea47b7dadbfc92b02"

func TestDockerVolumeDecode(t *testing.T) {
	vols := loadDockerVolumes(t)

	named := vols["mqltest-named"]
	assert.Equal(t, "local", named.Driver)
	assert.Equal(t, "local", named.Scope)
	assert.Equal(t, "/var/lib/docker/volumes/mqltest-named/_data", named.Mountpoint)
	assert.Equal(t, "me", named.Labels["owner"])
	assert.Nil(t, named.Options)

	assert.Equal(t, map[string]string{"device": "tmpfs", "o": "size=10m", "type": "tmpfs"}, vols["mqltest-opts"].Options)
}

func TestDockerVolumeAnonymous(t *testing.T) {
	vols := loadDockerVolumes(t)
	assert.True(t, dockerVolumeAnonymous(vols[dockerAnonymousVolumeFixture]))
	assert.False(t, dockerVolumeAnonymous(vols["mqltest-named"]))
	// a volume without any label decodes to a nil map
	assert.False(t, dockerVolumeAnonymous(vols["mqltest-opts"]))
}

func TestDockerVolumeCreated(t *testing.T) {
	vols := loadDockerVolumes(t)
	got := dockerVolumeCreated(vols["mqltest-named"].CreatedAt)
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2026, 10, 8, 3, 39, 9, 0, time.UTC), got.UTC())

	assert.Nil(t, dockerVolumeCreated(""))
	assert.Nil(t, dockerVolumeCreated("yesterday"))
}

func TestDockerContainerVolumeNames(t *testing.T) {
	ctrs := loadDockerContainerList(t)
	assert.ElementsMatch(t, []string{dockerAnonymousVolumeFixture, "mqltest-named"}, dockerContainerVolumeNames(ctrs["/mqltest-c1"]))
	assert.Equal(t, []string{"mqltest-named"}, dockerContainerVolumeNames(ctrs["/mqltest-c2"]))
	// created but never started still lists its volume
	assert.Equal(t, []string{"mqltest-opts"}, dockerContainerVolumeNames(ctrs["/mqltest-c3"]))
}
