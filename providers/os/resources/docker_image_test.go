// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/api/types/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// The fixtures in testdata/docker/image-inspect-*.json are `docker image
// inspect` output from Docker Desktop 29.8.2 (containerd image store) for
// alpine:3.22, nginx:latest, and an image built from alpine:3.22 with
// MAINTAINER, `USER 1000:1000`, `WORKDIR /srv`, `EXPOSE 8080/tcp 8443`,
// `HEALTHCHECK --interval=15s CMD wget ...`, and an ENTRYPOINT and CMD
// (hardened).
func loadDockerImageInspect(t *testing.T, name string) *image.InspectResponse {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "docker", "image-inspect-"+name+".json"))
	require.NoError(t, err)
	var res []image.InspectResponse
	require.NoError(t, json.Unmarshal(data, &res))
	require.Len(t, res, 1)
	return &res[0]
}

func TestDockerImageConfig(t *testing.T) {
	hard := loadDockerImageInspect(t, "hardened")
	cfg := dockerImageConfig(hard)
	assert.Equal(t, "1000:1000", cfg.User)
	assert.False(t, imageUserIsRoot(cfg.User))
	assert.Equal(t, "/srv", cfg.WorkingDir)
	assert.Equal(t, []string{"/bin/sh", "-c"}, cfg.Entrypoint)
	assert.Equal(t, []string{"sleep 3600"}, cfg.Cmd)
	assert.Equal(t, []any{"8080/tcp", "8443/tcp"}, sortedPorts(cfg.ExposedPorts))
	assert.True(t, healthcheckDefined(cfg.Healthcheck))
	secs, ok := healthcheckIntervalSeconds(cfg.Healthcheck)
	assert.True(t, ok)
	assert.Equal(t, int64(15), secs)
	assert.Equal(t, "Example Maintainer <maint@example.com>", hard.Author)
	assert.Equal(t, "arm64", hard.Architecture)
	assert.Equal(t, "linux", hard.Os)
	assert.Len(t, hard.RootFS.Layers, 3)
	assert.Equal(t, "sha256:9fd9b3248f2fb670edfab1393d1d1e8cd828eb9c65de376b2fcc23268a45d500", hard.RootFS.Layers[0])

	nginx := loadDockerImageInspect(t, "nginx")
	cfg = dockerImageConfig(nginx)
	assert.Empty(t, cfg.User)
	assert.True(t, imageUserIsRoot(cfg.User))
	assert.Equal(t, []string{"/docker-entrypoint.sh"}, cfg.Entrypoint)
	assert.Equal(t, []any{"80/tcp"}, sortedPorts(cfg.ExposedPorts))
	assert.False(t, healthcheckDefined(cfg.Healthcheck))
	assert.Equal(t, "v8", nginx.Variant)

	alpine := loadDockerImageInspect(t, "alpine")
	cfg = dockerImageConfig(alpine)
	assert.Equal(t, []any{}, sortedPorts(cfg.ExposedPorts))
	assert.Empty(t, cfg.Entrypoint)
	assert.Equal(t, []string{"/bin/sh"}, cfg.Cmd)
	assert.Empty(t, alpine.Author)
}

func TestDockerImageConfigAbsent(t *testing.T) {
	cfg := dockerImageConfig(&image.InspectResponse{})
	require.NotNil(t, cfg)
	assert.Empty(t, cfg.User)
	assert.Nil(t, cfg.Healthcheck)
	assert.NotNil(t, dockerImageConfig(nil))
}

func TestImageUserIsRoot(t *testing.T) {
	for user, want := range map[string]bool{
		"":            true,
		"0":           true,
		"root":        true,
		"0:0":         true,
		"root:root":   true,
		"0:1000":      true,
		"1000":        false,
		"1000:0":      false,
		"nginx":       false,
		"65532:65532": false,
		"00":          true,
		"+0:1000":     true,
		"-0":          true,
		"0001":        false,
		"Root":        false,
	} {
		assert.Equal(t, want, imageUserIsRoot(user), user)
	}
}

func TestDockerImageCreated(t *testing.T) {
	ts, err := dockerImageCreated("2026-09-19T00:21:31.454274978Z")
	require.NoError(t, err)
	require.NotNil(t, ts)
	assert.Equal(t, time.Date(2026, 9, 19, 0, 21, 31, 454274978, time.UTC), ts.UTC())

	ts, err = dockerImageCreated("")
	require.NoError(t, err)
	assert.Nil(t, ts, "absent build time is null, not year 1")

	_, err = dockerImageCreated("yesterday")
	require.Error(t, err)
	assert.ErrorIs(t, err, llx.ErrMalformedData)
}
