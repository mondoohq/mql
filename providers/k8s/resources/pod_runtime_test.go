// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

const (
	digest1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digest2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func podRuntimeK8s(t *testing.T) *mqlK8s {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{Options: map[string]string{shared.OPTION_NAMESPACE: "default"}},
		},
	}, manifest.WithManifestFile("./testdata/pod-runtime.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn

	obj, err := NewResource(runtime, "k8s", nil)
	require.NoError(t, err)
	return obj.(*mqlK8s)
}

func podByNameRuntime(t *testing.T, k8s *mqlK8s, name string) *mqlK8sPod {
	t.Helper()
	pods := k8s.GetPods()
	require.NoError(t, pods.Error)
	for i := range pods.Data {
		p := pods.Data[i].(*mqlK8sPod)
		if p.GetName().Data == name {
			return p
		}
	}
	require.FailNowf(t, "pod not found", "pod %q not found", name)
	return nil
}

func TestPodRuntimeImageDigests(t *testing.T) {
	k8s := podRuntimeK8s(t)

	t.Run("mutable tag resolved to a digest drifts", func(t *testing.T) {
		p := podByNameRuntime(t, k8s, "drift-pod")
		assert.ElementsMatch(t, []any{digest1, digest2}, p.GetRunningImageDigests().Data, "runningImageDigests")
		assert.True(t, p.GetHasImageDigestDrift().Data, "hasImageDigestDrift")
	})

	t.Run("digest-pinned spec never drifts", func(t *testing.T) {
		p := podByNameRuntime(t, k8s, "pinned-pod")
		assert.ElementsMatch(t, []any{digest1}, p.GetRunningImageDigests().Data, "runningImageDigests")
		assert.False(t, p.GetHasImageDigestDrift().Data, "hasImageDigestDrift")
	})

	t.Run("no status yields no digests and no drift", func(t *testing.T) {
		p := podByNameRuntime(t, k8s, "no-status-pod")
		assert.Empty(t, p.GetRunningImageDigests().Data, "runningImageDigests")
		assert.False(t, p.GetHasImageDigestDrift().Data, "hasImageDigestDrift")
	})
}

func TestPodContainerStatusGroupsPreserveOptionalStarted(t *testing.T) {
	k8s := podRuntimeK8s(t)
	p := podByNameRuntime(t, k8s, "status-groups-pod")

	statuses := p.GetContainerStatuses()
	require.NoError(t, statuses.Error)
	require.Len(t, statuses.Data, 3)
	for _, want := range []string{"app", "init", "debugger"} {
		var found *mqlK8sContainerStatus
		for _, item := range statuses.Data {
			candidate := item.(*mqlK8sContainerStatus)
			if candidate.GetName().Data == want {
				found = candidate
				break
			}
		}
		require.NotNil(t, found, want)
		assert.NotZero(t, found.GetStarted().State&plugin.StateIsNull, want+" started")
	}

	initStatuses := p.GetInitContainerStatuses()
	require.NoError(t, initStatuses.Error)
	require.Len(t, initStatuses.Data, 1)
	assert.Equal(t, "init", initStatuses.Data[0].(*mqlK8sContainerStatus).GetName().Data)
	assert.True(t, initStatuses.Data[0].(*mqlK8sContainerStatus).GetStarted().State&plugin.StateIsNull != 0)

	ephemeralStatuses := p.GetEphemeralContainerStatuses()
	require.NoError(t, ephemeralStatuses.Error)
	require.Len(t, ephemeralStatuses.Data, 1)
	assert.Equal(t, "debugger", ephemeralStatuses.Data[0].(*mqlK8sContainerStatus).GetName().Data)
	assert.True(t, ephemeralStatuses.Data[0].(*mqlK8sContainerStatus).GetStarted().State&plugin.StateIsNull != 0)
}

func TestImageDigestParsing(t *testing.T) {
	cases := map[string]string{
		"docker-pullable://nginx@" + digest1: digest1, // containerd/docker pullable form
		"nginx@" + digest1:                   digest1, // bare repo@digest
		digest1:                              digest1, // bare digest
		"nginx:1.25":                         "",      // tag only, no digest
		"":                                   "",      // empty
	}
	for in, want := range cases {
		assert.Equal(t, want, imageDigest(in), "imageDigest(%q)", in)
	}
}
