// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

func volumeTestRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{Options: map[string]string{shared.OPTION_NAMESPACE: "default"}},
		},
	}, manifest.WithManifestFile("../connection/shared/resources/testdata/pod-volumes.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

func podVolumes(t *testing.T, runtime *plugin.Runtime, name string) []any {
	t.Helper()
	obj, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData("default"),
	})
	require.NoError(t, err)

	vols := obj.(*mqlK8sPod).GetVolumes()
	require.NoError(t, vols.Error)
	return vols.Data
}

// A volume name is unique only within one pod spec, so two pods that both
// declare "shared-name" must not collide in the resource cache. A colliding
// key would make CreateResource hand back the first pod's volume, silently
// reporting the second pod's tmpfs as a hostPath mount of /var/log.
func TestVolumeIdCarriesTheOwningObject(t *testing.T) {
	runtime := volumeTestRuntime(t)

	first := podVolumes(t, runtime, "first")
	second := podVolumes(t, runtime, "second")
	require.Len(t, first, 2)
	require.Len(t, second, 1)

	firstShared := first[0].(*mqlK8sVolume)
	secondShared := second[0].(*mqlK8sVolume)

	assert.Equal(t, "shared-name", firstShared.GetName().Data)
	assert.Equal(t, "shared-name", secondShared.GetName().Data)
	assert.NotEqual(t, firstShared.MqlID(), secondShared.MqlID())

	// and each one reports its own source, not the other's
	assert.Equal(t, "hostPath", firstShared.GetType().Data)
	assert.Equal(t, "/var/log", firstShared.GetHostPath().Data)
	assert.Equal(t, "emptyDir", secondShared.GetType().Data)
	assert.Equal(t, "Memory", secondShared.GetEmptyDirMedium().Data)
	assert.Equal(t, "32Mi", secondShared.GetEmptyDirSizeLimit().Data)
}

// Fields that belong to another volume source must stay null. An empty string
// on hostPath would read as a mount of the filesystem root.
func TestVolumeUnrelatedSourceFieldsStayNull(t *testing.T) {
	runtime := volumeTestRuntime(t)
	second := podVolumes(t, runtime, "second")
	require.Len(t, second, 1)

	v := second[0].(*mqlK8sVolume)
	assert.NotEqual(t, 0, v.GetHostPath().State&plugin.StateIsNull)
	assert.NotEqual(t, 0, v.GetHostPathType().State&plugin.StateIsNull)
	assert.NotEqual(t, 0, v.GetCsiDriver().State&plugin.StateIsNull)
	assert.Empty(t, v.GetServiceAccountTokens().Data)
}

func TestVolumeProjectedServiceAccountTokenDetail(t *testing.T) {
	runtime := volumeTestRuntime(t)
	first := podVolumes(t, runtime, "first")
	require.Len(t, first, 2)

	tokens := first[1].(*mqlK8sVolume).GetServiceAccountTokens()
	require.NoError(t, tokens.Error)
	require.Len(t, tokens.Data, 2)

	assert.Equal(t, map[string]any{
		"audience":          "first-audience",
		"expirationSeconds": int64(600),
		"path":              "token",
	}, tokens.Data[0])

	// The manifest never requested a lifetime, so none is reported. On a live
	// cluster the API server defaults this field, which is exactly why the
	// manifest path is where the null case is observable.
	assert.Equal(t, map[string]any{
		"audience":          "",
		"expirationSeconds": nil,
		"path":              "legacy-token",
	}, tokens.Data[1])
}
