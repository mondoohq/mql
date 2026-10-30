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

func TestContainerSecurityContextFields(t *testing.T) {
	manifestFile := "../connection/shared/resources/testdata/pod-securitycontext.yaml"
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{Options: map[string]string{shared.OPTION_NAMESPACE: "default"}},
		},
	}, manifest.WithManifestFile(manifestFile))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn

	obj, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
		"name":      llx.StringData("secctx"),
		"namespace": llx.StringData("default"),
	})
	require.NoError(t, err)
	pod := obj.(*mqlK8sPod)

	containers := pod.GetContainers()
	require.NoError(t, containers.Error)
	require.Len(t, containers.Data, 2)

	t.Run("fully specified security context", func(t *testing.T) {
		c := containers.Data[0].(*mqlK8sContainer)
		assert.Equal(t, "app", c.GetName().Data)
		assert.Equal(t, false, c.GetPrivileged().Data)
		assert.Equal(t, false, c.GetAllowPrivilegeEscalation().Data)
		assert.Equal(t, true, c.GetRunAsNonRoot().Data)
		assert.Equal(t, int64(1000), c.GetRunAsUser().Data)
		assert.Equal(t, int64(3000), c.GetRunAsGroup().Data)
		assert.Equal(t, true, c.GetReadOnlyRootFilesystem().Data)
		assert.Equal(t, []any{"NET_BIND_SERVICE"}, c.GetAddedCapabilities().Data)
		assert.Equal(t, []any{"ALL"}, c.GetDroppedCapabilities().Data)
		assert.Equal(t, "RuntimeDefault", c.GetSeccompProfileType().Data)
		assert.Equal(t, "Localhost", c.GetAppArmorProfileType().Data)
		assert.Equal(t, "Unmasked", c.GetProcMount().Data)
		assert.Equal(t, "spc_t", c.GetSeLinuxType().Data)
		assert.Equal(t, "s0:c1,c2", c.GetSeLinuxLevel().Data)
	})

	t.Run("absent security context leaves pointer fields null", func(t *testing.T) {
		c := containers.Data[1].(*mqlK8sContainer)
		assert.Equal(t, "bare", c.GetName().Data)
		assert.NotEqual(t, 0, c.GetPrivileged().State&plugin.StateIsNull)
		assert.NotEqual(t, 0, c.GetRunAsUser().State&plugin.StateIsNull)
		assert.Empty(t, c.GetAddedCapabilities().Data)
		assert.Empty(t, c.GetDroppedCapabilities().Data)
		assert.Equal(t, "", c.GetSeccompProfileType().Data)
		// An unset confinement field must stay empty rather than reporting a
		// default: empty means "the container asked for nothing, so the pod
		// level decides", which is not the same as an explicit Unconfined.
		assert.Equal(t, "", c.GetAppArmorProfileType().Data)
		assert.Equal(t, "", c.GetProcMount().Data)
		assert.Equal(t, "", c.GetSeLinuxType().Data)
		assert.Equal(t, "", c.GetSeLinuxLevel().Data)
	})

	t.Run("pod requesting its own user namespace", func(t *testing.T) {
		assert.Equal(t, false, pod.GetHostUsers().Data)
	})
}
