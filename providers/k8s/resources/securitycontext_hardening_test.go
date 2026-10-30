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
	"go.mondoo.com/mql/utils/syncx"
	corev1 "k8s.io/api/core/v1"
)

// TestSecurityContextHardeningSpec covers the spec-level predicates directly,
// mutating a compliant spec to introduce exactly one violation at a time.
func TestSecurityContextHardeningSpec(t *testing.T) {
	t.Run("compliant spec trips nothing", func(t *testing.T) {
		s := restrictedSpec()
		assert.False(t, specUsesUnconfinedAppArmor(s))
		assert.False(t, specUsesUnmaskedProcMount(s))
		assert.False(t, specHasUnsafeSysctls(s))
	})

	t.Run("unconfined AppArmor", func(t *testing.T) {
		s := restrictedSpec()
		container(s).AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
		assert.True(t, specUsesUnconfinedAppArmor(s))
	})

	t.Run("unmasked procMount", func(t *testing.T) {
		s := restrictedSpec()
		pm := corev1.UnmaskedProcMount
		container(s).ProcMount = &pm
		assert.True(t, specUsesUnmaskedProcMount(s))
	})

	t.Run("unsafe sysctl", func(t *testing.T) {
		s := restrictedSpec()
		s.SecurityContext.Sysctls = []corev1.Sysctl{{Name: "kernel.msgmax", Value: "65536"}}
		assert.True(t, specHasUnsafeSysctls(s))
	})

	t.Run("safe sysctl is allowed", func(t *testing.T) {
		s := restrictedSpec()
		s.SecurityContext.Sysctls = []corev1.Sysctl{{Name: "net.ipv4.tcp_syncookies", Value: "1"}}
		assert.False(t, specHasUnsafeSysctls(s))
	})
}

func hardeningRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{}},
	}, manifest.WithManifestFile("./testdata/securitycontext_hardening.yaml"))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

// TestSecurityContextHardeningWiring confirms the predicates resolve through the
// runtime for a Pod (podSpecTyped accessor) and a Deployment (securitySpec
// accessor).
func TestSecurityContextHardeningWiring(t *testing.T) {
	runtime := hardeningRuntime(t)

	violator, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
		"name":      llx.StringData("violator"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	vp := violator.(*mqlK8sPod)
	for field, tv := range map[string]*plugin.TValue[bool]{
		"usesUnconfinedAppArmor": vp.GetUsesUnconfinedAppArmor(),
		"usesUnmaskedProcMount":  vp.GetUsesUnmaskedProcMount(),
		"hasUnsafeSysctls":       vp.GetHasUnsafeSysctls(),
	} {
		require.NoError(t, tv.Error, field)
		assert.True(t, tv.Data, field)
	}

	clean, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
		"name":      llx.StringData("clean"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	cp := clean.(*mqlK8sPod)
	for field, tv := range map[string]*plugin.TValue[bool]{
		"usesUnconfinedAppArmor": cp.GetUsesUnconfinedAppArmor(),
		"usesUnmaskedProcMount":  cp.GetUsesUnmaskedProcMount(),
		"hasUnsafeSysctls":       cp.GetHasUnsafeSysctls(),
	} {
		require.NoError(t, tv.Error, field)
		assert.False(t, tv.Data, field)
	}

	// Controller spec accessor (securitySpec) path.
	deploy, err := NewResource(runtime, "k8s.deployment", map[string]*llx.RawData{
		"name":      llx.StringData("deploy-violator"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	aa := deploy.(*mqlK8sDeployment).GetUsesUnconfinedAppArmor()
	require.NoError(t, aa.Error)
	assert.True(t, aa.Data)
}
