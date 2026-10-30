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
	"go.mondoo.com/mql/utils/syncx"
)

func admissionEnforcementK8s(t *testing.T) *mqlK8s {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{}},
	}, manifest.WithManifestFile("./testdata/admission-enforcement.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn

	obj, err := NewResource(runtime, "k8s", nil)
	require.NoError(t, err)
	return obj.(*mqlK8s)
}

func TestNamespaceEnforcesPodSecurity(t *testing.T) {
	k8s := admissionEnforcementK8s(t)

	want := map[string]bool{
		"enforced-ns":   true,
		"audit-only-ns": false, // audit-only is not enforcement
		"unenforced-ns": false,
	}

	nss := k8s.GetNamespaces()
	require.NoError(t, nss.Error)
	seen := map[string]bool{}
	for i := range nss.Data {
		ns := nss.Data[i].(*mqlK8sNamespace)
		name := ns.GetName().Data
		if exp, ok := want[name]; ok {
			seen[name] = true
			assert.Equal(t, exp, ns.GetEnforcesPodSecurity().Data, "enforcesPodSecurity for %s", name)
		}
	}
	for name := range want {
		assert.True(t, seen[name], "namespace %s not found", name)
	}
}

func TestWebhookFailsOpen(t *testing.T) {
	k8s := admissionEnforcementK8s(t)

	t.Run("validating webhooks", func(t *testing.T) {
		want := map[string]bool{"vwc-failopen": true, "vwc-failclosed": false}
		list := k8s.GetValidatingWebhookConfigurations()
		require.NoError(t, list.Error)
		seen := map[string]bool{}
		for i := range list.Data {
			w := list.Data[i].(*mqlK8sAdmissionValidatingwebhookconfiguration)
			name := w.GetName().Data
			if exp, ok := want[name]; ok {
				seen[name] = true
				assert.Equal(t, exp, w.GetFailsOpen().Data, "failsOpen for %s", name)
			}
		}
		for name := range want {
			assert.True(t, seen[name], "validatingwebhookconfiguration %s not found", name)
		}
	})

	t.Run("mutating webhooks", func(t *testing.T) {
		list := k8s.GetMutatingWebhookConfigurations()
		require.NoError(t, list.Error)
		var found bool
		for i := range list.Data {
			w := list.Data[i].(*mqlK8sAdmissionMutatingwebhookconfiguration)
			if w.GetName().Data == "mwc-failopen" {
				found = true
				assert.True(t, w.GetFailsOpen().Data, "failsOpen for mwc-failopen")
			}
		}
		assert.True(t, found, "mwc-failopen not found")
	})
}
