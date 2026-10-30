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
)

// TestServiceAccountAutomountDefault pins the auto-mount default and guards the
// fix for the nil-pointer dereference that occurred when
// AutomountServiceAccountToken was unset: an unset field must default to true
// (core/v1 semantics) without dereferencing a nil pointer, while explicit
// true/false values are preserved.
func TestServiceAccountAutomountDefault(t *testing.T) {
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{Options: map[string]string{}}},
	}, manifest.WithManifestFile("testdata/serviceaccount_automount.yaml"))
	require.NoError(t, err)
	require.NotNil(t, conn)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn

	cases := map[string]bool{
		"sa-default":        true,  // unset -> defaults to true (must not panic)
		"sa-explicit-true":  true,  // explicit true preserved
		"sa-explicit-false": false, // explicit false preserved
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			obj, err := NewResource(runtime, "k8s.serviceaccount", map[string]*llx.RawData{
				"name":      llx.StringData(name),
				"namespace": llx.StringData("default"),
			})
			require.NoError(t, err)
			sa := obj.(*mqlK8sServiceaccount)
			got := sa.GetAutomountServiceAccountToken()
			require.NoError(t, got.Error)
			assert.Equal(t, want, got.Data)
		})
	}
}
