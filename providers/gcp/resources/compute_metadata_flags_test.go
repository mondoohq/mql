// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestMetadataBoolFlag(t *testing.T) {
	for _, tc := range []struct {
		name string
		md   map[string]any
		key  string
		want bool
	}{
		{name: "absent key", md: map[string]any{}, key: "serial-port-enable"},
		{name: "nil map", md: nil, key: "serial-port-enable"},
		{name: "TRUE", md: map[string]any{"serial-port-enable": "TRUE"}, key: "serial-port-enable", want: true},
		{name: "true", md: map[string]any{"serial-port-enable": "true"}, key: "serial-port-enable", want: true},
		{name: "1", md: map[string]any{"serial-port-enable": "1"}, key: "serial-port-enable", want: true},
		{name: "FALSE", md: map[string]any{"serial-port-enable": "FALSE"}, key: "serial-port-enable"},
		{name: "0", md: map[string]any{"serial-port-enable": "0"}, key: "serial-port-enable"},
		{name: "empty string", md: map[string]any{"serial-port-enable": ""}, key: "serial-port-enable"},
		{name: "non-string value", md: map[string]any{"serial-port-enable": true}, key: "serial-port-enable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, metadataBoolFlag(tc.md, tc.key))
		})
	}
}

// seedProjectMetadataEndpoints serves the two calls the project-metadata
// fallback makes: initGcpProject's Cloud Resource Manager get, and the Compute
// projects.get that carries commonInstanceMetadata.
func seedProjectMetadataEndpoints(t *testing.T, env *testEnv, items string) {
	t.Helper()
	seedProjectEndpoint(t, env)
	env.Mux.HandleFunc("/compute/v1/projects/"+testProjectId, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"name": %q, "commonInstanceMetadata": {"items": [%s]}}`, testProjectId, items)
	})
}

func newMetadataTestInstance(env *testEnv, md map[string]any) *mqlGcpProjectComputeServiceInstance {
	i := &mqlGcpProjectComputeServiceInstance{MqlRuntime: env.Runtime}
	i.ProjectId = plugin.TValue[string]{Data: testProjectId, State: plugin.StateIsSet}
	i.Metadata = plugin.TValue[map[string]any]{Data: md, State: plugin.StateIsSet}
	return i
}

// TestSerialPortEnabledInheritsProjectMetadata pins how Compute Engine resolves
// interactive serial console access: the instance's own serial-port-enable
// metadata wins, and an instance that does not set the key inherits the
// project's commonInstanceMetadata value.
//
// Reading only the instance metadata reported false for every VM in a project
// that had switched serial console access on project-wide -- exactly the case
// the control exists to catch, and a false there is indistinguishable from a
// VM that genuinely has it off. Confirmed against a live project: with
// serial-port-enable=TRUE set project-wide and no instance metadata, the VM
// read false while gcp.project.compute.projectSerialPortEnabled read true.
func TestSerialPortEnabledInheritsProjectMetadata(t *testing.T) {
	t.Run("inherits the project value when the instance does not set it", func(t *testing.T) {
		env := setupTestEnv(t, projectScopes())
		seedProjectMetadataEndpoints(t, env, `{"key": "serial-port-enable", "value": "TRUE"}`)

		got, err := newMetadataTestInstance(env, map[string]any{}).serialPortEnabled()
		require.NoError(t, err)
		assert.True(t, got, "the project enables serial console access for every VM that does not opt out")
	})

	t.Run("instance metadata overrides the project", func(t *testing.T) {
		env := setupTestEnv(t, projectScopes())
		seedProjectMetadataEndpoints(t, env, `{"key": "serial-port-enable", "value": "TRUE"}`)

		md := map[string]any{"serial-port-enable": "FALSE"}
		got, err := newMetadataTestInstance(env, md).serialPortEnabled()
		require.NoError(t, err)
		assert.False(t, got, "an explicit instance value wins over the project default")
	})

	t.Run("false when neither sets it", func(t *testing.T) {
		env := setupTestEnv(t, projectScopes())
		seedProjectMetadataEndpoints(t, env, "")

		got, err := newMetadataTestInstance(env, map[string]any{}).serialPortEnabled()
		require.NoError(t, err)
		assert.False(t, got)
	})
}

// TestOsLoginEnabledInheritsProjectMetadata keeps the sibling accessor pinned:
// serialPortEnabled and osLoginEnabled now share projectMetadataFlag, so a
// change to one must not silently change the other.
func TestOsLoginEnabledInheritsProjectMetadata(t *testing.T) {
	env := setupTestEnv(t, projectScopes())
	seedProjectMetadataEndpoints(t, env, `{"key": "enable-oslogin", "value": "TRUE"}`)

	got, err := newMetadataTestInstance(env, map[string]any{}).osLoginEnabled()
	require.NoError(t, err)
	assert.True(t, got)

	env2 := setupTestEnv(t, projectScopes())
	seedProjectMetadataEndpoints(t, env2, `{"key": "enable-oslogin", "value": "TRUE"}`)
	got, err = newMetadataTestInstance(env2, map[string]any{"enable-oslogin": "FALSE"}).osLoginEnabled()
	require.NoError(t, err)
	assert.False(t, got)
}
