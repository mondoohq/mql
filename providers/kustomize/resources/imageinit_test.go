// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/kustomize/connection"
)

func newImageTestRuntime(t *testing.T, kustomization string) *plugin.Runtime {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(kustomization), 0o600))

	asset := &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": dir},
	}}}
	conn, err := connection.NewKustomizeConnection(1, asset, &inventory.Config{})
	require.NoError(t, err)
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

const imagesKustomization = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
images:
- name: nginx
  newTag: 1.2.3
- name: redis
  digest: sha256:abc123
`

// The schema documents `kustomize.image(name: "nginx")`. Without an init the
// runtime built the resource from the `name` arg alone: newTag/digest were
// UNSET (the "primitive with no type information" symptom), and no __id was
// assigned, so every bare lookup in a session shared one cache slot.
func TestInitKustomizeImageResolvesDocumentedSelector(t *testing.T) {
	rt := newImageTestRuntime(t, imagesKustomization)

	res, err := NewResource(rt, "kustomize.image", map[string]*llx.RawData{
		"name": llx.StringData("nginx"),
	})
	require.NoError(t, err)

	img := res.(*mqlKustomizeImage)
	assert.Equal(t, "nginx", img.Name.Data)
	assert.Equal(t, "1.2.3", img.NewTag.Data, "newTag must be populated, not unset")
	assert.NotEmpty(t, img.MqlID(), "a resolved image must carry a stable __id")
}

// Two different selectors must not alias. With an empty __id they shared the
// cache key `kustomize.image\x00`, so the second returned the first's data.
func TestInitKustomizeImageDoesNotAlias(t *testing.T) {
	rt := newImageTestRuntime(t, imagesKustomization)

	first, err := NewResource(rt, "kustomize.image", map[string]*llx.RawData{
		"name": llx.StringData("nginx"),
	})
	require.NoError(t, err)
	second, err := NewResource(rt, "kustomize.image", map[string]*llx.RawData{
		"name": llx.StringData("redis"),
	})
	require.NoError(t, err)

	a, b := first.(*mqlKustomizeImage), second.(*mqlKustomizeImage)
	require.NotEqual(t, a.MqlID(), b.MqlID(), "distinct images need distinct __ids")
	assert.Equal(t, "nginx", a.Name.Data)
	assert.Equal(t, "redis", b.Name.Data)
	assert.Equal(t, "1.2.3", a.NewTag.Data)
	assert.Equal(t, "sha256:abc123", b.Digest.Data)
}

// A miss must be an error, not a husk. Falling through to `args, nil, nil`
// rebuilds exactly the empty resource this init exists to prevent.
func TestInitKustomizeImageUnknownNameErrors(t *testing.T) {
	rt := newImageTestRuntime(t, imagesKustomization)

	_, err := NewResource(rt, "kustomize.image", map[string]*llx.RawData{
		"name": llx.StringData("does-not-exist"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does-not-exist")
}

// `name` is the only way to reach this resource, so a bare or empty-named
// lookup must error. Accepting it would build the exact husk this init exists
// to prevent: an empty `__id` that every other bare lookup then aliases onto.
func TestInitKustomizeImageRequiresName(t *testing.T) {
	rt := newImageTestRuntime(t, imagesKustomization)

	for _, tc := range []struct {
		name string
		args map[string]*llx.RawData
	}{
		{name: "no args", args: map[string]*llx.RawData{}},
		{name: "empty name", args: map[string]*llx.RawData{"name": llx.StringData("")}},
		{name: "nil name", args: map[string]*llx.RawData{"name": nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, res, err := initKustomizeImage(rt, tc.args)
			require.Error(t, err)
			assert.Nil(t, res)
			assert.Contains(t, err.Error(), `requires a "name"`)
		})
	}
}
