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
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

const sourceContextFixture = "testdata/source-context"

func manifestRuntime(t *testing.T, opt manifest.Option) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{
			Options: map[string]string{shared.OPTION_NAMESPACE: "default"},
		}},
	}, opt)
	require.NoError(t, err)
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

func deploymentContext(t *testing.T, runtime *plugin.Runtime, name string) *mqlK8sContext {
	t.Helper()
	obj, err := NewResource(runtime, "k8s.deployment", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData("default"),
	})
	require.NoError(t, err)
	ctx := obj.(*mqlK8sDeployment).GetContext()
	require.NoError(t, ctx.Error)
	return ctx.Data
}

func TestSourceContext_ManifestDirectory(t *testing.T) {
	runtime := manifestRuntime(t, manifest.WithManifestFile(sourceContextFixture))

	// Each object reports the file it was declared in, with lines counted from
	// the start of that file, not of the directory's concatenated stream.
	for _, name := range []string{"a", "b"} {
		ctx := deploymentContext(t, runtime, "web-"+name)
		require.NotNil(t, ctx)
		assert.Equal(t, filepath.Join(sourceContextFixture, name+".yaml"), ctx.Path.Data)
		assert.Equal(t, llx.NewRange().AddLineRange(1, 17).String(), ctx.Range.Data.String())
		// The excerpt is cut from the object's own file.
		assert.Contains(t, ctx.Content.Data, "17:            image: nginx:1.27")
		assert.NotContains(t, ctx.Content.Data, "---")
	}
}

func TestSourceContext_ManifestFile(t *testing.T) {
	file := filepath.Join(sourceContextFixture, "b.yaml")
	runtime := manifestRuntime(t, manifest.WithManifestFile(file))

	ctx := deploymentContext(t, runtime, "web-b")
	require.NotNil(t, ctx)
	assert.Equal(t, file, ctx.Path.Data)
	assert.Equal(t, llx.NewRange().AddLineRange(1, 17).String(), ctx.Range.Data.String())
}

func TestSourceContext_ManifestContent(t *testing.T) {
	// Manifest content passed in directly (stdin) has no file to point at, so
	// its objects carry no source context, and reading them must still work.
	content, err := os.ReadFile(filepath.Join(sourceContextFixture, "a.yaml"))
	require.NoError(t, err)
	runtime := manifestRuntime(t, manifest.WithManifestContent(content))

	assert.Nil(t, deploymentContext(t, runtime, "web-a"))
}
