// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func newTestService(path string) (*Service, *plugin.ConnectRes) {
	srv := Init()

	resp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type:    DefaultConnectionType,
					Options: map[string]string{"path": path},
				},
			},
		},
	}, nil)
	if err != nil {
		panic(err)
	}
	return srv, resp
}

func getData(t *testing.T, srv *Service, connID uint32, resource, resourceID, field string) *plugin.DataRes {
	t.Helper()
	resp, err := srv.GetData(&plugin.DataReq{
		Connection: connID,
		Resource:   resource,
		ResourceId: resourceID,
		Field:      field,
	})
	require.NoError(t, err)
	require.Empty(t, resp.Error)
	return resp
}

func TestParseCLI(t *testing.T) {
	srv := Init()

	t.Run("path argument", func(t *testing.T) {
		res, err := srv.ParseCLI(&plugin.ParseCLIReq{
			Connector: "kustomize",
			Args:      []string{"./overlays/prod"},
		})
		require.NoError(t, err)
		require.NotNil(t, res.Asset)
		require.Len(t, res.Asset.Connections, 1)
		assert.Equal(t, "kustomize", res.Asset.Connections[0].Type)
		assert.Equal(t, "./overlays/prod", res.Asset.Connections[0].Options["path"])
	})

	t.Run("no args errors", func(t *testing.T) {
		_, err := srv.ParseCLI(&plugin.ParseCLIReq{
			Connector: "kustomize",
			Args:      []string{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "requires a path argument")
	})
}

func TestConnect(t *testing.T) {
	t.Run("basic kustomization", func(t *testing.T) {
		srv, resp := newTestService("../testdata/basic")
		require.NotNil(t, srv)
		require.NotNil(t, resp)
		assert.NotZero(t, resp.Id)
		assert.Contains(t, resp.Asset.Name, "basic")
		assert.Equal(t, "kustomize", resp.Asset.Platform.Name)
	})

	t.Run("nonexistent path", func(t *testing.T) {
		srv := Init()
		_, err := srv.Connect(&plugin.ConnectReq{
			Asset: &inventory.Asset{
				Connections: []*inventory.Config{
					{
						Type:    DefaultConnectionType,
						Options: map[string]string{"path": "../testdata/nonexistent"},
					},
				},
			},
		}, nil)
		assert.Error(t, err)
	})

	t.Run("empty dir (no kustomization.yaml)", func(t *testing.T) {
		srv := Init()
		_, err := srv.Connect(&plugin.ConnectReq{
			Asset: &inventory.Asset{
				Connections: []*inventory.Config{
					{
						Type:    DefaultConnectionType,
						Options: map[string]string{"path": "../testdata/empty-dir"},
					},
				},
			},
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no kustomization file found")
	})

	t.Run("nil request", func(t *testing.T) {
		srv := Init()
		_, err := srv.Connect(nil, nil)
		assert.Error(t, err)
	})
}

func TestDetect(t *testing.T) {
	_, resp := newTestService("../testdata/basic")
	assert.Equal(t, "kustomize", resp.Asset.Platform.Name)
	assert.Equal(t, []string{"kustomize"}, resp.Asset.Platform.Family)
	assert.Equal(t, "Kustomize", resp.Asset.Platform.Title)
	assert.NotEmpty(t, resp.Asset.PlatformIds)
	assert.Contains(t, resp.Asset.PlatformIds[0], "//platformid.api.mondoo.app/runtime/kustomize/hash/")
}

func TestKustomizations(t *testing.T) {
	srv, resp := newTestService("../testdata/basic")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)

	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	require.Len(t, kustsResp.Data.Array, 1)
	kID := string(kustsResp.Data.Array[0].Value)

	t.Run("metadata", func(t *testing.T) {
		apiResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "apiVersion")
		assert.Equal(t, "kustomize.config.k8s.io/v1beta1", string(apiResp.Data.Value))

		kindResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "kind")
		assert.Equal(t, "Kustomization", string(kindResp.Data.Value))

		nsResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "namespace")
		assert.Equal(t, "production", string(nsResp.Data.Value))

		prefixResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "namePrefix")
		assert.Equal(t, "prod-", string(prefixResp.Data.Value))

		suffixResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "nameSuffix")
		assert.Equal(t, "-v1", string(suffixResp.Data.Value))
	})

	t.Run("resourceRefs", func(t *testing.T) {
		refsResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "resourceRefs")
		require.Len(t, refsResp.Data.Array, 2)
	})

	t.Run("componentRefs", func(t *testing.T) {
		compsResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "componentRefs")
		assert.Empty(t, compsResp.Data.Array)
	})
}

func TestPatches(t *testing.T) {
	srv, resp := newTestService("../testdata/basic")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)
	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	kID := string(kustsResp.Data.Array[0].Value)

	patchesResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "patches")
	require.Len(t, patchesResp.Data.Array, 1)

	pID := string(patchesResp.Data.Array[0].Value)
	kindResp := getData(t, srv, resp.Id, "kustomize.patch", pID, "targetKind")
	assert.Equal(t, "Deployment", string(kindResp.Data.Value))

	nameResp := getData(t, srv, resp.Id, "kustomize.patch", pID, "targetName")
	assert.Equal(t, "myapp", string(nameResp.Data.Value))

	contentResp := getData(t, srv, resp.Id, "kustomize.patch", pID, "content")
	assert.Contains(t, string(contentResp.Data.Value), "replicas")
}

func TestConfigMapGenerators(t *testing.T) {
	srv, resp := newTestService("../testdata/basic")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)
	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	kID := string(kustsResp.Data.Array[0].Value)

	gensResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "configMapGenerators")
	require.Len(t, gensResp.Data.Array, 1)

	gID := string(gensResp.Data.Array[0].Value)
	nameResp := getData(t, srv, resp.Id, "kustomize.generator", gID, "name")
	assert.Equal(t, "app-config", string(nameResp.Data.Value))

	typeResp := getData(t, srv, resp.Id, "kustomize.generator", gID, "type")
	assert.Equal(t, "configmap", string(typeResp.Data.Value))

	literalsResp := getData(t, srv, resp.Id, "kustomize.generator", gID, "literals")
	require.Len(t, literalsResp.Data.Array, 2)
}

func TestSecretGenerators(t *testing.T) {
	srv, resp := newTestService("../testdata/basic")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)
	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	kID := string(kustsResp.Data.Array[0].Value)

	gensResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "secretGenerators")
	require.Len(t, gensResp.Data.Array, 1)

	gID := string(gensResp.Data.Array[0].Value)
	nameResp := getData(t, srv, resp.Id, "kustomize.generator", gID, "name")
	assert.Equal(t, "app-secrets", string(nameResp.Data.Value))

	typeResp := getData(t, srv, resp.Id, "kustomize.generator", gID, "type")
	assert.Equal(t, "secret", string(typeResp.Data.Value))
}

func TestImages(t *testing.T) {
	srv, resp := newTestService("../testdata/basic")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)
	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	kID := string(kustsResp.Data.Array[0].Value)

	imagesResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "images")
	require.Len(t, imagesResp.Data.Array, 2)

	// Find the nginx image
	for _, img := range imagesResp.Data.Array {
		imgID := string(img.Value)
		nameResp := getData(t, srv, resp.Id, "kustomize.image", imgID, "name")
		if string(nameResp.Data.Value) == "nginx" {
			newNameResp := getData(t, srv, resp.Id, "kustomize.image", imgID, "newName")
			assert.Equal(t, "registry.example.com/nginx", string(newNameResp.Data.Value))

			newTagResp := getData(t, srv, resp.Id, "kustomize.image", imgID, "newTag")
			assert.Equal(t, "1.25-alpine", string(newTagResp.Data.Value))
			return
		}
	}
	t.Fatal("nginx image not found")
}

func TestReplacements(t *testing.T) {
	srv, resp := newTestService("../testdata/basic")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)
	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	kID := string(kustsResp.Data.Array[0].Value)

	repsResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "replacements")
	require.Len(t, repsResp.Data.Array, 1)

	rID := string(repsResp.Data.Array[0].Value)
	pathResp := getData(t, srv, resp.Id, "kustomize.replacement", rID, "sourcePath")
	assert.Equal(t, "metadata.name", string(pathResp.Data.Value))

	kindResp := getData(t, srv, resp.Id, "kustomize.replacement", rID, "sourceKind")
	assert.Equal(t, "Deployment", string(kindResp.Data.Value))

	targetsResp := getData(t, srv, resp.Id, "kustomize.replacement", rID, "targets")
	require.Len(t, targetsResp.Data.Array, 1)

	tID := string(targetsResp.Data.Array[0].Value)
	fpResp := getData(t, srv, resp.Id, "kustomize.replacementTarget", tID, "fieldPath")
	assert.Equal(t, "spec.selector.app", string(fpResp.Data.Value))
}

func TestRenderedResources(t *testing.T) {
	srv, resp := newTestService("../testdata/basic")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)
	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	kID := string(kustsResp.Data.Array[0].Value)

	resourcesResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "resources")
	// Should have: Deployment, Service, ConfigMap (generator), Secret (generator) = 4
	require.GreaterOrEqual(t, len(resourcesResp.Data.Array), 4)

	// Find the Deployment and verify kustomize transformations were applied
	for _, res := range resourcesResp.Data.Array {
		resID := string(res.Value)
		kindResp := getData(t, srv, resp.Id, "kustomize.resource", resID, "kind")
		if string(kindResp.Data.Value) == "Deployment" {
			nameResp := getData(t, srv, resp.Id, "kustomize.resource", resID, "name")
			name := string(nameResp.Data.Value)
			assert.Contains(t, name, "prod-", "should have namePrefix applied")
			assert.Contains(t, name, "-v1", "should have nameSuffix applied")

			nsResp := getData(t, srv, resp.Id, "kustomize.resource", resID, "namespace")
			assert.Equal(t, "production", string(nsResp.Data.Value))

			manifestResp := getData(t, srv, resp.Id, "kustomize.resource", resID, "manifest")
			assert.NotNil(t, manifestResp.Data.Value)
			return
		}
	}
	t.Fatal("Deployment resource not found in rendered output")
}

func TestMinimalKustomization(t *testing.T) {
	srv, resp := newTestService("../testdata/minimal")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)
	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	require.Len(t, kustsResp.Data.Array, 1)

	kID := string(kustsResp.Data.Array[0].Value)

	// No patches, generators, images, or replacements
	patchesResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "patches")
	assert.Empty(t, patchesResp.Data.Array)

	cmGensResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "configMapGenerators")
	assert.Empty(t, cmGensResp.Data.Array)

	imagesResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "images")
	assert.Empty(t, imagesResp.Data.Array)

	// Should have 1 rendered resource (the ConfigMap)
	resourcesResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "resources")
	require.Len(t, resourcesResp.Data.Array, 1)

	resID := string(resourcesResp.Data.Array[0].Value)
	kindResp := getData(t, srv, resp.Id, "kustomize.resource", resID, "kind")
	assert.Equal(t, "ConfigMap", string(kindResp.Data.Value))
}

func TestMultiOverlayDirectory(t *testing.T) {
	// Point at the parent dir containing base/ and staging/ — both have kustomization.yaml
	srv, resp := newTestService("../testdata/multi-overlay")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)

	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	require.Len(t, kustsResp.Data.Array, 2)
}

// The canonical Kustomize layout puts overlays two levels below the root
// (base/ next to overlays/<env>/). A one-level scan found only base/ and
// silently dropped every overlay; the recursive scan discovers all three.
func TestNestedOverlayDirectory(t *testing.T) {
	srv, resp := newTestService("../testdata/nested-overlays")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)

	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	require.Len(t, kustsResp.Data.Array, 3, "base plus both nested overlays should be discovered")

	namespaces := map[string]bool{}
	for _, k := range kustsResp.Data.Array {
		kID := string(k.Value)
		nsResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "namespace")
		namespaces[string(nsResp.Data.Value)] = true
	}
	assert.True(t, namespaces["dev"], "dev overlay should be present")
	assert.True(t, namespaces["prod"], "prod overlay should be present")
}

func TestStagingOverlay(t *testing.T) {
	// Point directly at the staging overlay which references ../base
	srv, resp := newTestService("../testdata/multi-overlay/staging")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)
	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	kID := string(kustsResp.Data.Array[0].Value)

	nsResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "namespace")
	assert.Equal(t, "staging", string(nsResp.Data.Value))

	// Rendered resources should include base deployment with namespace override
	resourcesResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "resources")
	require.GreaterOrEqual(t, len(resourcesResp.Data.Array), 1)

	resID := string(resourcesResp.Data.Array[0].Value)
	resNsResp := getData(t, srv, resp.Id, "kustomize.resource", resID, "namespace")
	assert.Equal(t, "staging", string(resNsResp.Data.Value))
}

// A kustomization that references a non-existent file used to silently
// produce zero resources (rendering error swallowed, []any{} returned).
// That made audits like `.resources.length > 0` pass on broken
// overlays. The accessor now surfaces the krusty error.
func TestKustomizeResourcesPropagatesRenderError(t *testing.T) {
	srv, resp := newTestService("../testdata/broken-render")

	kustResp := getData(t, srv, resp.Id, "kustomize", "", "")
	kustID := string(kustResp.Data.Value)
	kustsResp := getData(t, srv, resp.Id, "kustomize", kustID, "kustomizations")
	require.NotEmpty(t, kustsResp.Data.Array)
	kID := string(kustsResp.Data.Array[0].Value)

	// Use the lower-level call instead of getData so we can inspect Error.
	resp2, err := srv.GetData(&plugin.DataReq{
		Connection: resp.Id,
		Resource:   "kustomize.kustomization",
		ResourceId: kID,
		Field:      "resources",
	})
	require.NoError(t, err, "transport-level call should not fail")
	assert.NotEmpty(t, resp2.Error, "expected render failure to surface as a field error")
}

// A directory containing a kustomization.yaml that doesn't parse used
// to fall through to a subdir scan and return "no kustomization found"
// — masking the real problem. Now the connection refuses with the
// parse error.
func TestConnect_MalformedKustomizationSurfaces(t *testing.T) {
	srv := Init()
	_, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type:    DefaultConnectionType,
					Options: map[string]string{"path": "../testdata/malformed"},
				},
			},
		},
	}, nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "no kustomization file found",
		"a parse error must not be reported as 'no kustomization found'")
}

// initKustomizeKustomization lets users select a specific kustomization
// by path (`kustomize.kustomization(path: "...")`) without first walking
// `kustomize.kustomizations`. The resource it returns must have Internal
// state populated so the field accessors (patches, images, replacements,
// resources) work — previously they would nil-deref on a bare resource.
func TestInitKustomizeKustomization_SelectorWorks(t *testing.T) {
	srv, resp := newTestService("../testdata/multi-overlay")

	createResp, err := srv.GetData(&plugin.DataReq{
		Connection: resp.Id,
		Resource:   "kustomize.kustomization",
		Args: map[string]*llx.Primitive{
			"path": llx.StringPrimitive("../testdata/multi-overlay/staging"),
		},
	})
	require.NoError(t, err)
	require.Empty(t, createResp.Error)
	require.NotNil(t, createResp.Data)
	kID := string(createResp.Data.Value)
	require.NotEmpty(t, kID)

	// The path field works (proves args were stamped).
	pathResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "path")
	assert.Equal(t, "../testdata/multi-overlay/staging", string(pathResp.Data.Value))

	// And — the regression we care about — a computed field that depends
	// on Internal state (k.kustomization) resolves rather than panicking.
	patchesResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "patches")
	require.NotNil(t, patchesResp.Data)

	nsResp := getData(t, srv, resp.Id, "kustomize.kustomization", kID, "namespace")
	assert.Equal(t, "staging", string(nsResp.Data.Value))
}

// A selector for a path the connection didn't load used to fall through to
// `args, nil, nil`. The runtime then built the resource from the `path` arg
// alone, leaving every other field UNSET — not null, unset — which surfaces
// client-side as "llx: encountered a primitive with no type information,
// coercing to null" with nothing pointing at the cause. The miss is now
// reported where it happens, the way the sibling kustomize.image init does.
func TestInitKustomizeKustomization_UnknownPathIsNotFound(t *testing.T) {
	srv, resp := newTestService("../testdata/basic")

	_, err := srv.GetData(&plugin.DataReq{
		Connection: resp.Id,
		Resource:   "kustomize.kustomization",
		Args: map[string]*llx.Primitive{
			"path": llx.StringPrimitive("/does/not/exist"),
		},
	})
	require.Error(t, err, "an unresolvable path must not produce a husk resource")
	assert.Contains(t, err.Error(), "no kustomization loaded for path")
	assert.Contains(t, err.Error(), "/does/not/exist")
}
