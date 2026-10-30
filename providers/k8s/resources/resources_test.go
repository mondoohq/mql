// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	sharedres "go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	"go.mondoo.com/mql/utils/syncx"
)

type K8sObjectKindTest struct {
	kind string
}

func TestManifestFiles(t *testing.T) {
	tests := []K8sObjectKindTest{
		{
			kind: "cronjob",
		},
		{kind: "job"},
		{kind: "deployment"},
		{kind: "pod"},
		{kind: "statefulset"},
		{kind: "replicaset"},
		{kind: "daemonset"},
	}
	for _, testCase := range tests {
		t.Run("k8s "+testCase.kind, func(t *testing.T) {
			manifestFile := "../connection/shared/resources/testdata/" + testCase.kind + ".yaml"
			conn, err := manifest.NewConnection(0, &inventory.Asset{
				Connections: []*inventory.Config{
					{
						Options: map[string]string{
							shared.OPTION_NAMESPACE: "default",
						},
					},
				},
			}, manifest.WithManifestFile(manifestFile))
			require.NoError(t, err)
			require.NotNil(t, conn)

			runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
			runtime.Connection = conn

			obj, err := NewResource(
				runtime,
				"k8s."+testCase.kind,
				map[string]*llx.RawData{
					"name":      llx.StringData("mondoo"),
					"namespace": llx.StringData("default"),
				},
			)
			require.NoError(t, err)

			switch v := obj.(type) {
			case *mqlK8sCronjob:
				assert.Equal(t, "mondoo", v.GetName().Data)
				podSpec := v.GetPodSpec().Data
				assert.NotNil(t, podSpec)
				podSpecMap := podSpec.(map[string]any)
				assert.NotNil(t, podSpecMap["containers"])
			case *mqlK8sJob:
				assert.Equal(t, "mondoo", v.GetName().Data)
				podSpec := v.GetPodSpec().Data
				assert.NotNil(t, podSpec)
				podSpecMap := podSpec.(map[string]any)
				assert.NotNil(t, podSpecMap["containers"])
			case *mqlK8sDeployment:
				assert.Equal(t, "mondoo", v.GetName().Data)
				podSpec := v.GetPodSpec().Data
				assert.NotNil(t, podSpec)
				podSpecMap := podSpec.(map[string]any)
				assert.NotNil(t, podSpecMap["containers"])
			case *mqlK8sStatefulset:
				assert.Equal(t, "mondoo", v.GetName().Data)
				podSpec := v.GetPodSpec().Data
				assert.NotNil(t, podSpec)
				podSpecMap := podSpec.(map[string]any)
				assert.NotNil(t, podSpecMap["containers"])
			case *mqlK8sReplicaset:
				assert.Equal(t, "mondoo", v.GetName().Data)
				podSpec := v.GetPodSpec().Data
				assert.NotNil(t, podSpec)
				podSpecMap := podSpec.(map[string]any)
				assert.NotNil(t, podSpecMap["containers"])
			case *mqlK8sDaemonset:
				assert.Equal(t, "mondoo", v.GetName().Data)
				podSpec := v.GetPodSpec().Data
				assert.NotNil(t, podSpec)
				podSpecMap := podSpec.(map[string]any)
				assert.NotNil(t, podSpecMap["containers"])
			case *mqlK8sPod:
				assert.Equal(t, "mondoo", v.GetName().Data)
				podSpec := v.GetPodSpec().Data
				assert.NotNil(t, podSpec)
				podSpecMap := podSpec.(map[string]any)
				assert.NotNil(t, podSpecMap["containers"])
			default:
				fmt.Printf("I don't know about type %T!\n", v)
				t.FailNow()
			}

			manifestConn := conn.(*manifest.Connection)
			res := manifestConn.ManifestParser.Objects[0]

			assert.Equal(t, testCase.kind, strings.ToLower(res.GetObjectKind().GroupVersionKind().Kind))
			podSpec, err := sharedres.GetPodSpec(res)
			require.NoError(t, err)
			assert.NotNil(t, podSpec)
			containers, err := sharedres.GetContainers(res)
			require.NoError(t, err)
			assert.Equal(t, 1, len(containers))
			initContainers, err := sharedres.GetInitContainers(res)
			require.NoError(t, err)
			assert.Equal(t, 0, len(initContainers))
		})
	}
}

func TestManifestFile_CustomResource(t *testing.T) {
	manifestFile := "../connection/shared/resources/testdata/cr/tekton.yaml"
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Options: map[string]string{
					shared.OPTION_NAMESPACE: "default",
				},
			},
		},
	}, manifest.WithManifestFile(manifestFile))
	require.NoError(t, err)
	require.NotNil(t, conn)

	name := "demo-pipeline"
	namespace := "default"
	kind := "pipeline.tekton.dev"
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn

	parser := conn.(*manifest.Connection).ManifestParser

	res, err := parser.Resources(kind, name, namespace)
	require.NoError(t, err)

	assert.Equal(t, name, res.Name)
	assert.Equal(t, namespace, res.Namespace)
	assert.Equal(t, kind, res.Kind)
	assert.Equal(t, 1, len(res.Resources))

	rr, err := conn.Resources(kind, name, namespace)
	require.NoError(t, err)

	assert.Equal(t, name, rr.Name)
	assert.Equal(t, namespace, rr.Namespace)
	assert.Equal(t, kind, rr.Kind)
}

func TestManifestContentProvider(t *testing.T) {
	t.Run("k8s manifest provider with content", func(t *testing.T) {
		manifestFile := "../connection/shared/resources/testdata/pod.yaml"
		data, err := os.ReadFile(manifestFile)
		require.NoError(t, err)

		conn, err := manifest.NewConnection(0, &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Options: map[string]string{
						shared.OPTION_NAMESPACE: "default",
					},
				},
			},
		}, manifest.WithManifestContent(data))
		require.NoError(t, err)
		require.NotNil(t, conn)
	})
}

func TestLoadManifestDirRecursively(t *testing.T) {
	manifests, err := shared.LoadManifestFile("../connection/shared/resources/testdata/")
	require.NoError(t, err)

	manifestsAsString := string(manifests[:])
	// This is content from files of the root dir
	assert.Contains(t, manifestsAsString, "mondoo")
	assert.Contains(t, manifestsAsString, "RollingUpdate")

	// Files containing this should be skipped
	assert.NotContains(t, manifestsAsString, "AdmissionReview")
	assert.NotContains(t, manifestsAsString, "README")
	assert.NotContains(t, manifestsAsString, "operators.coreos.com")

	// This is from files in subdirs which should be included
	assert.Contains(t, manifestsAsString, "hello-1")
	assert.Contains(t, manifestsAsString, "hello-2")
	assert.Contains(t, manifestsAsString, "MondooAuditConfig")
}
