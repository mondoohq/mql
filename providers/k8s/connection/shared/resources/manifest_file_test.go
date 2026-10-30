// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestLoadManifestFile(t *testing.T) {
	f, err := os.Open("./testdata/deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}

	list, err := resources.ResourcesFromManifest(f)
	require.NoError(t, err)
	assert.Equal(t, 1, len(list))

	resource := list[0]
	deployment := resource.(*appsv1.Deployment)
	assert.Equal(t, "mondoo", deployment.Name)
}

func TestLoadManifestDir(t *testing.T) {
	input, err := resources.MergeManifestFiles([]string{"./testdata/deployment.yaml", "./testdata/configmap.yaml", "./testdata/daemonset.yaml"})
	require.NoError(t, err)

	list, err := resources.ResourcesFromManifest(input)
	require.NoError(t, err)
	assert.Equal(t, 3, len(list))

	resource := list[0]
	deployment := resource.(*appsv1.Deployment)
	assert.Equal(t, "mondoo", deployment.Name)

	resource = list[1]
	configmap := resource.(*corev1.ConfigMap)
	assert.Equal(t, "mondoo-daemonset-config", configmap.Name)

	resource = list[2]
	daemonset := resource.(*appsv1.DaemonSet)
	assert.Equal(t, "mondoo", daemonset.Name)
}
