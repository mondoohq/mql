// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestContainerEnvironmentCompatibilityFieldsPreserveEntries(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	container := corev1.Container{
		Name: "main",
		Env: []corev1.EnvVar{
			{Name: "DUPLICATE", Value: "first"},
			{Name: "DUPLICATE", Value: "second"},
		},
		EnvFrom: []corev1.EnvFromSource{
			{Prefix: "A_", ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}}},
			{Prefix: "A_", SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}}},
		},
	}
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "environment-fields",
			Namespace: "default",
			UID:       "environment-fields-uid",
		},
		Spec: corev1.PodSpec{
			Containers:     []corev1.Container{container},
			InitContainers: []corev1.Container{container},
			EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name:    "main",
				Env:     container.Env,
				EnvFrom: container.EnvFrom,
			}}},
		},
	}

	envNames := []any{
		map[string]any{"name": "DUPLICATE", "value": "first"},
		map[string]any{"name": "DUPLICATE", "value": "second"},
	}
	envFromNames := []any{
		map[string]any{"prefix": "A_", "configMapRef": map[string]any{"name": "settings"}},
		map[string]any{"prefix": "A_", "secretRef": map[string]any{"name": "settings"}},
	}

	assertFields := func(t *testing.T, legacyEnv any, typedEnv []any, legacyFrom any, typedFrom []any) {
		t.Helper()
		assert.Equal(t, envNames, legacyEnv, "legacy env field keeps its released runtime array")
		assert.Equal(t, envNames, typedEnv, "typed env replacement preserves order and duplicate names")
		assert.Equal(t, envFromNames, legacyFrom, "legacy envFrom field keeps its released runtime array")
		assert.Equal(t, envFromNames, typedFrom, "typed envFrom replacement preserves order and duplicate sources")
	}

	t.Run("container", func(t *testing.T) {
		items, err := getContainers(pod, pod, runtime, ContainerContainerType)
		require.NoError(t, err)
		require.Len(t, items, 1)
		c := items[0].(*mqlK8sContainer)
		assertFields(t, c.GetEnv().Data, c.GetEnvs().Data, c.GetEnvFrom().Data, c.GetEnvFromEntries().Data)
	})
	t.Run("init", func(t *testing.T) {
		items, err := getContainers(pod, pod, runtime, InitContainerType)
		require.NoError(t, err)
		require.Len(t, items, 1)
		c := items[0].(*mqlK8sInitContainer)
		assertFields(t, c.GetEnv().Data, c.GetEnvs().Data, c.GetEnvFrom().Data, c.GetEnvFromEntries().Data)
	})
	t.Run("ephemeral", func(t *testing.T) {
		items, err := getContainers(pod, pod, runtime, EphemeralContainerType)
		require.NoError(t, err)
		require.Len(t, items, 1)
		c := items[0].(*mqlK8sEphemeralContainer)
		assertFields(t, c.GetEnv().Data, c.GetEnvs().Data, c.GetEnvFrom().Data, c.GetEnvFromEntries().Data)
	})
}
