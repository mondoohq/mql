// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// TestSecretConsumptionRollups_Fixtures checks the workload-side Secret rollups:
// secret-consumer references Secrets via env, a mounted volume, and an image
// pull secret, while hardened references none.
func TestSecretConsumptionRollups_Fixtures(t *testing.T) {
	k8s := workloadSecurityK8s(t)

	t.Run("workload that consumes secrets", func(t *testing.T) {
		d := deploymentByName(t, k8s, "secret-consumer")
		assert.True(t, d.GetUsesSecretsAsEnv().Data, "usesSecretsAsEnv")
		assert.True(t, d.GetMountsSecretVolumes().Data, "mountsSecretVolumes")
		assert.ElementsMatch(t,
			[]any{"api-secret", "env-secret", "tls-secret", "registry-creds"},
			d.GetConsumedSecrets().Data, "consumedSecrets")
	})

	t.Run("workload that consumes no secrets", func(t *testing.T) {
		d := deploymentByName(t, k8s, "hardened")
		assert.False(t, d.GetUsesSecretsAsEnv().Data, "usesSecretsAsEnv")
		assert.False(t, d.GetMountsSecretVolumes().Data, "mountsSecretVolumes")
		assert.Empty(t, d.GetConsumedSecrets().Data, "consumedSecrets")
	})
}

func TestSecretConsumptionRollups_Helpers(t *testing.T) {
	t.Run("nil spec", func(t *testing.T) {
		assert.False(t, specUsesSecretsAsEnv(nil))
		assert.False(t, specMountsSecretVolumes(nil))
		assert.Empty(t, specConsumedSecrets(nil))
	})

	t.Run("env secretKeyRef only", func(t *testing.T) {
		spec := &corev1.PodSpec{Containers: []corev1.Container{{
			Name: "a",
			Env: []corev1.EnvVar{{Name: "K", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Name: "s1", Key: "k",
				},
			}}},
		}}}
		assert.True(t, specUsesSecretsAsEnv(spec))
		assert.False(t, specMountsSecretVolumes(spec))
		assert.ElementsMatch(t, []any{"s1"}, specConsumedSecrets(spec))
	})

	t.Run("projected secret volume and dedup", func(t *testing.T) {
		spec := &corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "v1", Secret: &corev1.SecretVolumeSource{SecretName: "shared"}},
				{Name: "v2", Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{
						Name: "shared",
					}}},
				}},
			},
			Containers: []corev1.Container{{
				Name:    "a",
				EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{Name: "shared"}}},
			}},
		}
		assert.True(t, specMountsSecretVolumes(spec))
		assert.True(t, specUsesSecretsAsEnv(spec))
		// "shared" is referenced three ways but appears once.
		assert.ElementsMatch(t, []any{"shared"}, specConsumedSecrets(spec))
	})

	t.Run("configmap refs are not secrets", func(t *testing.T) {
		spec := &corev1.PodSpec{Containers: []corev1.Container{{
			Name:    "a",
			EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{Name: "cm"}}},
		}}}
		assert.False(t, specUsesSecretsAsEnv(spec))
		assert.Empty(t, specConsumedSecrets(spec))
	})
}
