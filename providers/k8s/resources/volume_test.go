// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestVolumeSourceType(t *testing.T) {
	tests := []struct {
		name     string
		source   corev1.VolumeSource
		expected string
	}{
		{
			name:     "no source at all",
			source:   corev1.VolumeSource{},
			expected: "",
		},
		{
			name:     "hostPath",
			source:   corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run"}},
			expected: "hostPath",
		},
		{
			name:     "emptyDir",
			source:   corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
			expected: "emptyDir",
		},
		{
			name:     "secret",
			source:   corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "creds"}},
			expected: "secret",
		},
		{
			name:     "configMap",
			source:   corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}},
			expected: "configMap",
		},
		{
			name:     "projected",
			source:   corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{}},
			expected: "projected",
		},
		{
			name:     "persistentVolumeClaim",
			source:   corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}},
			expected: "persistentVolumeClaim",
		},
		{
			name:     "csi",
			source:   corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "secrets-store.csi.k8s.io"}},
			expected: "csi",
		},
		{
			name:     "downwardAPI",
			source:   corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{}},
			expected: "downwardAPI",
		},
		{
			name:     "ephemeral",
			source:   corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}},
			expected: "ephemeral",
		},
		{
			name:     "nfs",
			source:   corev1.VolumeSource{NFS: &corev1.NFSVolumeSource{Server: "10.0.0.1"}},
			expected: "nfs",
		},
		{
			name:     "iscsi",
			source:   corev1.VolumeSource{ISCSI: &corev1.ISCSIVolumeSource{}},
			expected: "iscsi",
		},
		{
			name:     "image",
			source:   corev1.VolumeSource{Image: &corev1.ImageVolumeSource{}},
			expected: "image",
		},
		{
			// hostPath is checked first, so a spec that somehow carries two
			// sources still reports the one that decides host reachability.
			name: "hostPath wins over a second source",
			source: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: "/"},
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
			expected: "hostPath",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, volumeSourceType(test.source))
		})
	}
}

func TestVolumeSecretNames(t *testing.T) {
	tests := []struct {
		name     string
		source   corev1.VolumeSource
		expected []string
	}{
		{
			name:     "no secret",
			source:   corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
			expected: nil,
		},
		{
			name:     "plain secret source",
			source:   corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "creds"}},
			expected: []string{"creds"},
		},
		{
			name:     "secret source with an empty name is skipped",
			source:   corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{}},
			expected: nil,
		},
		{
			name: "every projected secret source is reported",
			source: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{
					{Secret: &corev1.SecretProjection{Name: "one"}},
					{ConfigMap: &corev1.ConfigMapProjection{Name: "cm"}},
					{Secret: &corev1.SecretProjection{Name: "two"}},
					{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}},
				},
			}},
			expected: []string{"one", "two"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, volumeSecretNames(test.source))
		})
	}
}

func TestVolumeConfigMapNames(t *testing.T) {
	tests := []struct {
		name     string
		source   corev1.VolumeSource
		expected []string
	}{
		{
			name:     "no configMap",
			source:   corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "creds"}},
			expected: nil,
		},
		{
			name:     "plain configMap source",
			source:   corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{Name: "settings"}},
			expected: []string{"settings"},
		},
		{
			name: "every projected configMap source is reported",
			source: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{
					{ConfigMap: &corev1.ConfigMapProjection{Name: "ca"}},
					{Secret: &corev1.SecretProjection{Name: "s"}},
					{ConfigMap: &corev1.ConfigMapProjection{Name: "extra"}},
				},
			}},
			expected: []string{"ca", "extra"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, volumeConfigMapNames(test.source))
		})
	}
}

func TestProjectedServiceAccountTokens(t *testing.T) {
	expiry := int64(3600)

	t.Run("a non-projected volume carries none", func(t *testing.T) {
		assert.Equal(t, []any{}, projectedServiceAccountTokens(
			corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "creds"}}))
	})

	t.Run("a projected volume with no token source carries none", func(t *testing.T) {
		assert.Equal(t, []any{}, projectedServiceAccountTokens(
			corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{
					{ConfigMap: &corev1.ConfigMapProjection{Name: "ca"}},
				},
			}}))
	})

	t.Run("audience and expiry are reported per token", func(t *testing.T) {
		got := projectedServiceAccountTokens(corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			Sources: []corev1.VolumeProjection{
				{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
					Audience: "vault", ExpirationSeconds: &expiry, Path: "token",
				}},
			},
		}})
		assert.Equal(t, []any{map[string]any{
			"audience":          "vault",
			"expirationSeconds": int64(3600),
			"path":              "token",
		}}, got)
	})

	t.Run("an unrequested expiry stays null rather than becoming zero", func(t *testing.T) {
		// A manifest that omits expirationSeconds has not asked for a
		// lifetime; the kubelet picks one. Reporting 0 would read as "this pod
		// requested a token that expires immediately".
		got := projectedServiceAccountTokens(corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			Sources: []corev1.VolumeProjection{
				{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}},
			},
		}})
		assert.Equal(t, []any{map[string]any{
			"audience":          "",
			"expirationSeconds": nil,
			"path":              "token",
		}}, got)
	})
}
