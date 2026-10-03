// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"
)

// mergeDeprecatedFlagsIntoConfig used to read the wrong map key for
// "manifest-url-header" (a literal tab), which both dropped the value and
// panicked on the type assertion when the flag was actually set.
func TestMergeDeprecatedFlags_ManifestURLHeader(t *testing.T) {
	config := map[string]any{}
	flags := map[string]any{
		"manifest-url-header": "X-Example:value,Authorization:Bearer token",
	}

	require.NotPanics(t, func() {
		err := mergeDeprecatedFlagsIntoConfig(config, flags)
		require.NoError(t, err)
	})

	header, ok := config["staticPodURLHeader"].(map[string]any)
	require.True(t, ok, "expected staticPodURLHeader to be set")
	assert.Equal(t, "value", header["X-Example"])
	assert.Equal(t, "Bearer token", header["Authorization"])
}

// A header value without a colon must be skipped instead of panicking on the
// missing split element.
func TestMergeDeprecatedFlags_ManifestURLHeaderMalformed(t *testing.T) {
	config := map[string]any{}
	flags := map[string]any{
		"manifest-url-header": "no-colon-here",
	}

	require.NotPanics(t, func() {
		err := mergeDeprecatedFlagsIntoConfig(config, flags)
		require.NoError(t, err)
	})

	header, ok := config["staticPodURLHeader"].(map[string]any)
	require.True(t, ok)
	assert.Empty(t, header)
}

// The anonymous-auth flag must land in the config even when the config has no
// pre-existing authentication block (the previous code built the nested maps
// but never linked them back, silently dropping the flag).
func TestMergeDeprecatedFlags_AnonymousAuthFromEmptyConfig(t *testing.T) {
	config := map[string]any{}
	flags := map[string]any{
		"anonymous-auth": "false",
	}

	err := mergeDeprecatedFlagsIntoConfig(config, flags)
	require.NoError(t, err)

	auth, ok := config["authentication"].(map[string]any)
	require.True(t, ok, "expected authentication block to be created")
	anon, ok := auth["anonymous"].(map[string]any)
	require.True(t, ok, "expected anonymous block to be created")
	assert.Equal(t, "false", anon["enabled"])
}

// The authentication-token-webhook flag must likewise survive when no
// authentication block exists yet.
func TestMergeDeprecatedFlags_AuthTokenWebhookFromEmptyConfig(t *testing.T) {
	config := map[string]any{}
	flags := map[string]any{
		"authentication-token-webhook": "true",
	}

	err := mergeDeprecatedFlagsIntoConfig(config, flags)
	require.NoError(t, err)

	auth, ok := config["authentication"].(map[string]any)
	require.True(t, ok, "expected authentication block to be created")
	webhook, ok := auth["webhook"].(map[string]any)
	require.True(t, ok, "expected webhook block to be created")
	assert.Equal(t, "true", webhook["enabled"])
}

func TestParseKubeletVersion(t *testing.T) {
	assert.Equal(t, "v1.34.0", parseKubeletVersion("Kubernetes v1.34.0\n"))
	assert.Equal(t, "v1.28.3", parseKubeletVersion("  Kubernetes v1.28.3  "))
	// tolerate output that omits the "Kubernetes" prefix
	assert.Equal(t, "v1.30.1", parseKubeletVersion("v1.30.1"))
	assert.Equal(t, "", parseKubeletVersion(""))
}

func TestKubeletValueCoercion(t *testing.T) {
	// flags arrive as strings, config/defaults as native types
	assert.True(t, kubeletBool(true))
	assert.True(t, kubeletBool("true"))
	assert.False(t, kubeletBool("false"))
	assert.False(t, kubeletBool(nil))

	assert.Equal(t, int64(0), kubeletInt("0"))
	assert.Equal(t, int64(50), kubeletInt(50.0))
	assert.Equal(t, int64(10255), kubeletInt(int64(10255)))
	assert.Equal(t, int64(0), kubeletInt(nil))

	assert.Equal(t, "Webhook", kubeletString("Webhook"))
	assert.Equal(t, "", kubeletString(nil))
}

// createConfiguration applies the kubelet defaults. These assertions lock in
// the values from the release-1.34 defaults (the oldest supported Kubernetes
// release) so an accidental regression in kubelet_defaults.go is caught.
func TestCreateConfiguration_Defaults_1_34(t *testing.T) {
	config, err := createConfiguration(map[string]any{}, "")
	require.NoError(t, err)

	// values bumped in newer releases (were 5 / 10 in 1.25)
	assert.Equal(t, 50.0, config["eventRecordQPS"])
	assert.Equal(t, 100.0, config["eventBurst"])
	assert.Equal(t, 50.0, config["kubeAPIQPS"])
	assert.Equal(t, 100.0, config["kubeAPIBurst"])
	assert.Equal(t, 0.9, config["memoryThrottlingFactor"])

	// fields introduced after 1.25
	assert.Equal(t, "/var/log/pods", config["podLogsDir"])
	assert.Equal(t, "unix:///run/containerd/containerd.sock", config["containerRuntimeEndpoint"])
	assert.Equal(t, false, config["failCgroupV1"])
	assert.Equal(t, false, config["mergeDefaultEvictionSettings"])
	assert.Equal(t, 1.0, config["containerLogMaxWorkers"])

	// security-relevant defaults that must remain stable
	assert.Equal(t, false, config["authentication"].(map[string]any)["anonymous"].(map[string]any)["enabled"])
	assert.Equal(t, "Webhook", config["authorization"].(map[string]any)["mode"])
}

// Feature-gated defaults must stay unset unless the operator explicitly
// enabled the gate, and must be applied when it is.
func TestSetDefaults_FeatureGatedDefaults(t *testing.T) {
	off := &kubeletconfigv1beta1.KubeletConfiguration{}
	SetDefaults_KubeletConfiguration(off)
	assert.Empty(t, off.ImagePullCredentialsVerificationPolicy)
	assert.Nil(t, off.CrashLoopBackOff.MaxContainerRestartPeriod)

	on := &kubeletconfigv1beta1.KubeletConfiguration{
		FeatureGates: map[string]bool{
			"KubeletEnsureSecretPulledImages": true,
			"KubeletCrashLoopBackOffMax":      true,
		},
	}
	SetDefaults_KubeletConfiguration(on)
	assert.Equal(t, kubeletconfigv1beta1.NeverVerifyPreloadedImages, on.ImagePullCredentialsVerificationPolicy)
	assert.NotNil(t, on.CrashLoopBackOff.MaxContainerRestartPeriod)
}

// When an authentication block already exists (e.g. from the applied defaults),
// the flag must update it in place without clobbering sibling settings.
func TestMergeDeprecatedFlags_AnonymousAuthMergesExisting(t *testing.T) {
	config := map[string]any{
		"authentication": map[string]any{
			"anonymous": map[string]any{"enabled": true},
			"webhook":   map[string]any{"enabled": true},
		},
	}
	flags := map[string]any{
		"anonymous-auth": false,
	}

	err := mergeDeprecatedFlagsIntoConfig(config, flags)
	require.NoError(t, err)

	auth := config["authentication"].(map[string]any)
	assert.Equal(t, false, auth["anonymous"].(map[string]any)["enabled"])
	// sibling webhook block must be preserved
	assert.Equal(t, true, auth["webhook"].(map[string]any)["enabled"])
}

// /var/lib/kubelet/config.yaml at 0600 (CIS) on a non-root scan: reading it
// as empty reported kubelet's defaults (readOnlyPort 0, Webhook).
func TestKubeletConfigContent(t *testing.T) {
	refused := &plugin.TValue[string]{Error: &fs.PathError{Op: "open", Path: "/var/lib/kubelet/config.yaml", Err: fs.ErrPermission}, State: plugin.StateIsSet | plugin.StateIsNull}

	t.Run("content", func(t *testing.T) {
		c, err := kubeletConfigContent(&plugin.TValue[string]{Data: "readOnlyPort: 10255\n", State: plugin.StateIsSet})
		require.NoError(t, err)
		assert.Equal(t, "readOnlyPort: 10255\n", c)
	})

	t.Run("no config file", func(t *testing.T) {
		c, err := kubeletConfigContent(&plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull})
		require.NoError(t, err)
		assert.Equal(t, "", c)
		c, err = kubeletConfigContent(nil)
		require.NoError(t, err)
		assert.Equal(t, "", c)
	})

	t.Run("refused before structured errors", func(t *testing.T) {
		require.False(t, plugin.StructuredErrors())
		_, err := kubeletConfigContent(refused)
		assert.NoError(t, err)
	})

	t.Run("refused with structured errors", func(t *testing.T) {
		enableStructuredErrorsForTest(t)
		_, err := kubeletConfigContent(refused)
		require.Error(t, err)
		assert.True(t, errors.Is(err, llx.ErrForbidden))
		_, err = kubeletConfigContent(&plugin.TValue[string]{Error: fs.ErrNotExist, State: plugin.StateIsSet | plugin.StateIsNull})
		assert.NoError(t, err)
	})

	t.Run("an I/O error is not swallowed", func(t *testing.T) {
		require.False(t, plugin.StructuredErrors())
		_, err := kubeletConfigContent(&plugin.TValue[string]{Error: errors.New("read: input/output error"), State: plugin.StateIsSet | plugin.StateIsNull})
		assert.Error(t, err)
	})
}
