// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/utils/sysproxy"
)

func TestAddProxyConfig(t *testing.T) {
	t.Run("opt-out travels to the provider", func(t *testing.T) {
		t.Setenv(sysproxy.EnvSystemProxy, "false")
		cmd := exec.Command("provider")
		addProxyConfig(cmd)
		assert.Equal(t, []string{sysproxy.EnvSystemProxy + "=false"}, cmd.Env)
	})

	t.Run("nothing is added when the environment already names a proxy", func(t *testing.T) {
		t.Setenv(sysproxy.EnvSystemProxy, "")
		t.Setenv("HTTPS_PROXY", "http://env-proxy:3128")
		cmd := exec.Command("provider")
		addProxyConfig(cmd)
		assert.Empty(t, cmd.Env, "the provider inherits HTTPS_PROXY as it is")
	})

	t.Run("nothing is added without system settings", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("depends on the machine's proxy settings")
		}
		t.Setenv(sysproxy.EnvSystemProxy, "")
		t.Setenv("HTTPS_PROXY", "")
		t.Setenv("HTTP_PROXY", "")
		cmd := exec.Command("provider")
		addProxyConfig(cmd)
		assert.Empty(t, cmd.Env)
	})
}
