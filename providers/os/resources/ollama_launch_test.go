// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

// /proc of ollama/ollama started with -e OLLAMA_ORIGINS=*: the image's ENV
// sets OLLAMA_HOST=0.0.0.0:11434, and nothing else declares either.
var ollamaImageProc = map[string]string{
	"/proc/1/cmdline": "/bin/ollama\x00serve\x00",
	"/proc/1/stat":    "1 (ollama) S 0 1 1 0 -1",
	"/proc/1/environ": "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\x00HOSTNAME=b1696eb277aa\x00OLLAMA_ORIGINS=*\x00LD_LIBRARY_PATH=/usr/local/nvidia/lib:/usr/local/nvidia/lib64\x00OLLAMA_HOST=0.0.0.0:11434\x00HOME=/root\x00",
	"/bin/ollama":     "\x7fELF",
}

// a unit that would bind to loopback on its next start
const ollamaLoopbackUnit = "[Service]\nExecStart=/usr/local/bin/ollama serve\nEnvironment=\"OLLAMA_HOST=127.0.0.1:11434\"\n"

func ollamaConfOf(t *testing.T, rt *plugin.Runtime) *mqlOllamaConfig {
	t.Helper()
	res, err := NewResource(rt, "ollama.config", nil)
	require.NoError(t, err)
	return res.(*mqlOllamaConfig)
}

func TestOllamaConfigFollowsServerEnvironment(t *testing.T) {
	pgrep := map[string]*mock.Command{"pgrep -x 'ollama'": {Stdout: "1\n"}}

	t.Run("the running server's environment", func(t *testing.T) {
		cfg := ollamaConfOf(t, newLaunchRuntime(t, ollamaImageProc, pgrep, nil))
		require.NoError(t, cfg.GetBindAddress().Error)
		assert.Equal(t, "0.0.0.0", cfg.GetBindAddress().Data)
		assert.True(t, cfg.GetListensOnAllInterfaces().Data)
		assert.True(t, cfg.GetAllowsAnyOrigin().Data)
		assert.Equal(t, "/proc/1/environ", cfg.GetVariableSources().Data["OLLAMA_ORIGINS"])
		assert.Equal(t, "*", cfg.GetVariables().Data["OLLAMA_ORIGINS"])
		assert.NotContains(t, cfg.GetVariables().Data, "PATH")
		assert.True(t, cfg.GetInstalled().Data)
	})

	t.Run("the running server wins over its unit", func(t *testing.T) {
		files := mergeFiles(ollamaImageProc, map[string]string{"/etc/systemd/system/ollama.service": ollamaLoopbackUnit})
		cfg := ollamaConfOf(t, newLaunchRuntime(t, files, pgrep, nil))
		assert.Equal(t, "0.0.0.0", cfg.GetBindAddress().Data)
	})

	t.Run("an unreadable environment falls back to the unit", func(t *testing.T) {
		files := map[string]string{
			"/proc/1/cmdline":                    "/usr/local/bin/ollama\x00serve\x00",
			"/proc/1/stat":                       "1 (ollama) S 0 1 1 0 -1",
			"/etc/systemd/system/ollama.service": ollamaLoopbackUnit,
		}
		cfg := ollamaConfOf(t, newLaunchRuntime(t, files, pgrep, nil))
		assert.Equal(t, "127.0.0.1", cfg.GetBindAddress().Data)
		assert.False(t, cfg.GetListensOnAllInterfaces().Data)
	})

	t.Run("a client or model runner is not the server", func(t *testing.T) {
		files := map[string]string{
			"/proc/9/cmdline": "/usr/local/bin/ollama\x00run\x00llama3\x00",
			"/proc/9/stat":    "9 (ollama) S 1 9 9 0 -1",
			"/proc/9/environ": "OLLAMA_HOST=0.0.0.0:11434\x00",
		}
		cfg := ollamaConfOf(t, newLaunchRuntime(t, files, map[string]*mock.Command{"pgrep -x 'ollama'": {Stdout: "9\n"}}, nil))
		assert.False(t, cfg.GetInstalled().Data)
	})

	t.Run("the image's Env", func(t *testing.T) {
		image := &tar.ImageConfig{
			Entrypoint: []string{"/bin/ollama"},
			Cmd:        []string{"serve"},
			Env:        []string{"PATH=/usr/local/sbin:/usr/local/bin", "OLLAMA_HOST=0.0.0.0:11434"},
		}
		cfg := ollamaConfOf(t, newLaunchRuntime(t, map[string]string{"/bin/ollama": "\x7fELF"}, nil, image))
		assert.Equal(t, "0.0.0.0", cfg.GetBindAddress().Data)
		assert.True(t, cfg.GetListensOnAllInterfaces().Data)
		assert.False(t, cfg.GetAllowsAnyOrigin().Data)
		assert.Equal(t, "image configuration", cfg.GetVariableSources().Data["OLLAMA_HOST"])
	})
}

// deniedConn serves its files through deniedFs (idp_activedirectory_test.go),
// as /proc/<pid>/environ refuses a scan that is neither the process's user
// nor root with ptrace rights.
type deniedConn struct {
	shared.Connection
	denied string
}

func (c deniedConn) FileSystem() afero.Fs {
	return deniedFs{Fs: c.Connection.FileSystem(), denied: c.denied}
}

func TestOllamaConfigRefusedEnvironment(t *testing.T) {
	files := map[string]string{
		"/proc/1/cmdline":                    "/usr/local/bin/ollama\x00serve\x00",
		"/proc/1/stat":                       "1 (ollama) S 0 1 1 0 -1",
		"/proc/1/environ":                    "OLLAMA_HOST=0.0.0.0:11434\x00",
		"/etc/systemd/system/ollama.service": ollamaLoopbackUnit,
	}
	newRt := func() *plugin.Runtime {
		rt := newLaunchRuntime(t, files, map[string]*mock.Command{"pgrep -x 'ollama'": {Stdout: "1\n"}}, nil)
		rt.Connection = deniedConn{Connection: rt.Connection.(shared.Connection), denied: "/proc/1/environ"}
		return rt
	}

	t.Run("v13: the unit's environment", func(t *testing.T) {
		withStructuredErrors(t, false)
		cfg := ollamaConfOf(t, newRt())
		assert.Equal(t, "127.0.0.1", cfg.GetBindAddress().Data)
	})

	t.Run("structured errors: a refusal, not the unit's loopback", func(t *testing.T) {
		withStructuredErrors(t, true)
		cfg := ollamaConfOf(t, newRt())
		err := cfg.GetBindAddress().Error
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	})
}
