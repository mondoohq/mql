// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ollama

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// An unset environment must resolve to Ollama's own defaults, not to zero
// values. Reporting an empty bind address would read as "not exposed" for the
// same reason as the loopback default, but by accident rather than by fact.
func TestResolve_Defaults(t *testing.T) {
	c := Resolve(nil, "/var/lib/ollama", nil)

	assert.Equal(t, "http://127.0.0.1:11434", c.Host)
	assert.Equal(t, "127.0.0.1", c.BindAddress)
	assert.Equal(t, int64(11434), c.Port)
	assert.False(t, c.ListensOnAllInterfaces)
	assert.False(t, c.TLS)
	assert.Empty(t, c.Origins)
	assert.False(t, c.AllowsAnyOrigin)
	assert.False(t, c.AuthEnabled)
	assert.True(t, c.CloudEnabled)
	assert.Equal(t, "none", c.CloudDisabledSource)
	assert.Equal(t, []string{"ollama.com"}, c.Remotes)
	assert.Equal(t, "/var/lib/ollama/.ollama/models", c.ModelsPath)
	assert.False(t, c.DebugLogRequests)
	assert.Equal(t, "info", c.LogLevel)
	assert.True(t, c.HistoryEnabled)
	assert.Equal(t, int64(300), c.KeepAliveSeconds)
	assert.Equal(t, int64(300), c.LoadTimeoutSeconds)
	assert.Equal(t, int64(1), c.NumParallel)
	assert.Equal(t, int64(512), c.MaxQueue)
	assert.Equal(t, int64(0), c.MaxLoadedModels)
	assert.Equal(t, int64(0), c.ContextLength)
}

func TestResolveHost(t *testing.T) {
	for _, tc := range []struct {
		in            string
		wantURL       string
		wantBind      string
		wantPort      int64
		wantTLS       bool
		wantAllIfaces bool
	}{
		{"", "http://127.0.0.1:11434", "127.0.0.1", 11434, false, false},
		// The bare bind address is the form the install docs hand out, and the
		// one that puts the API on the network.
		{"0.0.0.0", "http://0.0.0.0:11434", "0.0.0.0", 11434, false, true},
		{"0.0.0.0:11434", "http://0.0.0.0:11434", "0.0.0.0", 11434, false, true},
		{"::", "http://[::]:11434", "::", 11434, false, true},
		{"[::]:11434", "http://[::]:11434", "::", 11434, false, true},
		{"127.0.0.1", "http://127.0.0.1:11434", "127.0.0.1", 11434, false, false},
		{"192.168.1.10:11434", "http://192.168.1.10:11434", "192.168.1.10", 11434, false, false},
		// A scheme changes the default port, so an https host with no port is
		// on 443 rather than on 11434.
		{"https://ollama.example.com", "https://ollama.example.com:443", "ollama.example.com", 443, true, false},
		{"http://ollama.example.com", "http://ollama.example.com:80", "ollama.example.com", 80, false, false},
		{"https://ollama.example.com:8443", "https://ollama.example.com:8443", "ollama.example.com", 8443, true, false},
		{"ollama.com", "https://ollama.com:443", "ollama.com", 443, true, false},
		// An out-of-range port falls back to the default rather than being
		// reported as configured.
		{"1.2.3.4:99999", "http://1.2.3.4:11434", "1.2.3.4", 11434, false, false},
		{"1.2.3.4:notaport", "http://1.2.3.4:11434", "1.2.3.4", 11434, false, false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			c := Resolve(map[string]string{"OLLAMA_HOST": tc.in}, "/home/u", nil)
			assert.Equal(t, tc.wantURL, c.Host)
			assert.Equal(t, tc.wantBind, c.BindAddress)
			assert.Equal(t, tc.wantPort, c.Port)
			assert.Equal(t, tc.wantTLS, c.TLS)
			assert.Equal(t, tc.wantAllIfaces, c.ListensOnAllInterfaces)
		})
	}
}

func TestResolve_Origins(t *testing.T) {
	c := Resolve(map[string]string{
		"OLLAMA_ORIGINS": "http://a.example, http://b.example ,",
	}, "/home/u", nil)
	assert.Equal(t, []string{"http://a.example", "http://b.example"}, c.Origins)
	assert.False(t, c.AllowsAnyOrigin)

	// Ollama turns on gin's wildcard matching, so a bare "*" is allow-any.
	c = Resolve(map[string]string{"OLLAMA_ORIGINS": "http://a.example,*"}, "/home/u", nil)
	assert.True(t, c.AllowsAnyOrigin)

	c = Resolve(nil, "/home/u", nil)
	assert.Empty(t, c.Origins)
	assert.False(t, c.AllowsAnyOrigin)
}

func TestResolve_Cloud(t *testing.T) {
	for _, tc := range []struct {
		name       string
		vars       map[string]string
		settings   *ServerSettings
		wantEnable bool
		wantSource string
	}{
		{"unset", nil, nil, true, "none"},
		{"env", map[string]string{"OLLAMA_NO_CLOUD": "1"}, nil, false, "env"},
		{"config", nil, &ServerSettings{DisableOllamaCloud: true}, false, "config"},
		{"both", map[string]string{"OLLAMA_NO_CLOUD": "true"}, &ServerSettings{DisableOllamaCloud: true}, false, "both"},
		{"config present but false", nil, &ServerSettings{DisableOllamaCloud: false}, true, "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Resolve(tc.vars, "/home/u", tc.settings)
			assert.Equal(t, tc.wantEnable, c.CloudEnabled)
			assert.Equal(t, tc.wantSource, c.CloudDisabledSource)
		})
	}
}

func TestResolve_Remotes(t *testing.T) {
	c := Resolve(map[string]string{"OLLAMA_REMOTES": "ollama.com,models.internal"}, "/home/u", nil)
	assert.Equal(t, []string{"ollama.com", "models.internal"}, c.Remotes)

	// An empty value is not "no remotes allowed"; Ollama falls back to its default.
	c = Resolve(map[string]string{"OLLAMA_REMOTES": ""}, "/home/u", nil)
	assert.Equal(t, []string{"ollama.com"}, c.Remotes)
}

func TestModelsPath(t *testing.T) {
	// The packaged Arch unit sets OLLAMA_MODELS, and the store is not under the
	// default path at all. Assuming $HOME/.ollama/models finds nothing there.
	assert.Equal(t, "/var/lib/ollama",
		ModelsPath(map[string]string{"OLLAMA_MODELS": "/var/lib/ollama"}, "/var/lib/ollama"))
	assert.Equal(t, "/home/u/.ollama/models", ModelsPath(nil, "/home/u"))
	assert.Equal(t, "/home/u/.ollama/models", ModelsPath(nil, "/home/u/"))
	assert.Equal(t, "", ModelsPath(nil, ""), "no home and no override yields no path, not a relative one")
}

// Ollama treats a boolean it cannot parse as true. Mirroring that matters in the
// permissive direction: OLLAMA_FLASH_ATTENTION=yes really does turn it on.
func TestResolve_BoolQuirks(t *testing.T) {
	assert.True(t, Resolve(map[string]string{"OLLAMA_FLASH_ATTENTION": "yes"}, "/h", nil).FlashAttention)
	assert.True(t, Resolve(map[string]string{"OLLAMA_FLASH_ATTENTION": "1"}, "/h", nil).FlashAttention)
	assert.False(t, Resolve(map[string]string{"OLLAMA_FLASH_ATTENTION": "0"}, "/h", nil).FlashAttention)
	assert.False(t, Resolve(map[string]string{"OLLAMA_FLASH_ATTENTION": "false"}, "/h", nil).FlashAttention)
	assert.False(t, Resolve(nil, "/h", nil).FlashAttention)

	assert.False(t, Resolve(map[string]string{"OLLAMA_NOHISTORY": "1"}, "/h", nil).HistoryEnabled)
	assert.True(t, Resolve(map[string]string{"OLLAMA_NOHISTORY": "0"}, "/h", nil).HistoryEnabled)
}

func TestResolve_LogLevel(t *testing.T) {
	for in, want := range map[string]string{
		"":      "info",
		"0":     "info",
		"false": "info",
		"1":     "debug",
		"true":  "debug",
		"2":     "trace",
		"3":     "trace",
		"junk":  "info",
	} {
		assert.Equal(t, want, Resolve(map[string]string{"OLLAMA_DEBUG": in}, "/h", nil).LogLevel, "OLLAMA_DEBUG=%q", in)
	}
}

func TestResolve_Durations(t *testing.T) {
	// KeepAlive: negative is unbounded, zero means unload immediately.
	assert.Equal(t, int64(Infinite), Resolve(map[string]string{"OLLAMA_KEEP_ALIVE": "-1"}, "/h", nil).KeepAliveSeconds)
	assert.Equal(t, int64(0), Resolve(map[string]string{"OLLAMA_KEEP_ALIVE": "0"}, "/h", nil).KeepAliveSeconds)
	assert.Equal(t, int64(600), Resolve(map[string]string{"OLLAMA_KEEP_ALIVE": "10m"}, "/h", nil).KeepAliveSeconds)
	assert.Equal(t, int64(45), Resolve(map[string]string{"OLLAMA_KEEP_ALIVE": "45"}, "/h", nil).KeepAliveSeconds)
	assert.Equal(t, int64(300), Resolve(map[string]string{"OLLAMA_KEEP_ALIVE": "junk"}, "/h", nil).KeepAliveSeconds)

	// LoadTimeout differs: zero is unbounded there, not instant.
	assert.Equal(t, int64(Infinite), Resolve(map[string]string{"OLLAMA_LOAD_TIMEOUT": "0"}, "/h", nil).LoadTimeoutSeconds)
	assert.Equal(t, int64(Infinite), Resolve(map[string]string{"OLLAMA_LOAD_TIMEOUT": "-5m"}, "/h", nil).LoadTimeoutSeconds)
	assert.Equal(t, int64(120), Resolve(map[string]string{"OLLAMA_LOAD_TIMEOUT": "2m"}, "/h", nil).LoadTimeoutSeconds)
}

func TestResolve_Uints(t *testing.T) {
	c := Resolve(map[string]string{
		"OLLAMA_NUM_PARALLEL":      "8",
		"OLLAMA_MAX_LOADED_MODELS": "3",
		"OLLAMA_MAX_QUEUE":         "not-a-number",
		"OLLAMA_CONTEXT_LENGTH":    "32768",
		"OLLAMA_GPU_OVERHEAD":      "1073741824",
	}, "/h", nil)

	assert.Equal(t, int64(8), c.NumParallel)
	assert.Equal(t, int64(3), c.MaxLoadedModels)
	assert.Equal(t, int64(512), c.MaxQueue, "an unparseable value falls back to the default, not to zero")
	assert.Equal(t, int64(32768), c.ContextLength)
	assert.Equal(t, int64(1073741824), c.GpuOverhead)
}

// Quotes survive being carried through a unit file, and a value still wrapped in
// them must not be compared as though the quotes were part of it.
func TestResolve_StripsQuotes(t *testing.T) {
	c := Resolve(map[string]string{
		"OLLAMA_HOST":   `"0.0.0.0:11434"`,
		"OLLAMA_MODELS": ` '/srv/models' `,
	}, "/h", nil)

	assert.Equal(t, "0.0.0.0", c.BindAddress)
	assert.True(t, c.ListensOnAllInterfaces)
	assert.Equal(t, "/srv/models", c.ModelsPath)
}

func TestResolve_Proxies(t *testing.T) {
	c := Resolve(map[string]string{
		"https_proxy": "http://proxy.internal:3128",
		"NO_PROXY":    "localhost,127.0.0.1",
	}, "/h", nil)

	assert.Equal(t, "http://proxy.internal:3128", c.HTTPSProxy, "the lowercase spelling is honored")
	assert.Equal(t, "localhost,127.0.0.1", c.NoProxy)
	assert.Empty(t, c.HTTPProxy)
}

func TestIsConfigVar(t *testing.T) {
	for _, name := range []string{
		"OLLAMA_HOST", "OLLAMA_MODELS", "OLLAMA_KEEP_ALIVE", "OLLAMA_KV_CACHE_TYPE",
		"OLLAMA_NO_CLOUD", "LLAMA_ARG_FIT", "HOME",
		"HTTP_PROXY", "https_proxy", "no_proxy",
		"CUDA_VISIBLE_DEVICES", "HSA_OVERRIDE_GFX_VERSION",
	} {
		assert.True(t, IsConfigVar(name), name)
	}

	for _, name := range []string{
		// Credential-shaped names are excluded even under the OLLAMA_ prefix.
		"OLLAMA_API_TOKEN", "OLLAMA_API_KEY", "AWS_SECRET_ACCESS_KEY",
		"DB_PASSWORD", "GH_TOKEN", "SERVICE_CREDENTIALS", "MY_APIKEY",
		// So is anything that is not an Ollama setting at all.
		"PATH", "USER", "LD_LIBRARY_PATH", "SYSTEMD_EXEC_PID",
	} {
		assert.False(t, IsConfigVar(name), name)
	}
}

// The settings whose names come closest to the credential filter must survive
// it: dropping OLLAMA_KEEP_ALIVE as a secret would silently lose a real value.
func TestConfigVars(t *testing.T) {
	got := ConfigVars(map[string]string{
		"OLLAMA_HOST":       "0.0.0.0",
		"OLLAMA_KEEP_ALIVE": "-1",
		"OLLAMA_API_TOKEN":  "sk-should-not-appear",
		"HOME":              "/var/lib/ollama",
		"PATH":              "/usr/bin",
	})

	assert.Equal(t, map[string]string{
		"OLLAMA_HOST":       "0.0.0.0",
		"OLLAMA_KEEP_ALIVE": "-1",
		"HOME":              "/var/lib/ollama",
	}, got)
}
