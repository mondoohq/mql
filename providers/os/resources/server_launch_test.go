// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/tar"
	"go.mondoo.com/mql/utils/syncx"
)

// /proc of the official haproxy image started with
// `docker run haproxy haproxy -f /opt/alt.cfg`: its docker-entrypoint.sh
// adds -W -db, so pid 1 is the master and pid 8 its worker, and -db means
// no pid file is written.
var haproxyImageProc = map[string]string{
	"/proc/1/cmdline":  "haproxy\x00-W\x00-db\x00-f\x00/opt/alt.cfg\x00",
	"/proc/1/stat":     "1 (haproxy) S 0 1 1 0 -1 4194560 4398 0 0 0 2 5 0 0 20 0 1 0 2444339 115486720 5400",
	"/proc/8/cmdline":  "haproxy\x00-W\x00-db\x00-f\x00/opt/alt.cfg\x00",
	"/proc/8/stat":     "8 (haproxy) S 1 1 1 0 -1 4194624 3621 0 0 0 2 5 0 0 20 0 14 0 2444354 1029615616 7094",
	"/proc/22/cmdline": "sh\x00-c\x00sleep 1\x00",
	"/proc/22/stat":    "22 (sh) S 0 22 22 0 -1 4194560 938 155 0 0 1 1 0 0 20 0 1 0 2444598 2473984 361",
}

const haproxyAltCfg = "global\n    maxconn 999\n"

// haproxyDecoyCfg sits at the default path but is not what haproxy loads.
const haproxyDecoyCfg = "global\n    maxconn 512\n"

type launchTestConn struct {
	*mock.Connection
	image *tar.ImageConfig
}

func (c *launchTestConn) LaunchConfig() *tar.ImageConfig { return c.image }

func newLaunchRuntime(t *testing.T, files map[string]string, commands map[string]*mock.Command, image *tar.ImageConfig) *plugin.Runtime {
	t.Helper()
	mockFiles := map[string]*mock.MockFileData{}
	for p, content := range files {
		mockFiles[p] = &mock.MockFileData{Path: p, Content: content}
		// the mock lists a directory only when it has an entry of its own
		for dir := path.Dir(p); dir != "/" && mockFiles[dir] == nil; dir = path.Dir(dir) {
			mockFiles[dir] = &mock.MockFileData{Path: dir, StatData: mock.FileInfo{IsDir: true, Mode: os.ModeDir | 0o755}}
		}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix"}}},
		mock.WithData(&mock.TomlData{Files: mockFiles, Commands: commands}))
	require.NoError(t, err)
	rt := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	if image != nil {
		rt.Connection = &launchTestConn{Connection: conn, image: image}
	} else {
		rt.Connection = conn
	}
	return rt
}

func mergeFiles(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// pgrepMissing is what a shell answers for pgrep in an image without procps.
func pgrepMissing(names string) map[string]*mock.Command {
	return map[string]*mock.Command{
		"pgrep -x '" + names + "'": {Stderr: "sh: 1: pgrep: not found", ExitStatus: 127},
	}
}

func TestFindServerLaunches(t *testing.T) {
	t.Run("pgrep missing: every /proc entry is read and the master wins", func(t *testing.T) {
		rt := newLaunchRuntime(t, haproxyImageProc, pgrepMissing("haproxy"), nil)
		got := findServerLaunches(rt, haproxyLaunch)
		require.Len(t, got, 1)
		assert.Equal(t, serverLaunchProcess, got[0].Source)
		assert.Equal(t, 1, got[0].Pid)
		assert.Equal(t, []string{"haproxy", "-W", "-db", "-f", "/opt/alt.cfg"}, got[0].Argv)
	})

	t.Run("pgrep narrows the processes read", func(t *testing.T) {
		files := mergeFiles(haproxyImageProc, map[string]string{
			// not listed by pgrep, so never read
			"/proc/300/cmdline": "haproxy\x00-f\x00/etc/other.cfg\x00",
			"/proc/300/stat":    "300 (haproxy) S 0 300 300 0 -1",
		})
		rt := newLaunchRuntime(t, files, map[string]*mock.Command{
			"pgrep -x 'haproxy'": {Stdout: "1\n8\n"},
		}, nil)
		got := findServerLaunches(rt, haproxyLaunch)
		require.Len(t, got, 1)
		assert.Equal(t, 1, got[0].Pid)
	})

	t.Run("pgrep finding nothing is an answer: /proc is not read", func(t *testing.T) {
		rt := newLaunchRuntime(t, haproxyImageProc, map[string]*mock.Command{
			"pgrep -x 'haproxy'": {ExitStatus: 1},
		}, nil)
		assert.Empty(t, findServerLaunches(rt, haproxyLaunch))
	})

	t.Run("environment of the master", func(t *testing.T) {
		files := map[string]string{
			"/proc/1/cmdline": "/bin/ollama\x00serve\x00",
			"/proc/1/stat":    "1 (ollama) S 0 1 1 0 -1",
			"/proc/1/environ": "PATH=/usr/local/sbin:/usr/local/bin\x00OLLAMA_HOST=0.0.0.0:11434\x00OLLAMA_ORIGINS=*\x00",
		}
		rt := newLaunchRuntime(t, files, pgrepMissing("ollama"), nil)
		got := findServerLaunches(rt, serverLaunchSpec{Names: []string{"ollama"}, Env: true})
		require.Len(t, got, 1)
		assert.NoError(t, got[0].EnvErr)
		assert.Equal(t, "*", got[0].Env["OLLAMA_ORIGINS"])
		assert.Equal(t, "0.0.0.0:11434", got[0].Env["OLLAMA_HOST"])
	})

	t.Run("an unreadable environment is reported, not empty", func(t *testing.T) {
		files := map[string]string{
			"/proc/1/cmdline": "/bin/ollama\x00serve\x00",
			"/proc/1/stat":    "1 (ollama) S 0 1 1 0 -1",
		}
		rt := newLaunchRuntime(t, files, pgrepMissing("ollama"), nil)
		got := findServerLaunches(rt, serverLaunchSpec{Names: []string{"ollama"}, Env: true})
		require.Len(t, got, 1)
		assert.Error(t, got[0].EnvErr)
		assert.Nil(t, got[0].Env)
	})

	t.Run("image configuration when no process runs", func(t *testing.T) {
		// haproxy:latest's configuration
		image := &tar.ImageConfig{
			Entrypoint: []string{"docker-entrypoint.sh"},
			Cmd:        []string{"haproxy", "-f", "haproxy.cfg"},
			Env:        []string{"PATH=/usr/local/sbin:/usr/local/bin", "HAPROXY_VERSION=3.4.6"},
			WorkingDir: "/usr/local/etc/haproxy",
		}
		rt := newLaunchRuntime(t, map[string]string{"/etc/hostname": "x"}, nil, image)
		got := findServerLaunches(rt, serverLaunchSpec{Names: haproxyLaunch.Names, IsServer: haproxyLaunch.IsServer, Env: true})
		require.Len(t, got, 1)
		assert.Equal(t, serverLaunchImage, got[0].Source)
		assert.Equal(t, []string{"haproxy", "-f", "haproxy.cfg"}, got[0].Argv)
		assert.Equal(t, "3.4.6", got[0].Env["HAPROXY_VERSION"])
		assert.Equal(t, "/usr/local/etc/haproxy/haproxy.cfg", got[0].resolve("haproxy.cfg"))
	})

	t.Run("an image that starts another program", func(t *testing.T) {
		image := &tar.ImageConfig{Entrypoint: []string{"docker-entrypoint.sh"}, Cmd: []string{"postgres"}}
		rt := newLaunchRuntime(t, map[string]string{"/etc/hostname": "x"}, nil, image)
		assert.Empty(t, findServerLaunches(rt, haproxyLaunch))
	})
}

func TestServerLaunchResolve(t *testing.T) {
	assert.Equal(t, "/etc/haproxy/haproxy.cfg", serverLaunch{}.resolve("etc/haproxy/haproxy.cfg"), "systemd and a container without WORKDIR start in /")
	assert.Equal(t, "/var/lib/haproxy/a.cfg", serverLaunch{Dir: "/var/lib/haproxy"}.resolve("a.cfg"))
	assert.Equal(t, "/opt/alt.cfg", serverLaunch{Dir: "/var/lib/haproxy"}.resolve("/opt/alt.cfg"))
	assert.Equal(t, "", serverLaunch{Dir: "/x"}.resolve(""))
}

func TestHaproxyConfigFollowsRunningMaster(t *testing.T) {
	files := mergeFiles(haproxyImageProc, map[string]string{
		"/opt/alt.cfg":             haproxyAltCfg,
		"/etc/haproxy/haproxy.cfg": haproxyDecoyCfg,
	})
	rt := newLaunchRuntime(t, files, pgrepMissing("haproxy"), nil)
	res, err := NewResource(rt, "haproxy.config", nil)
	require.NoError(t, err)
	cfg := res.(*mqlHaproxyConfig)

	file := cfg.GetFile()
	require.NoError(t, file.Error)
	assert.Equal(t, "/opt/alt.cfg", file.Data.Path.Data)

	global := cfg.GetGlobal()
	require.NoError(t, global.Error)
	assert.Equal(t, int64(999), global.Data.GetMaxconn().Data)
}

func TestHaproxyConfigFollowsImage(t *testing.T) {
	// haproxy:latest's configuration, with its config at the path the
	// image's Cmd names rather than the distribution default
	image := &tar.ImageConfig{
		Entrypoint: []string{"docker-entrypoint.sh"},
		Cmd:        []string{"haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"},
		WorkingDir: "/var/lib/haproxy",
	}
	rt := newLaunchRuntime(t, map[string]string{"/usr/local/etc/haproxy/haproxy.cfg": haproxyAltCfg}, nil, image)
	res, err := NewResource(rt, "haproxy.config", nil)
	require.NoError(t, err)
	cfg := res.(*mqlHaproxyConfig)

	file := cfg.GetFile()
	require.NoError(t, file.Error)
	assert.Equal(t, "/usr/local/etc/haproxy/haproxy.cfg", file.Data.Path.Data)
	global := cfg.GetGlobal()
	require.NoError(t, global.Error)
	assert.Equal(t, int64(999), global.Data.GetMaxconn().Data)
}
