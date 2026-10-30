// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/systemd"
)

// TestHaproxyVersionRegex_RuntimeOutput covers the regex used against
// `haproxy -v` output. Both the legacy "HA-Proxy" and modern "HAProxy"
// banners must yield the same captured version body.
func TestHaproxyVersionRegex_RuntimeOutput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "modern 2.x banner",
			in:   "HAProxy version 2.8.24-eea79933d 2026/05/11 - https://haproxy.org/\nStatus: long-term supported branch",
			want: "2.8.24-eea79933d",
		},
		{
			name: "legacy 1.x banner",
			in:   "HA-Proxy version 1.8.31-1ppa1~jammy 2020/01/08 - https://haproxy.org/",
			want: "1.8.31-1ppa1~jammy",
		},
		{
			name: "no banner present",
			in:   "some unrelated text",
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := reHaproxyVersion.FindStringSubmatch(tc.in)
			if tc.want == "" {
				assert.Nil(t, m)
				return
			}
			require.Len(t, m, 2)
			assert.Equal(t, tc.want, m[1])
		})
	}
}

// TestHaproxyEmbeddedVersionRegex guards against the regression where the
// previous binary-scan logic returned "2.5." from the deprecation message
// `parsing [...]: the '...' keyword is not supported any more since
// HAProxy version 2.5.`. The replacement anchors on the `, released
// YYYY/MM/DD` marker so only the real embedded version string matches.
func TestHaproxyEmbeddedVersionRegex(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "real embedded version literal",
			in:   "0\x00 version 2.8.24-eea79933d, released 2026/05/11\nGCC: (Debian 14.2.0-19) 14.2.0\n",
			want: "2.8.24-eea79933d",
		},
		{
			name: "deprecation message must NOT match",
			in:   "parsing [%s:%d]: the '%s' keyword is not supported any more since HAProxy version 2.5.\ndispatch",
			want: "",
		},
		{
			name: "printf format string must NOT match",
			in:   "HAProxy version %s %s - https://haproxy.org/\nStatus: long-term",
			want: "",
		},
		{
			name: "version without suffix",
			in:   "padding\x00 version 3.0.0, released 2026/01/15\nGCC:",
			want: "3.0.0",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := reHaproxyEmbeddedVersion.FindStringSubmatch(tc.in)
			if tc.want == "" {
				assert.Nil(t, m, "unexpected match: %v", m)
				return
			}
			require.Len(t, m, 2)
			assert.Equal(t, tc.want, m[1])
		})
	}
}

// TestScanHaproxyBinary_FullScan exercises the chunked-read path against
// an afero in-memory file that holds the embedded version literal beyond
// the first 64 KiB so the carry-over logic gets exercised.
func TestScanHaproxyBinary_FullScan(t *testing.T) {
	fs := afero.NewMemMapFs()

	// Push the version literal past the first chunk boundary so the
	// rolling-overlap path is the one that finds it.
	padding := make([]byte, 80*1024)
	for i := range padding {
		padding[i] = 'x'
	}
	body := append(padding, []byte(" version 2.9.1, released 2026/03/01\nGCC:")...)
	require.NoError(t, afero.WriteFile(fs, "/usr/sbin/haproxy", body, 0o755))

	v := scanHaproxyBinary(&afero.Afero{Fs: fs}, "/usr/sbin/haproxy")
	assert.Equal(t, "2.9.1", v)

	// Non-existent path must return empty, not panic.
	assert.Equal(t, "", scanHaproxyBinary(&afero.Afero{Fs: fs}, "/nope"))

	// A binary that lacks the marker entirely returns empty (no false-
	// positive from a stray `version` token).
	require.NoError(t, afero.WriteFile(fs, "/no-marker", []byte("hello version foo bar"), 0o644))
	assert.Equal(t, "", scanHaproxyBinary(&afero.Afero{Fs: fs}, "/no-marker"))
}

func writeHaproxyFS(t *testing.T, files map[string]string) *afero.Afero {
	t.Helper()
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for p, c := range files {
		require.NoError(t, afs.WriteFile(p, []byte(c), 0o644))
	}
	return afs
}

// Ubuntu 24.04 [Service] lines that decide the haproxy command line.
const ubuntu2404HaproxyService = `[Service]
EnvironmentFile=-/etc/default/haproxy
EnvironmentFile=-/etc/sysconfig/haproxy
Environment="CONFIG=/etc/haproxy/haproxy.cfg" "PIDFILE=/run/haproxy.pid" "EXTRAOPTS=-S /run/haproxy-master.sock"
ExecStart=/usr/sbin/haproxy -Ws -f $CONFIG -p $PIDFILE $EXTRAOPTS
`

func TestHaproxyServiceLaunch_IgnoresUnpassedConfD(t *testing.T) {
	// conf.d exists but neither the unit nor /etc/default/haproxy passes it.
	afs := writeHaproxyFS(t, map[string]string{
		"/lib/systemd/system/haproxy.service": ubuntu2404HaproxyService,
		"/etc/default/haproxy":                "#CONFIG=\"/etc/haproxy/haproxy.cfg\"\n#EXTRAOPTS=\"-de -m 16\"\n",
		"/etc/haproxy/haproxy.cfg":            "global\n",
		"/etc/haproxy/conf.d/legacy.cfg":      "frontend legacy_unloaded\n\tbind *:9999\n",
	})
	got := haproxyServiceLaunch(afs, systemd.AllDropInDirs)
	assert.Equal(t, []string{"/etc/haproxy/haproxy.cfg"}, got.Configs)
	assert.Equal(t, "/run/haproxy.pid", got.PidFile)
}

func TestHaproxyServiceLaunch_DropInAndDefaults(t *testing.T) {
	afs := writeHaproxyFS(t, map[string]string{
		"/lib/systemd/system/haproxy.service":                 ubuntu2404HaproxyService,
		"/etc/default/haproxy":                                "EXTRAOPTS=\"-f /etc/haproxy/conf.d\"\n",
		"/etc/systemd/system/haproxy.service.d/override.conf": "[Service]\nEnvironment=CONFIG=/srv/lb.cfg\n",
	})
	got := haproxyServiceLaunch(afs, systemd.AllDropInDirs)
	assert.Equal(t, []string{"/srv/lb.cfg", "/etc/haproxy/conf.d"}, got.Configs)

	assert.Empty(t, haproxyServiceLaunch(writeHaproxyFS(t, nil), systemd.AllDropInDirs).Configs)
}

func TestHaproxyProcessConfigs(t *testing.T) {
	afs := writeHaproxyFS(t, map[string]string{
		"/run/haproxy.pid":    "22176\n",
		"/proc/22176/cmdline": "/usr/sbin/haproxy\x00-Ws\x00-f\x00/etc/haproxy/haproxy.cfg\x00-f\x00/etc/haproxy/conf.d\x00-p\x00/run/haproxy.pid\x00",
		"/run/stale.pid":      "4242\n",
		"/proc/4242/cmdline":  "/usr/sbin/sshd\x00-f\x00/etc/ssh/sshd_config\x00",
		"/run/garbage.pid":    "not-a-pid\n",
	})
	assert.Equal(t, []string{"/etc/haproxy/haproxy.cfg", "/etc/haproxy/conf.d"}, haproxyProcessConfigs(afs, "/run/haproxy.pid"))
	assert.Nil(t, haproxyProcessConfigs(afs, "/run/stale.pid"))
	assert.Nil(t, haproxyProcessConfigs(afs, "/run/garbage.pid"))
	assert.Nil(t, haproxyProcessConfigs(afs, "/run/missing.pid"))
}

func TestExpandHaproxyConfigArg(t *testing.T) {
	afs := writeHaproxyFS(t, map[string]string{
		"/etc/haproxy/haproxy.cfg":     "",
		"/etc/haproxy/conf.d/20-b.cfg": "",
		"/etc/haproxy/conf.d/10-a.cfg": "",
		"/etc/haproxy/conf.d/README":   "",
	})
	assert.Equal(t, []string{"/etc/haproxy/conf.d/10-a.cfg", "/etc/haproxy/conf.d/20-b.cfg"}, expandHaproxyConfigArg(afs, "/etc/haproxy/conf.d"))
	assert.Equal(t, []string{"/etc/haproxy/haproxy.cfg"}, expandHaproxyConfigArg(afs, "/etc/haproxy/haproxy.cfg"))
}

// /etc/systemd/system/service.d applies to haproxy.service too, on systemd
// releases that read type-level drop-ins.
func TestHaproxyServiceLaunch_TypeLevelDropIn(t *testing.T) {
	afs := writeHaproxyFS(t, map[string]string{
		"/lib/systemd/system/haproxy.service":   ubuntu2404HaproxyService,
		"/etc/systemd/system/service.d/zz.conf": "[Service]\nEnvironment=CONFIG=/srv/lb.cfg\n",
	})
	assert.Equal(t, []string{"/srv/lb.cfg"}, haproxyServiceLaunch(afs, systemd.AllDropInDirs).Configs)
	assert.Equal(t, []string{"/etc/haproxy/haproxy.cfg"}, haproxyServiceLaunch(afs, systemd.DropInDirsForVersion(241, false)).Configs)
}

func TestDropInDirsOnDisk(t *testing.T) {
	// RHEL 7: systemd 219, no libsystemd-shared
	rhel7 := writeHaproxyFS(t, map[string]string{"/usr/lib/systemd/systemd": ""})
	assert.Equal(t, systemd.DropInDirs{}, dropInDirsOnDisk(rhel7, true))

	// RHEL 8: 239 with the type-level backport
	rhel8 := writeHaproxyFS(t, map[string]string{
		"/usr/lib/systemd/systemd":                  "",
		"/usr/lib/systemd/libsystemd-shared-239.so": "",
	})
	assert.Equal(t, systemd.DropInDirs{Prefix: true, TypeLevel: true}, dropInDirsOnDisk(rhel8, true))

	// Debian 10: 241, no backport
	deb10 := writeHaproxyFS(t, map[string]string{
		"/lib/systemd/systemd":                  "",
		"/lib/systemd/libsystemd-shared-241.so": "",
	})
	assert.Equal(t, systemd.DropInDirs{Prefix: true}, dropInDirsOnDisk(deb10, false))

	// no systemd on disk reads like a current release
	assert.Equal(t, systemd.AllDropInDirs, dropInDirsOnDisk(writeHaproxyFS(t, nil), false))
}
