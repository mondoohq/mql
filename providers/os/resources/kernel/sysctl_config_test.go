// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sysctlFile struct {
	path    string
	content string
}

func parseSysctlFiles(t *testing.T, files ...sysctlFile) *SysctlConfig {
	t.Helper()
	cfg := NewSysctlConfig()
	for _, f := range files {
		require.NoError(t, cfg.Parse(strings.NewReader(f.content), f.path))
	}
	return cfg
}

// effectiveValue returns the value that takes effect for name, and false
// when no assignment does.
func effectiveValue(cfg *SysctlConfig, name string) (string, bool) {
	settings, i := cfg.Lookup(name)
	if i < 0 {
		return "", false
	}
	return settings[i].Value, true
}

func TestNormalizeSysctlName(t *testing.T) {
	for in, want := range map[string]string{
		"fs.protected_hardlinks":              "fs.protected_hardlinks",
		"fs/protected_hardlinks":              "fs.protected_hardlinks",
		"/fs/protected_hardlinks":             "fs.protected_hardlinks",
		"  kernel.domainname ":                "kernel.domainname",
		"net.ipv4.conf.enp3s0/200.forwarding": "net.ipv4.conf.enp3s0/200.forwarding",
		"net/ipv4/conf/enp3s0.200/forwarding": "net.ipv4.conf.enp3s0/200.forwarding",
		"key.middle/part/with/dots.foo":       "key.middle/part/with/dots.foo",
		"key/middle.part.with.dots/foo":       "key.middle/part/with/dots.foo",
		"vm":                                  "vm",
		"net/ipv4/conf/*/rp_filter":           "net.ipv4.conf.*.rp_filter",
	} {
		assert.Equal(t, want, NormalizeSysctlName(in), in)
	}
}

func TestNormalizeSysctlValue(t *testing.T) {
	assert.Equal(t, "32768 60999", NormalizeSysctlValue("32768\t60999"))
	assert.Equal(t, "32768 60999", NormalizeSysctlValue("  32768   60999 "))
	assert.Equal(t, "", NormalizeSysctlValue(" "))
}

func TestSysctlConfigParse(t *testing.T) {
	cfg := parseSysctlFiles(t, sysctlFile{"/etc/sysctl.d/10-test.conf", `
# comment
; also a comment
fs.protected_hardlinks = 1
kernel/yama/ptrace_scope=2
-net.ipv4.conf.all.rp_filter = 0
-net.ipv4.conf.lo.rp_filter
not an assignment
kernel.domainname = a=b
net.ipv4.ip_local_port_range = 32768	60999
 = orphan value
`})

	require.Len(t, cfg.Assignments, 5)
	assert.Equal(t, SysctlAssignment{
		Key: "fs.protected_hardlinks", Name: "fs.protected_hardlinks", Value: "1",
		File: "/etc/sysctl.d/10-test.conf", Line: 4,
	}, cfg.Assignments[0])
	assert.Equal(t, "kernel/yama/ptrace_scope", cfg.Assignments[1].Key)
	assert.Equal(t, "kernel.yama.ptrace_scope", cfg.Assignments[1].Name)
	assert.Equal(t, 5, cfg.Assignments[1].Line)

	// A leading "-" on an assignment ignores errors, the key is the same.
	assert.Equal(t, "net.ipv4.conf.all.rp_filter", cfg.Assignments[2].Name)
	assert.True(t, cfg.Assignments[2].IgnoreErrors)

	// "-key" with no value excludes from globs and is not an assignment.
	assert.True(t, cfg.Exclusions["net.ipv4.conf.lo.rp_filter"])

	// A value is split at the first "=" only.
	assert.Equal(t, "a=b", cfg.Assignments[3].Value)
	assert.Equal(t, "32768 60999", cfg.Assignments[4].Value)
}

// The last assignment of a key takes effect, and every earlier one is still
// reported. The PR this resource replaces accepted any of them.
func TestSysctlConfigLastWins(t *testing.T) {
	cfg := parseSysctlFiles(t,
		sysctlFile{"/etc/sysctl.d/10-hardening.conf", "fs.protected_hardlinks = 1\n"},
		sysctlFile{"/etc/sysctl.d/99-local.conf", "fs/protected_hardlinks = 0\n"},
	)

	settings, i := cfg.Lookup("fs.protected_hardlinks")
	require.Len(t, settings, 2)
	assert.Equal(t, 1, i)
	assert.Equal(t, "0", settings[i].Value)
	assert.Equal(t, "/etc/sysctl.d/99-local.conf", settings[i].File)
}

func TestSysctlConfigUnset(t *testing.T) {
	cfg := parseSysctlFiles(t, sysctlFile{"/etc/sysctl.conf", "fs.suid_dumpable = 0\n"})
	settings, i := cfg.Lookup("fs.protected_hardlinks")
	assert.Empty(t, settings)
	assert.Equal(t, -1, i)
}

// Measured on Debian 12 with systemd-sysctl 252 and procps-ng 4.0.2: an
// explicit key is excluded from a glob even when the glob comes later.
func TestSysctlConfigExplicitBeatsLaterGlob(t *testing.T) {
	cfg := parseSysctlFiles(t,
		sysctlFile{"/etc/sysctl.d/10-explicit.conf", "net.ipv4.conf.lo.rp_filter = 0\n"},
		sysctlFile{"/etc/sysctl.d/20-glob.conf", "net.ipv4.conf.*.rp_filter = 2\n"},
	)

	v, ok := effectiveValue(cfg, "net.ipv4.conf.lo.rp_filter")
	assert.True(t, ok)
	assert.Equal(t, "0", v)

	// The glob is still listed for lo, it just doesn't take effect.
	settings, i := cfg.Lookup("net.ipv4.conf.lo.rp_filter")
	require.Len(t, settings, 2)
	assert.Equal(t, 0, i)

	v, ok = effectiveValue(cfg, "net.ipv4.conf.eth0.rp_filter")
	assert.True(t, ok)
	assert.Equal(t, "2", v)
}

// RHEL 9 ships this shape in /usr/lib/sysctl.d/50-redhat.conf: set every
// interface, exclude "all".
func TestSysctlConfigGlobExclusion(t *testing.T) {
	cfg := parseSysctlFiles(t, sysctlFile{"/usr/lib/sysctl.d/50-redhat.conf", `
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.*.rp_filter = 1
-net.ipv4.conf.all.rp_filter
`})

	settings, i := cfg.Lookup("net.ipv4.conf.all.rp_filter")
	require.Len(t, settings, 1)
	assert.Equal(t, -1, i)

	v, ok := effectiveValue(cfg, "net.ipv4.conf.eth0.rp_filter")
	assert.True(t, ok)
	assert.Equal(t, "1", v)

	// default is set explicitly, the glob matches it too
	settings, i = cfg.Lookup("net.ipv4.conf.default.rp_filter")
	require.Len(t, settings, 2)
	assert.Equal(t, 0, i)
}

func TestSysctlConfigLastGlobWins(t *testing.T) {
	cfg := parseSysctlFiles(t,
		sysctlFile{"/etc/sysctl.d/10-a.conf", "net.ipv4.conf.*.rp_filter = 1\n"},
		sysctlFile{"/etc/sysctl.d/20-b.conf", "net.ipv4.conf.e*.rp_filter = 2\n"},
	)
	v, _ := effectiveValue(cfg, "net.ipv4.conf.eth0.rp_filter")
	assert.Equal(t, "2", v)
	v, _ = effectiveValue(cfg, "net.ipv4.conf.lo.rp_filter")
	assert.Equal(t, "1", v)
}

// A wildcard stays within one /proc/sys path component.
func TestSysctlConfigGlobComponent(t *testing.T) {
	assert.True(t, MatchSysctlGlob("net.ipv4.conf.*.rp_filter", "net.ipv4.conf.eth0.rp_filter"))
	// VLAN interface enp3s0.200 is the component "enp3s0/200" in dotted form
	assert.True(t, MatchSysctlGlob("net.ipv4.conf.*.rp_filter", "net.ipv4.conf.enp3s0/200.rp_filter"))
	assert.False(t, MatchSysctlGlob("net.*.rp_filter", "net.ipv4.conf.eth0.rp_filter"))
	assert.True(t, MatchSysctlGlob("net/ipv4/conf/*/rp_filter", "net.ipv4.conf.lo.rp_filter"))
	assert.True(t, MatchSysctlGlob("net.ipv4.conf.eth[!1].rp_filter", "net.ipv4.conf.eth0.rp_filter"))
	assert.False(t, MatchSysctlGlob("net.ipv4.conf.eth[!1].rp_filter", "net.ipv4.conf.eth1.rp_filter"))
}

// A glob that matched no live parameter is listed under its pattern, and only
// the assignments of exactly that pattern apply to it.
func TestSysctlConfigPatternLookup(t *testing.T) {
	cfg := parseSysctlFiles(t, sysctlFile{"/etc/sysctl.d/10-a.conf", `
net.ipv4.conf.*.rp_filter = 1
net.ipv4.conf.e*.rp_filter = 2
net.ipv4.conf.*.rp_filter = 3
`})
	settings, i := cfg.Lookup("net.ipv4.conf.*.rp_filter")
	require.Len(t, settings, 2)
	assert.Equal(t, "3", settings[i].Value)

	assert.Equal(t, []string{"net.ipv4.conf.*.rp_filter", "net.ipv4.conf.e*.rp_filter"}, cfg.Names())
}
