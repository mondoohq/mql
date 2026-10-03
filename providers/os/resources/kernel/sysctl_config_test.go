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

// The configuration file from the RHEL 7 and RHEL 8 reproductions, after an
// explicit kernel.kptr_restrict = 1 in an earlier file.
var legacySysctlFiles = []sysctlFile{
	{"/etc/sysctl.d/90-g01.conf", "kernel.kptr_restrict = 1\n"},
	{"/etc/sysctl.d/91-g01dash.conf", `-kernel.kptr_restrict = 2
net.ipv4.conf.*.log_martians = 1
-net.ipv4.conf.lo.log_martians
`},
}

func parseSysctlFilesWith(t *testing.T, features SysctlFeatures, files ...sysctlFile) *SysctlConfig {
	t.Helper()
	cfg := NewSysctlConfig()
	cfg.Features = features
	for _, f := range files {
		require.NoError(t, cfg.Parse(strings.NewReader(f.content), f.path))
	}
	return cfg
}

// systemd 219 (RHEL 7) knows neither a "-" prefix nor globs. It wrote "2" to
// /proc/sys/-kernel/kptr_restrict and "1" to the literal path
// net/ipv4/conf/*/log_martians, both failed, and the live values stayed 1
// and 0.
func TestSysctlConfigSystemd219(t *testing.T) {
	cfg := parseSysctlFilesWith(t, SysctlFeatures{}, legacySysctlFiles...)

	v, ok := effectiveValue(cfg, "kernel.kptr_restrict")
	assert.True(t, ok)
	assert.Equal(t, "1", v)

	_, ok = effectiveValue(cfg, "net.ipv4.conf.eth0.log_martians")
	assert.False(t, ok)

	// The dashed key is a parameter of its own, which no kernel has.
	settings, i := cfg.Lookup("-kernel.kptr_restrict")
	require.Equal(t, 0, i)
	assert.Equal(t, "-kernel.kptr_restrict", settings[0].Key)
	assert.False(t, settings[0].IgnoreErrors)

	// The glob is a literal name too, listed on its own, and the exclusion
	// line is not an assignment.
	assert.False(t, cfg.IsGlob("net.ipv4.conf.*.log_martians"))
	v, ok = effectiveValue(cfg, "net.ipv4.conf.*.log_martians")
	assert.True(t, ok)
	assert.Equal(t, "1", v)
	assert.Empty(t, cfg.Exclusions)
}

// systemd 239 on RHEL 8 has the "-" prefix backported, not globs: it set
// kernel.kptr_restrict to 2 and logged "Couldn't write '1' to
// 'net/ipv4/conf/*/log_martians', ignoring".
func TestSysctlConfigSystemdDashWithoutGlobs(t *testing.T) {
	cfg := parseSysctlFilesWith(t, SysctlFeatures{IgnoreErrorsPrefix: true}, legacySysctlFiles...)

	v, ok := effectiveValue(cfg, "kernel.kptr_restrict")
	assert.True(t, ok)
	assert.Equal(t, "2", v)
	settings, i := cfg.Lookup("kernel.kptr_restrict")
	assert.True(t, settings[i].IgnoreErrors)

	_, ok = effectiveValue(cfg, "net.ipv4.conf.eth0.log_martians")
	assert.False(t, ok)
	assert.Empty(t, cfg.Exclusions)
}

func TestSysctlConfigSystemdModern(t *testing.T) {
	cfg := parseSysctlFiles(t, legacySysctlFiles...)

	v, _ := effectiveValue(cfg, "kernel.kptr_restrict")
	assert.Equal(t, "2", v)
	v, ok := effectiveValue(cfg, "net.ipv4.conf.eth0.log_martians")
	assert.True(t, ok)
	assert.Equal(t, "1", v)
	_, ok = effectiveValue(cfg, "net.ipv4.conf.lo.log_martians")
	assert.False(t, ok)
}

func TestParseSystemdSysctlFeatures(t *testing.T) {
	none := SysctlFeatures{}
	dash := SysctlFeatures{IgnoreErrorsPrefix: true}
	all := SysctlFeatures{IgnoreErrorsPrefix: true, Globs: true}
	for out, want := range map[string]SysctlFeatures{
		// RHEL 7
		"systemd 219\n+PAM +AUDIT +SELINUX +IMA -APPARMOR +SMACK +SYSVINIT\n": none,
		// Debian 9, Ubuntu 18.04, Debian 10
		"systemd 232\n+PAM +AUDIT\n":          none,
		"systemd 237\n+PAM +AUDIT +SELINUX\n": none,
		"systemd 241 (241)\n+PAM +AUDIT\n":    none,
		"systemd 242\n":                       none,
		// RHEL 8 before and after the backport of the "-" prefix
		"systemd 239 (239-51.el8_5.2)\n+PAM\n":    none,
		"systemd 239 (239-57.el8)\n+PAM\n":        dash,
		"systemd 239 (239-82.el8_10.17)\n+PAM\n":  dash,
		"systemd 243\n":                           dash,
		"systemd 244 (244.1-1)\n":                 dash,
		"systemd 245 (245.4-4ubuntu3.24)\n+PAM\n": all,
		"systemd 252 (252-51.el9_6.1)\n":          all,
		"systemd 258 (258.2-1.fc44)\n":            all,
	} {
		got, ok := ParseSystemdSysctlFeatures(out)
		assert.True(t, ok, out)
		assert.Equal(t, want, got, out)
	}

	for _, out := range []string{"", "bash: systemd-sysctl: command not found\n", "systemd\n"} {
		_, ok := ParseSystemdSysctlFeatures(out)
		assert.False(t, ok, out)
	}
}
