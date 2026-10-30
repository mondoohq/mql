// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// Install directive tests
func TestParseInstall_BasicCommand(t *testing.T) {
	content := "install pcspkr /bin/true"
	matches := installRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "pcspkr", matches[1])    // module
	assert.Equal(t, "/bin/true", matches[2]) // command
}

func TestParseInstall_ComplexCommand(t *testing.T) {
	content := "install nouveau /bin/false"
	matches := installRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "nouveau", matches[1])
	assert.Equal(t, "/bin/false", matches[2])
}

func TestParseInstall_CommandWithArguments(t *testing.T) {
	content := "install nvidia modprobe --ignore-install nvidia $CMDLINE_OPTS"
	matches := installRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "nvidia", matches[1])
	assert.Contains(t, matches[2], "modprobe")
	assert.Contains(t, matches[2], "$CMDLINE_OPTS")
}

// Remove directive tests
func TestParseRemove_BasicCommand(t *testing.T) {
	content := "remove pcspkr /bin/true"
	matches := removeRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "pcspkr", matches[1])
	assert.Equal(t, "/bin/true", matches[2])
}

func TestParseRemove_ComplexCommand(t *testing.T) {
	content := "remove nvidia /sbin/modprobe -r --ignore-remove nvidia"
	matches := removeRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "nvidia", matches[1])
	assert.Contains(t, matches[2], "modprobe -r")
}

// Blacklist directive tests
func TestParseBlacklist_SingleModule(t *testing.T) {
	content := "blacklist nouveau"
	matches := blacklistRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "nouveau", matches[1])
}

func TestParseBlacklist_ModuleWithUnderscore(t *testing.T) {
	content := "blacklist i2c_piix4"
	matches := blacklistRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "i2c_piix4", matches[1])
}

func TestParseBlacklist_ModuleWithHyphen(t *testing.T) {
	content := "blacklist floppy"
	matches := blacklistRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "floppy", matches[1])
}

// Options directive tests
func TestParseOptions_SingleParameter(t *testing.T) {
	content := "options snd-hda-intel power_save=1"
	matches := optionsRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "snd-hda-intel", matches[1])
	assert.Equal(t, "power_save=1", matches[2])
}

func TestParseOptions_MultipleParameters(t *testing.T) {
	content := "options nvidia NVreg_DeviceFileGID=44 NVreg_DeviceFileUID=0"
	matches := optionsRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "nvidia", matches[1])
	assert.Contains(t, matches[2], "NVreg_DeviceFileGID=44")
	assert.Contains(t, matches[2], "NVreg_DeviceFileUID=0")
}

func TestParseOptions_BooleanFlag(t *testing.T) {
	content := "options kvm_intel nested=1"
	matches := optionsRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "kvm_intel", matches[1])
	assert.Equal(t, "nested=1", matches[2])
}

func TestParseOptions_QuotedValue(t *testing.T) {
	content := `options module param="value with spaces"`
	matches := optionsRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "module", matches[1])
	assert.Contains(t, matches[2], "param=")
}

// Alias directive tests
func TestParseAlias_BasicAlias(t *testing.T) {
	content := "alias eth0 e1000e"
	matches := aliasRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "eth0", matches[1])
	assert.Equal(t, "e1000e", matches[2])
}

func TestParseAlias_WildcardPattern(t *testing.T) {
	content := "alias pci:v00008086d* e1000e"
	matches := aliasRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Contains(t, matches[1], "pci:")
	assert.Equal(t, "e1000e", matches[2])
}

func TestParseAlias_SymbolAlias(t *testing.T) {
	content := "alias symbol:nvidiafb nvidia"
	matches := aliasRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Contains(t, matches[1], "symbol:")
	assert.Equal(t, "nvidia", matches[2])
}

// Softdep directive tests
func TestParseSoftdep_PreOnly(t *testing.T) {
	content := "softdep nvidia pre: nvidia-uvm"
	matches := softdepRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "nvidia", matches[1])
	assert.Contains(t, matches[2], "pre:")
	assert.Contains(t, matches[2], "nvidia-uvm")
}

func TestParseSoftdep_PostOnly(t *testing.T) {
	content := "softdep nvidia post: nvidia-modeset"
	matches := softdepRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "nvidia", matches[1])
	assert.Contains(t, matches[2], "post:")
	assert.Contains(t, matches[2], "nvidia-modeset")
}

func TestParseSoftdep_PreAndPost(t *testing.T) {
	content := "softdep nvidia pre: nvidia-uvm post: nvidia-modeset"
	matches := softdepRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "nvidia", matches[1])
	assert.Contains(t, matches[2], "pre:")
	assert.Contains(t, matches[2], "post:")
}

func TestParseSoftdep_MultipleModules(t *testing.T) {
	content := "softdep drm pre: drm_kms_helper ttm post: i915"
	matches := softdepRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "drm", matches[1])
	assert.Contains(t, matches[2], "drm_kms_helper")
	assert.Contains(t, matches[2], "ttm")
	assert.Contains(t, matches[2], "i915")
}

// Comment and empty line tests
func TestParseDirectives_Comments(t *testing.T) {
	content := "# This is a comment"

	assert.Nil(t, installRegex.FindStringSubmatch(content))
	assert.Nil(t, removeRegex.FindStringSubmatch(content))
	assert.Nil(t, blacklistRegex.FindStringSubmatch(content))
	assert.Nil(t, optionsRegex.FindStringSubmatch(content))
	assert.Nil(t, aliasRegex.FindStringSubmatch(content))
	assert.Nil(t, softdepRegex.FindStringSubmatch(content))
}

func TestParseDirectives_EmptyLine(t *testing.T) {
	content := ""

	assert.Nil(t, installRegex.FindStringSubmatch(content))
	assert.Nil(t, removeRegex.FindStringSubmatch(content))
	assert.Nil(t, blacklistRegex.FindStringSubmatch(content))
	assert.Nil(t, optionsRegex.FindStringSubmatch(content))
	assert.Nil(t, aliasRegex.FindStringSubmatch(content))
	assert.Nil(t, softdepRegex.FindStringSubmatch(content))
}

// Real-world examples
func TestParseInstall_DisableModuleLoading(t *testing.T) {
	// Common pattern to prevent module from loading
	content := "install dccp /bin/false"
	matches := installRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "dccp", matches[1])
	assert.Equal(t, "/bin/false", matches[2])
}

func TestParseBlacklist_Nouveau(t *testing.T) {
	// Common pattern when using NVIDIA proprietary drivers
	content := "blacklist nouveau"
	matches := blacklistRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "nouveau", matches[1])
}

func TestParseOptions_NvidiaDriverOptions(t *testing.T) {
	content := "options nvidia-drm modeset=1"
	matches := optionsRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "nvidia-drm", matches[1])
	assert.Equal(t, "modeset=1", matches[2])
}

func TestParseOptions_MultipleSoundOptions(t *testing.T) {
	content := "options snd-hda-intel model=auto power_save=1"
	matches := optionsRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "snd-hda-intel", matches[1])
	assert.Contains(t, matches[2], "model=auto")
	assert.Contains(t, matches[2], "power_save=1")
}

func TestParseBlacklist_IPv6(t *testing.T) {
	// Common pattern to disable IPv6
	content := "blacklist ipv6"
	matches := blacklistRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "ipv6", matches[1])
}

func TestParseInstall_USBStorage(t *testing.T) {
	// Disable USB storage devices
	content := "install usb-storage /bin/true"
	matches := installRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "usb-storage", matches[1])
	assert.Equal(t, "/bin/true", matches[2])
}

func TestParseOptions_KVMNesting(t *testing.T) {
	content := "options kvm-intel nested=Y"
	matches := optionsRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "kvm-intel", matches[1])
	assert.Equal(t, "nested=Y", matches[2])
}

func TestParseSoftdep_ComplexDependency(t *testing.T) {
	content := "softdep cfg80211 pre: regulatory post: ath9k"
	matches := softdepRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "cfg80211", matches[1])
	assert.Contains(t, matches[2], "pre: regulatory")
	assert.Contains(t, matches[2], "post: ath9k")
}

// Edge cases
func TestParseOptions_EmptyParameters(t *testing.T) {
	// Invalid but should not crash
	content := "options module"
	matches := optionsRegex.FindStringSubmatch(content)

	// Should not match (no parameters)
	assert.Nil(t, matches)
}

func TestParseAlias_MultipleSpaces(t *testing.T) {
	content := "alias   eth0    e1000e"
	matches := aliasRegex.FindStringSubmatch(strings.TrimSpace(content))

	// After trim and normalize spaces, should still match
	require.NotNil(t, matches)
}

func TestParseSoftdep_OnlyKeyword(t *testing.T) {
	content := "softdep drm"
	matches := softdepRegex.FindStringSubmatch(content)

	// Should not match (no dependencies)
	assert.Nil(t, matches)
}

// parseModprobeParams tests
func TestParseModprobeParams_Simple(t *testing.T) {
	params := parseModprobeParams("key1=value1 key2=value2")

	assert.Equal(t, []string{"key1=value1", "key2=value2"}, params)
}

func TestParseModprobeParams_QuotedValue(t *testing.T) {
	params := parseModprobeParams(`key="value with spaces"`)

	require.Len(t, params, 1)
	assert.Equal(t, `key="value with spaces"`, params[0])
}

func TestParseModprobeParams_SingleQuotedValue(t *testing.T) {
	params := parseModprobeParams(`key='value with spaces'`)

	require.Len(t, params, 1)
	assert.Equal(t, `key='value with spaces'`, params[0])
}

func TestParseModprobeParams_MixedQuotedAndUnquoted(t *testing.T) {
	params := parseModprobeParams(`simple=value quoted="has spaces" another=test`)

	require.Len(t, params, 3)
	assert.Equal(t, "simple=value", params[0])
	assert.Equal(t, `quoted="has spaces"`, params[1])
	assert.Equal(t, "another=test", params[2])
}

func TestParseModprobeParams_BooleanFlags(t *testing.T) {
	params := parseModprobeParams("flag1 key=value flag2")

	require.Len(t, params, 3)
	assert.Equal(t, "flag1", params[0])
	assert.Equal(t, "key=value", params[1])
	assert.Equal(t, "flag2", params[2])
}

func TestParseModprobeParams_Empty(t *testing.T) {
	params := parseModprobeParams("")

	assert.Empty(t, params)
}

func TestParseModprobeParams_MultipleSpaces(t *testing.T) {
	params := parseModprobeParams("key1=value1    key2=value2")

	assert.Equal(t, []string{"key1=value1", "key2=value2"}, params)
}

func TestParseModprobeParams_TabSeparated(t *testing.T) {
	params := parseModprobeParams("key1=value1\tkey2=value2")

	assert.Equal(t, []string{"key1=value1", "key2=value2"}, params)
}

// The options line from the Ubuntu sweep fixture. Every value in the map must
// be a string: the field is map[string]string, and a bool for the bare
// `verbose` flag made the whole options list fail to serialize.
func TestParseModprobeOptionParams_BareFlagIsString(t *testing.T) {
	params := parseModprobeOptionParams(`debug=1 name="hello world" verbose 'mode=a b'`)

	assert.Equal(t, map[string]any{
		"debug":   "1",
		"name":    "hello world",
		"verbose": "true",
		"mode":    "a b",
	}, params)
	for k, v := range params {
		_, ok := v.(string)
		assert.Truef(t, ok, "param %q has non-string value %T", k, v)
	}
}

func TestParseModprobeOptionParams_ListValue(t *testing.T) {
	params := parseModprobeOptionParams("InterruptThrottleRate=3000,3000")
	assert.Equal(t, map[string]any{"InterruptThrottleRate": "3000,3000"}, params)
}

func TestParseModprobeOptionParams_Empty(t *testing.T) {
	assert.Empty(t, parseModprobeOptionParams(""))
}

// Directory listings as found on an Ubuntu 24.04 sweep host plus a /run
// override. modprobe -c on that host showed that /etc beats /run beats
// /usr/local/lib beats /usr/lib and /lib for the same file name, and that
// files are applied in name order across all directories.
func TestSelectModprobeConfigFiles(t *testing.T) {
	listings := [][]string{
		// /etc/modprobe.d
		{"blacklist.conf", "g01-ovr.conf", "ignored.txt", "sweep.conf", "zz-linked.conf"},
		// /run/modprobe.d
		{"sweep-lib.conf", "zz-run.conf"},
		// /usr/local/lib/modprobe.d
		{"sweep-lib.conf"},
		// /usr/lib/modprobe.d
		{"aliases.conf", "g01-ovr.conf", "sweep-lib.conf", "systemd.conf"},
		// /lib/modprobe.d (same directory as /usr/lib on merged-/usr)
		{"aliases.conf", "g01-ovr.conf", "sweep-lib.conf", "systemd.conf"},
	}

	got := selectConfDFiles(modprobeSearchPaths, listings)
	assert.Equal(t, []string{
		"/usr/lib/modprobe.d/aliases.conf",
		"/etc/modprobe.d/blacklist.conf",
		"/etc/modprobe.d/g01-ovr.conf",
		"/run/modprobe.d/sweep-lib.conf",
		"/etc/modprobe.d/sweep.conf",
		"/usr/lib/modprobe.d/systemd.conf",
		"/etc/modprobe.d/zz-linked.conf",
		"/run/modprobe.d/zz-run.conf",
	}, got)
}

// Ubuntu 16.04: kmod 22 has no /usr/lib/modprobe.d, the kernel package ships
// its blacklist in /lib/modprobe.d.
func TestSelectModprobeConfigFiles_LibOnly(t *testing.T) {
	listings := [][]string{
		{"sweep.conf"},
		nil,
		nil,
		nil,
		{"blacklist_linux-aws_4.4.0-1191-aws.conf", "sweep-lib.conf"},
	}

	got := selectConfDFiles(modprobeSearchPaths, listings)
	assert.Equal(t, []string{
		"/lib/modprobe.d/blacklist_linux-aws_4.4.0-1191-aws.conf",
		"/lib/modprobe.d/sweep-lib.conf",
		"/etc/modprobe.d/sweep.conf",
	}, got)
}

func TestSelectModprobeConfigFiles_Empty(t *testing.T) {
	assert.Empty(t, selectConfDFiles(modprobeSearchPaths, make([][]string, len(modprobeSearchPaths))))
}

// First lines of `kmod --version` on the sweep hosts: RHEL 7 (kmod 20),
// RHEL 9 (28), Fedora 44 and Debian 13 (34.2).
func TestParseKmodRelease(t *testing.T) {
	assert.Equal(t, 20, parseKmodRelease("kmod version 20\n-XZ +ZLIB -OPENSSL\n"))
	assert.Equal(t, 28, parseKmodRelease("kmod version 28\n+ZSTD +XZ +ZLIB +LIBCRYPTO -EXPERIMENTAL\n"))
	assert.Equal(t, 34, parseKmodRelease("kmod version 34.2\n+ZSTD +XZ +ZLIB +OPENSSL\n"))
	assert.Equal(t, 0, parseKmodRelease(""))
	assert.Equal(t, 0, parseKmodRelease("sh: kmod: command not found\n"))
}

// Directories each kmod release reads, checked against the paths compiled
// into kmod (strings $(command -v kmod)) and modprobe -c on the sweep hosts.
func TestModprobeSearchPathsFor(t *testing.T) {
	all := modprobeSearchPaths

	// RHEL/Alma 7, 8, 9 (kmod 20, 25, 28), merged /usr: no /usr/local/lib.
	// /usr/lib/modprobe.d is /lib/modprobe.d there, so it stays.
	el := []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"}
	assert.Equal(t, el, modprobeSearchPathsFor(20, true, false))
	assert.Equal(t, el, modprobeSearchPathsFor(25, true, false))
	assert.Equal(t, el, modprobeSearchPathsFor(28, true, false))

	// Debian 9 (kmod 23), /lib is a real directory: only /etc, /run, /lib.
	assert.Equal(t, []string{"/etc/modprobe.d", "/run/modprobe.d", "/lib/modprobe.d"},
		modprobeSearchPathsFor(23, false, false))

	// SLES/Leap 15 (kmod 29), /lib is a real directory, but SUSE's kmod
	// reads /usr/lib/modprobe.d.
	assert.Equal(t, all, modprobeSearchPathsFor(29, false, true))

	// Debian 12 (kmod 30, merged), RHEL 10 (31), Fedora 44 (34): everything.
	assert.Equal(t, all, modprobeSearchPathsFor(30, true, false))
	assert.Equal(t, all, modprobeSearchPathsFor(31, true, false))
	assert.Equal(t, all, modprobeSearchPathsFor(34, false, false))

	// Unknown release: keep everything.
	assert.Equal(t, all, modprobeSearchPathsFor(0, false, false))
}

// RHEL 8 sweep host (kmod 25): /usr/local/lib/modprobe.d/sweep-local.conf
// blacklists sweeplocal, but modprobe -c shows no trace of it.
func TestSelectModprobeConfigFiles_Kmod25SkipsUsrLocal(t *testing.T) {
	lib := []string{"blacklist-amdgpu.conf", "blacklist-nouveau.conf", "dist-blacklist.conf", "sweep-lib.conf", "sweep-run.conf", "sweep-shadow.conf", "systemd.conf"}
	onDisk := map[string][]string{
		"/etc/modprobe.d":           {"firewalld-sysctls.conf", "ignored.txt", "sweep.conf", "sweep-shadow.conf", "tuned.conf", "zz-linked.conf"},
		"/run/modprobe.d":           {"sweep-run.conf"},
		"/usr/local/lib/modprobe.d": {"sweep-local.conf"},
		"/usr/lib/modprobe.d":       lib,
		"/lib/modprobe.d":           lib,
	}
	dirs := modprobeSearchPathsFor(25, true, false)
	listings := make([][]string, len(dirs))
	for i, dir := range dirs {
		listings[i] = onDisk[dir]
	}
	got := selectConfDFiles(dirs, listings)
	assert.NotContains(t, got, "/usr/local/lib/modprobe.d/sweep-local.conf")
	assert.Equal(t, []string{
		"/usr/lib/modprobe.d/blacklist-amdgpu.conf",
		"/usr/lib/modprobe.d/blacklist-nouveau.conf",
		"/usr/lib/modprobe.d/dist-blacklist.conf",
		"/etc/modprobe.d/firewalld-sysctls.conf",
		"/usr/lib/modprobe.d/sweep-lib.conf",
		"/run/modprobe.d/sweep-run.conf",
		"/etc/modprobe.d/sweep-shadow.conf",
		"/etc/modprobe.d/sweep.conf",
		"/usr/lib/modprobe.d/systemd.conf",
		"/etc/modprobe.d/tuned.conf",
		"/etc/modprobe.d/zz-linked.conf",
	}, got)
}

// SLES 15 SP7 / Leap 15.6 sweep hosts (kmod 29, /lib a real directory), a
// subset of /lib/modprobe.d plus the fixtures. modprobe --showconfig applies
// both g01-local (/usr/local/lib) and g01-usrlib (/usr/lib), and the
// /etc/modprobe.d/g01-ovr.conf shadows its /usr/lib namesake.
func TestSelectModprobeConfigFiles_Suse15ReadsUsrLib(t *testing.T) {
	onDisk := map[string][]string{
		"/etc/modprobe.d":           {"50-nvme.conf", "g01-blacklist.conf", "g01-ovr.conf", "README"},
		"/usr/local/lib/modprobe.d": {"g01-local.conf"},
		"/usr/lib/modprobe.d":       {"g01-ovr.conf", "g01-usrlib.conf"},
		"/lib/modprobe.d":           {"10-unsupported-modules.conf", "60-blacklist_fs-cramfs.conf", "README", "systemd.conf"},
	}
	dirs := modprobeSearchPathsFor(29, false, true)
	listings := make([][]string, len(dirs))
	for i, dir := range dirs {
		listings[i] = onDisk[dir]
	}
	assert.Equal(t, []string{
		"/lib/modprobe.d/10-unsupported-modules.conf",
		"/etc/modprobe.d/50-nvme.conf",
		"/lib/modprobe.d/60-blacklist_fs-cramfs.conf",
		"/etc/modprobe.d/g01-blacklist.conf",
		"/usr/local/lib/modprobe.d/g01-local.conf",
		"/etc/modprobe.d/g01-ovr.conf",
		"/usr/lib/modprobe.d/g01-usrlib.conf",
		"/lib/modprobe.d/systemd.conf",
	}, selectConfDFiles(dirs, listings))
}

// sweepCRLFConf and sweepContConf are /etc/modprobe.d/sweep-crlf.conf and
// sweep-cont.conf from the Fedora 44 sweep host. `modprobe -c` prints
// "blacklist sweepcrlf\r", "options sweepcrlfopt a=1 b=2\r" and
// "install sweepcont /bin/echo   continued" for them.
const (
	sweepCRLFConf = "blacklist sweepcrlf\r\noptions sweepcrlfopt a=1 b=2\r\n"
	sweepContConf = "install sweepcont /bin/echo \\\n  continued\n# comment\nblacklist sweepuni # ✓\n"
)

func TestModprobeLines(t *testing.T) {
	t.Run("backslash-newline joins lines like getline_wrapped", func(t *testing.T) {
		assert.Equal(t, []modprobeLine{
			{num: 1, text: "install sweepcont /bin/echo   continued"},
			{num: 3, text: "# comment"},
			{num: 4, text: "blacklist sweepuni # ✓"},
		}, modprobeLines(sweepContConf))
	})

	t.Run("carriage return stays in the line", func(t *testing.T) {
		assert.Equal(t, []modprobeLine{
			{num: 1, text: "blacklist sweepcrlf\r"},
			{num: 2, text: "options sweepcrlfopt a=1 b=2\r"},
		}, modprobeLines(sweepCRLFConf))
	})

	t.Run("a backslash escapes the next byte", func(t *testing.T) {
		// options fixbs a=x\y b=p\\ and options fixbs2 c=1\\\ + "  d=2";
		// modprobe -c prints "options fixbs a=xy b=p\" and
		// "options fixbs2 c=1\  d=2" on kmod 20, 23, 31 and 34.2
		assert.Equal(t, []modprobeLine{
			{num: 1, text: "options fixbs a=xy b=p\\"},
			{num: 2, text: "options fixbs2 c=1\\  d=2"},
		}, modprobeLines("options fixbs a=x\\y b=p\\\\\noptions fixbs2 c=1\\\\\\\n  d=2\n"))
	})
}

func newModprobeTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

func TestParseModprobeDirectivesLikeKmod(t *testing.T) {
	runtime := newModprobeTestRuntime()

	blacklists, err := parseBlacklists(runtime, "/etc/modprobe.d/sweep-crlf.conf", sweepCRLFConf)
	require.NoError(t, err)
	require.Len(t, blacklists, 1)
	// kmod keeps the \r, so this line does not blacklist sweepcrlf
	assert.Equal(t, "sweepcrlf\r", blacklists[0].(*mqlModprobeBlacklist).Module.Data)

	options, err := parseOptions(runtime, "/etc/modprobe.d/sweep-crlf.conf", sweepCRLFConf)
	require.NoError(t, err)
	require.Len(t, options, 1)
	assert.Equal(t, "a=1 b=2\r", options[0].(*mqlModprobeOption).Parameters.Data)

	installs, err := parseInstalls(runtime, "/etc/modprobe.d/sweep-cont.conf", sweepContConf)
	require.NoError(t, err)
	require.Len(t, installs, 1)
	inst := installs[0].(*mqlModprobeInstall)
	assert.Equal(t, "/bin/echo   continued", inst.Command.Data)
	assert.Equal(t, int64(1), inst.LineNumber.Data)

	blacklists, err = parseBlacklists(runtime, "/etc/modprobe.d/sweep-cont.conf", sweepContConf)
	require.NoError(t, err)
	require.Len(t, blacklists, 1)
	bl := blacklists[0].(*mqlModprobeBlacklist)
	assert.Equal(t, "sweepuni", bl.Module.Data)
	assert.Equal(t, int64(4), bl.LineNumber.Data)
}

func TestParseModprobeConfigLikeKmod(t *testing.T) {
	// `blacklist dummy\r` does not stop `modprobe -b dummy` (Fedora 44)
	got := parseModprobeConfig("blacklist dummy\r\n")
	assert.False(t, got["dummy"].blacklisted)

	got = parseModprobeConfig("install cramfs \\\n  /bin/false\n")
	assert.True(t, got["cramfs"].installBypass)
}
