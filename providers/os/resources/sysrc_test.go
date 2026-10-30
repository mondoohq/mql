// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSysrc(t *testing.T) {
	t.Run("standard rc.conf", func(t *testing.T) {
		content := `# System configuration
hostname="freebsd-host"
ifconfig_em0="DHCP"
sshd_enable="YES"
dumpdev="NO"
`
		entries := ParseSysrc(content)
		require.Len(t, entries, 4)

		require.Equal(t, SysrcEntry{Name: "hostname", Value: "freebsd-host"}, entries[0])
		require.Equal(t, SysrcEntry{Name: "ifconfig_em0", Value: "DHCP"}, entries[1])
		require.Equal(t, SysrcEntry{Name: "sshd_enable", Value: "YES"}, entries[2])
		require.Equal(t, SysrcEntry{Name: "dumpdev", Value: "NO"}, entries[3])
	})

	t.Run("single quotes", func(t *testing.T) {
		entries := ParseSysrc(`syslogd_flags='-s -s'`)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "syslogd_flags", Value: "-s -s"}, entries[0])
	})

	t.Run("unquoted value", func(t *testing.T) {
		entries := ParseSysrc(`savecore_enable=NO`)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "savecore_enable", Value: "NO"}, entries[0])
	})

	t.Run("empty lines and comments", func(t *testing.T) {
		content := `# comment

hostname="test"

# another comment
`
		entries := ParseSysrc(content)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "hostname", Value: "test"}, entries[0])
	})

	t.Run("empty value", func(t *testing.T) {
		entries := ParseSysrc(`gateway_enable=""`)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "gateway_enable", Value: ""}, entries[0])
	})

	t.Run("value with equals sign", func(t *testing.T) {
		entries := ParseSysrc(`ifconfig_em0="inet 10.0.0.1 netmask=255.255.255.0"`)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "ifconfig_em0", Value: "inet 10.0.0.1 netmask=255.255.255.0"}, entries[0])
	})

	t.Run("empty content", func(t *testing.T) {
		entries := ParseSysrc("")
		require.Nil(t, entries)
	})

	t.Run("duplicate keys last wins", func(t *testing.T) {
		content := `sshd_enable="NO"
sshd_enable="YES"
`
		entries := ParseSysrc(content)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "sshd_enable", Value: "YES"}, entries[0])
	})

	t.Run("trailing comment", func(t *testing.T) {
		content := "syslogd_flags=\"-s\"\t\t# Flags to syslogd (if enabled).\n" +
			"dumpdev=NO # no dumps\n"
		entries := ParseSysrc(content)
		require.Equal(t, []SysrcEntry{
			{Name: "syslogd_flags", Value: "-s"},
			{Name: "dumpdev", Value: "NO"},
		}, entries)
	})

	t.Run("hash inside quotes is not a comment", func(t *testing.T) {
		entries := ParseSysrc(`motd="a # b"`)
		require.Equal(t, []SysrcEntry{{Name: "motd", Value: "a # b"}}, entries)
	})

	t.Run("concatenated quoting and escapes", func(t *testing.T) {
		entries := ParseSysrc(`flags="-a "'-b'\ c" \"d\""`)
		require.Equal(t, []SysrcEntry{{Name: "flags", Value: `-a -b c "d"`}}, entries)
	})

	t.Run("unterminated quote is skipped", func(t *testing.T) {
		entries := ParseSysrc("broken=\"open\nok=YES\n")
		require.Equal(t, []SysrcEntry{{Name: "ok", Value: "YES"}}, entries)
	})

	t.Run("entries keep references as written", func(t *testing.T) {
		entries := ParseSysrc(`local_startup="${_localbase}/etc/rc.d"`)
		require.Equal(t, []SysrcEntry{{Name: "local_startup", Value: "${_localbase}/etc/rc.d"}}, entries)
	})

	t.Run("not an assignment", func(t *testing.T) {
		content := `: ${x:-"/usr/local"}
[ -n "$x" ] && y=1
foo bar=baz
a-b=c
1abc=d
`
		require.Nil(t, ParseSysrc(content))
	})

	t.Run("assignments inside conditionals and functions are skipped", func(t *testing.T) {
		// tail of FreeBSD 14.3 /etc/defaults/rc.conf
		content := `rc_conf_files="/etc/rc.conf /etc/rc.conf.local"
if [ -z "${source_rc_confs_defined}" ]; then
	source_rc_confs_defined=yes
	source_rc_confs() {
		local i sourced_files
		for i in ${rc_conf_files}; do
			case ${sourced_files} in
			*:$i:*)
				;;
			*)
				sourced_files="${sourced_files}:$i:"
				if [ -r $i ]; then
					. $i
				fi
				;;
			esac
		done
	}
fi
if [ -r /etc/defaults/vendor.conf ]; then
	. /etc/defaults/vendor.conf
fi
sshd_enable="NO"
`
		entries := ParseSysrc(content)
		require.Equal(t, []SysrcEntry{
			{Name: "rc_conf_files", Value: "/etc/rc.conf /etc/rc.conf.local"},
			{Name: "sshd_enable", Value: "NO"},
		}, entries)
	})

	t.Run("one-line conditional does not open a block", func(t *testing.T) {
		content := `if [ -r /x ]; then . /x; fi
sshd_enable="YES"
`
		entries := ParseSysrc(content)
		require.Equal(t, []SysrcEntry{{Name: "sshd_enable", Value: "YES"}}, entries)
	})
}

func TestResolveSysrcValues(t *testing.T) {
	defaults := `rc_conf_files="/etc/rc.conf /etc/rc.conf.local"
syslogd_flags="-s"		# Flags to syslogd (if enabled).
sshd_enable="NO"		# Enable sshd
dumpdev="NO"		# Device to crashdump to
`
	reader := func(files map[string]string) func(string) (string, bool, error) {
		return func(path string) (string, bool, error) {
			c, ok := files[path]
			return c, ok, nil
		}
	}

	t.Run("defaults apply when no rc.conf sets the variable", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf": defaults,
			"/etc/rc.conf":          `hostname="h"`,
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "-s", values["syslogd_flags"])
		require.Equal(t, "NO", values["dumpdev"])
		require.Equal(t, "h", values["hostname"])
	})

	t.Run("rc.conf.local overrides rc.conf overrides defaults", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf": defaults,
			"/etc/rc.conf":          "sshd_enable=\"YES\"\nsyslogd_flags=\"-ss\"\n",
			"/etc/rc.conf.local":    `sshd_enable="NO"`,
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "NO", values["sshd_enable"])
		require.Equal(t, "-ss", values["syslogd_flags"])
	})

	t.Run("vendor.conf overrides defaults and loses to rc.conf", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf":     defaults,
			"/etc/defaults/vendor.conf": "dumpdev=\"AUTO\"\nsshd_enable=\"YES\"\n",
			"/etc/rc.conf":              `sshd_enable="NO"`,
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "AUTO", values["dumpdev"])
		require.Equal(t, "NO", values["sshd_enable"])
	})

	t.Run("files outside rc_conf_files are not sourced", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf":  defaults,
			"/usr/local/etc/rc.conf": `sshd_enable="YES"`,
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "NO", values["sshd_enable"])
	})

	t.Run("redefined rc_conf_files adds files in the second pass", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf": defaults,
			"/etc/rc.conf":          "rc_conf_files=\"/etc/rc.conf /etc/extra.conf\"\nsshd_enable=\"YES\"\n",
			"/etc/rc.conf.local":    `dumpdev="AUTO"`,
			"/etc/extra.conf":       `sshd_enable="NO"`,
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "NO", values["sshd_enable"])
		// rc.conf.local was sourced in the first pass, before the redefinition
		require.Equal(t, "AUTO", values["dumpdev"])
		require.Equal(t, "/etc/rc.conf /etc/extra.conf", values["rc_conf_files"])
	})

	t.Run("a file is sourced once even when listed twice", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf": "rc_conf_files=\"/etc/a /etc/b /etc/a\"\n",
			"/etc/a":                `x="a"`,
			"/etc/b":                `x="b"`,
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "b", values["x"])
	})

	t.Run("missing defaults file falls back to the stock rc_conf_files", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/rc.conf.local": `sshd_enable="YES"`,
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "YES", values["sshd_enable"])
		_, ok := values["syslogd_flags"]
		require.False(t, ok)
		_, ok = values["rc_conf_files"]
		require.False(t, ok)
	})

	t.Run("no files at all yields no values", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{}), nil)
		require.NoError(t, err)
		require.Empty(t, values)
	})

	t.Run("explicit files replace rc_conf_files and keep the defaults", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf": defaults,
			"/etc/rc.conf":          `sshd_enable="YES"`,
			"/tmp/custom.conf":      `dumpdev="AUTO"`,
		}), []string{"/tmp/custom.conf"})
		require.NoError(t, err)
		require.Equal(t, "NO", values["sshd_enable"])
		require.Equal(t, "AUTO", values["dumpdev"])
		require.Equal(t, "-s", values["syslogd_flags"])
		require.Equal(t, "/etc/rc.conf /etc/rc.conf.local", values["rc_conf_files"])
	})

	t.Run("variable references expand", func(t *testing.T) {
		// from FreeBSD 14.3 /etc/defaults/rc.conf
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf": `: ${_localbase:="/usr/local"}
rc_conf_files="/etc/rc.conf"
local_startup="${_localbase}/etc/rc.d" # startup script dirs.
ldconfig_paths="/usr/lib/compat ${_localbase}/lib ${_localbase}/lib/compat/pkg"
`,
			"/etc/rc.conf": `quoted='${_localbase}'
bare=$_localbase/x
fallback="${unset_var:-none}"
empty_kept="${unset_var-}"
`,
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "/usr/local", values["_localbase"])
		require.Equal(t, "/usr/local/etc/rc.d", values["local_startup"])
		require.Equal(t, "/usr/lib/compat /usr/local/lib /usr/local/lib/compat/pkg", values["ldconfig_paths"])
		require.Equal(t, "${_localbase}", values["quoted"])
		require.Equal(t, "/usr/local/x", values["bare"])
		require.Equal(t, "none", values["fallback"])
		require.Equal(t, "", values["empty_kept"])
	})

	t.Run("default assignment keeps an earlier value", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf": "_localbase=/opt\n: ${_localbase:=\"/usr/local\"}\nx=\"$_localbase\"\n",
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "/opt", values["x"])
	})

	t.Run("nested references expand", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf": "b=\"inner\"\nx=\"${unset_a:-${b:-none}}/end\"\ny=\"${unset_a:-${unset_b:-none}}\"\n",
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "inner/end", values["x"])
		require.Equal(t, "none", values["y"])
	})

	t.Run("default assignment without colon keeps an empty value", func(t *testing.T) {
		values, err := ResolveSysrcValues(reader(map[string]string{
			"/etc/defaults/rc.conf": "empty=\"\"\n: ${empty=\"x\"}\n: ${unset_v=\"y\"}\n: ${empty2:=\"z\"}\nempty2=\"\"\n: ${empty2:=\"z\"}\n",
		}), nil)
		require.NoError(t, err)
		require.Equal(t, "", values["empty"])
		require.Equal(t, "y", values["unset_v"])
		require.Equal(t, "z", values["empty2"])
	})

	t.Run("read errors are returned", func(t *testing.T) {
		_, err := ResolveSysrcValues(func(string) (string, bool, error) {
			return "", false, errors.New("permission denied")
		}, nil)
		require.Error(t, err)
	})
}

// The parser reads a whole file already held in memory. A line over 64 KiB
// must not end the parse and drop the settings after it.
func TestParseSysrcAfterLongLine(t *testing.T) {
	entries := ParseSysrc("ifconfig_em0_aliases=\"" + strings.Repeat("x", 70000) + "\"\nsshd_enable=\"YES\"\n")
	require.Len(t, entries, 2)
	assert.Equal(t, SysrcEntry{Name: "sshd_enable", Value: "YES"}, entries[1])
}
