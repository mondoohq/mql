// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/multierr"
	"go.mondoo.com/mql/utils/syncx"
)

func newAuditdRulesTestRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "oraclelinux",
			Version: "8",
			Family:  []string{"oraclelinux", "linux"},
		},
	})
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

// newAuditdFilesTestRuntime serves files (path to content) and directories
// from a mock filesystem.
func newAuditdFilesTestRuntime(t *testing.T, files map[string]string, dirs ...string) *plugin.Runtime {
	t.Helper()

	data := &mock.TomlData{Files: map[string]*mock.MockFileData{}}
	for path, content := range files {
		data.Files[path] = &mock.MockFileData{Path: path, Content: content, StatData: mock.FileInfo{Mode: 0o640}}
	}
	for _, dir := range dirs {
		data.Files[dir] = &mock.MockFileData{Path: dir, StatData: mock.FileInfo{Mode: os.ModeDir | 0o750, IsDir: true}}
	}

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux"}},
	}, mock.WithData(data))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func controlValues(t *testing.T, rules *mqlAuditdRules, flag string) []string {
	t.Helper()
	controls := rules.GetControls()
	require.NoError(t, controls.Error)
	res := []string{}
	for _, raw := range controls.Data {
		c := raw.(*mqlAuditdRuleControl)
		if c.Flag.Data == flag {
			res = append(res, c.Value.Data)
		}
	}
	return res
}

func TestAuditdRulesReadsRulesDirLikeAugenrules(t *testing.T) {
	runtime := newAuditdFilesTestRuntime(t, map[string]string{
		"/etc/audit/rules.d/10-b.rules":        "-b 10\n",
		"/etc/audit/rules.d/9-a.rules":         "-b 9\n",
		"/etc/audit/rules.d/.hidden.rules":     "-b 0\n",
		"/etc/audit/rules.d/README":            "-b 1\n",
		"/etc/audit/rules.d/nested/x.rules":    "-b 2\n",
		"/etc/audit/rules.d/old.rules/x.rules": "-b 3\n",
		"/etc/audit/audit.rules":               "-b 4\n",
	}, "/etc/audit/rules.d", "/etc/audit/rules.d/nested", "/etc/audit/rules.d/old.rules")
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	assert.Equal(t, "/etc/audit/rules.d", rules.GetPath().Data)
	assert.True(t, rules.GetExists().Data)
	// top-level *.rules only, in natural order: 9-a before 10-b
	assert.Equal(t, []string{"9", "10"}, controlValues(t, rules, "-b"))
}

func TestAuditdRulesFallsBackToAuditRules(t *testing.T) {
	t.Run("rules.d missing", func(t *testing.T) {
		runtime := newAuditdFilesTestRuntime(t, map[string]string{
			"/etc/audit/audit.rules": "-w /etc/shadow -p wa -k identity\n",
		})
		rules := &mqlAuditdRules{MqlRuntime: runtime}

		assert.Equal(t, "/etc/audit/audit.rules", rules.GetPath().Data)
		assert.True(t, rules.GetExists().Data)
		files := rules.GetFiles()
		require.NoError(t, files.Error)
		require.Len(t, files.Data, 1)
		assert.Equal(t, "/etc/shadow", files.Data[0].(*mqlAuditdRuleFile).Path.Data)
	})

	t.Run("rules.d without rule files", func(t *testing.T) {
		runtime := newAuditdFilesTestRuntime(t, map[string]string{
			"/etc/audit/rules.d/README": "not a rule file\n",
			"/etc/audit/audit.rules":    "-b 8192\n",
		}, "/etc/audit/rules.d")
		rules := &mqlAuditdRules{MqlRuntime: runtime}

		assert.Equal(t, "/etc/audit/audit.rules", rules.GetPath().Data)
		assert.Equal(t, []string{"8192"}, controlValues(t, rules, "-b"))
	})
}

func TestAuditdRulesMissingPathReturnsEmptyLists(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	exists := rules.GetExists()
	require.NoError(t, exists.Error)
	assert.False(t, exists.Data)

	watches := rules.GetWatches()
	require.NoError(t, watches.Error)
	assert.Empty(t, watches.Data)

	immutable := rules.GetImmutable()
	require.NoError(t, immutable.Error)
	assert.False(t, immutable.Data)

	controls := rules.GetControls()
	require.NoError(t, controls.Error)
	assert.Empty(t, controls.Data)
	assert.Equal(t, plugin.StateIsSet, controls.State)

	files := rules.GetFiles()
	require.NoError(t, files.Error)
	assert.Empty(t, files.Data)
	assert.Equal(t, plugin.StateIsSet, files.State)

	syscalls := rules.GetSyscalls()
	require.NoError(t, syscalls.Error)
	assert.Empty(t, syscalls.Data)
	assert.Equal(t, plugin.StateIsSet, syscalls.State)
}

func TestAuditdSyscallRuleParsing(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	content := `
# 64-bit DAC permission modification rule
-a always,exit -F arch=b64 -S chmod,fchmod,chown -F auid>=1000 -F auid!=unset -k perm_mod
# 32-bit variant using the raw unset sentinel
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
# rule without any arch or auid filters
-a always,exit -S execve -k exec
`

	var errs multierr.Errors
	rules.parse(content, &errs)
	require.NoError(t, errs.Deduplicate())
	require.Len(t, rules.Syscalls.Data, 3)

	t.Run("b64 rule derives arch, auidMin and excludesUnsetAuid", func(t *testing.T) {
		r := rules.Syscalls.Data[0].(*mqlAuditdRuleSyscall)
		assert.Equal(t, "b64", r.Arch.Data)
		assert.Equal(t, []any{"chmod", "fchmod", "chown"}, r.Syscalls.Data)
		assert.Equal(t, int64(1000), r.AuidMin.Data)
		assert.Equal(t, plugin.StateIsSet, r.AuidMin.State)
		assert.True(t, r.ExcludesUnsetAuid.Data)
		assert.Equal(t, "perm_mod", r.Keyname.Data)
	})

	t.Run("b32 rule treats the 4294967295 sentinel as unset", func(t *testing.T) {
		r := rules.Syscalls.Data[1].(*mqlAuditdRuleSyscall)
		assert.Equal(t, "b32", r.Arch.Data)
		assert.Equal(t, int64(1000), r.AuidMin.Data)
		assert.True(t, r.ExcludesUnsetAuid.Data)
	})

	t.Run("rule without arch/auid filters leaves fields empty and auidMin null", func(t *testing.T) {
		r := rules.Syscalls.Data[2].(*mqlAuditdRuleSyscall)
		assert.Equal(t, "", r.Arch.Data)
		assert.False(t, r.ExcludesUnsetAuid.Data)
		assert.NotEqual(t, 0, r.AuidMin.State&plugin.StateIsNull)
	})
}

func TestAuditdSyscallAuidGreaterThan(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	// `auid>999` is the strict-greater-than spelling of `auid>=1000`; auidMin
	// reports the effective lower bound of 1000 either way.
	content := "-a always,exit -F arch=b64 -S execve -F auid>999 -k t\n"

	var errs multierr.Errors
	rules.parse(content, &errs)
	require.NoError(t, errs.Deduplicate())
	require.Len(t, rules.Syscalls.Data, 1)

	r := rules.Syscalls.Data[0].(*mqlAuditdRuleSyscall)
	assert.Equal(t, int64(1000), r.AuidMin.Data)
}

func TestAuditdSyscallRuleRepeatedFlags(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	// Syscalls may be supplied via repeated -S flags as well as comma lists;
	// both forms must accumulate into a single flat syscalls list.
	content := "-a always,exit -F arch=b64 -S open -S openat,creat -k access\n"

	var errs multierr.Errors
	rules.parse(content, &errs)
	require.NoError(t, errs.Deduplicate())
	require.Len(t, rules.Syscalls.Data, 1)

	r := rules.Syscalls.Data[0].(*mqlAuditdRuleSyscall)
	assert.Equal(t, []any{"open", "openat", "creat"}, r.Syscalls.Data)
}

func TestNormalizeAuditdConfigFields(t *testing.T) {
	t.Run("lowercases keys and downcases enum values", func(t *testing.T) {
		res, err := normalizeAuditdConfigFields(map[string]any{
			"Log_Format": "ENABLED",
			"Log_File":   "/var/log/audit/audit.log",
		})
		require.NoError(t, err)
		assert.Equal(t, "enabled", res["log_format"])
		// log_file is not a downcase keyword, so its value is preserved verbatim.
		assert.Equal(t, "/var/log/audit/audit.log", res["log_file"])
	})

	t.Run("reports the offending field name for non-string values", func(t *testing.T) {
		_, err := normalizeAuditdConfigFields(map[string]any{
			"broken": map[string]any{"nested": "value"},
		})
		require.Error(t, err)
		// The error must name the field that failed (`broken`), not an empty string.
		assert.Contains(t, err.Error(), "broken")
	})
}

func TestAuditdSyscallRuleMalformedAction(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	// A malformed `-a` rule carries no comma (the list segment is missing).
	// Parsing must not panic; the action is captured and the list is empty.
	content := "-a always -S execve -k t\n"

	var errs multierr.Errors
	require.NotPanics(t, func() {
		rules.parse(content, &errs)
	})
	require.NoError(t, errs.Deduplicate())
	require.Len(t, rules.Syscalls.Data, 1)

	r := rules.Syscalls.Data[0].(*mqlAuditdRuleSyscall)
	assert.Equal(t, "always", r.Action.Data)
	assert.Equal(t, "", r.List.Data)
}

func TestAuditdControlRuleParsing(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	content := `
# comment line, must be skipped

-D
-b 8192
-f 1
--backlog_wait_time 60000
`

	var errs multierr.Errors
	rules.parse(content, &errs)
	require.NoError(t, errs.Deduplicate())
	require.Len(t, rules.Controls.Data, 4)
	assert.Empty(t, rules.Syscalls.Data)
	assert.Empty(t, rules.Files.Data)

	got := map[string]string{}
	for _, raw := range rules.Controls.Data {
		c := raw.(*mqlAuditdRuleControl)
		got[c.Flag.Data] = c.Value.Data
	}
	assert.Equal(t, map[string]string{
		"-D":                  "",
		"-b":                  "8192",
		"-f":                  "1",
		"--backlog_wait_time": "60000",
	}, got)
}

func TestAuditdFileRuleParsing(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	content := `
-w /etc/shadow -p wa -k identity
-w /etc/passwd
`

	var errs multierr.Errors
	rules.parse(content, &errs)
	require.NoError(t, errs.Deduplicate())
	require.Len(t, rules.Files.Data, 2)

	shadow := rules.Files.Data[0].(*mqlAuditdRuleFile)
	assert.Equal(t, "/etc/shadow", shadow.Path.Data)
	assert.Equal(t, "wa", shadow.Permissions.Data)
	assert.Equal(t, "identity", shadow.Keyname.Data)

	// A watch with no -p/-k still parses, with empty permissions and keyname.
	passwd := rules.Files.Data[1].(*mqlAuditdRuleFile)
	assert.Equal(t, "/etc/passwd", passwd.Path.Data)
	assert.Equal(t, "", passwd.Permissions.Data)
	assert.Equal(t, "", passwd.Keyname.Data)
}

func TestAuditdSyscallFieldOperatorParsing(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	// Exercises the reOperator ordering (>= must win over =/>) and a key-only
	// field with no operator.
	content := "-a always,exit -F arch=b64 -F auid>=1000 -F success!=0 -F exit -S execve -k t\n"

	var errs multierr.Errors
	rules.parse(content, &errs)
	require.NoError(t, errs.Deduplicate())
	require.Len(t, rules.Syscalls.Data, 1)

	got := map[string][2]string{} // key -> {op, value}
	keyOnly := []string{}
	for _, raw := range rules.Syscalls.Data[0].(*mqlAuditdRuleSyscall).Fields.Data {
		f := raw.(map[string]any)
		key, _ := f["key"].(string)
		op, hasOp := f["op"].(string)
		if !hasOp {
			keyOnly = append(keyOnly, key)
			continue
		}
		val, _ := f["value"].(string)
		got[key] = [2]string{op, val}
	}

	assert.Equal(t, [2]string{"=", "b64"}, got["arch"])
	assert.Equal(t, [2]string{">=", "1000"}, got["auid"])
	assert.Equal(t, [2]string{"!=", "0"}, got["success"])
	assert.Contains(t, keyOnly, "exit")
}

func TestAuditdRulesImmutable(t *testing.T) {
	t.Run("rules directory uses the last -e, as augenrules does", func(t *testing.T) {
		runtime := newAuditdFilesTestRuntime(t, map[string]string{
			"/etc/audit/rules.d/10-base.rules":     "-e 2\n",
			"/etc/audit/rules.d/99-override.rules": "-e 1\n",
		}, "/etc/audit/rules.d")
		rules := &mqlAuditdRules{MqlRuntime: runtime}
		assert.False(t, rules.GetImmutable().Data)
	})

	t.Run("rules directory ending in -e 2", func(t *testing.T) {
		runtime := newAuditdFilesTestRuntime(t, map[string]string{
			"/etc/audit/rules.d/10-base.rules":     "-e 1\n",
			"/etc/audit/rules.d/99-finalize.rules": "-e 2\n",
		}, "/etc/audit/rules.d")
		rules := &mqlAuditdRules{MqlRuntime: runtime}
		assert.True(t, rules.GetImmutable().Data)
	})

	t.Run("single rules file is locked by any -e 2", func(t *testing.T) {
		runtime := newAuditdFilesTestRuntime(t, map[string]string{
			"/etc/audit/audit.rules": "-e 2\n-e 1\n",
		})
		rules := &mqlAuditdRules{MqlRuntime: runtime}
		assert.Equal(t, "/etc/audit/audit.rules", rules.GetPath().Data)
		assert.True(t, rules.GetImmutable().Data)
	})

	t.Run("no -e control", func(t *testing.T) {
		runtime := newAuditdFilesTestRuntime(t, map[string]string{
			"/etc/audit/audit.rules": "-b 8192\n",
		})
		rules := &mqlAuditdRules{MqlRuntime: runtime}
		assert.False(t, rules.GetImmutable().Data)
	})
}

func TestAuditdRulesWatches(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	content := `
-w /etc/shadow -p aw -k identity
-w /etc/passwd
-w /etc/sudoers.d/ -p wa -k scope
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -F key=modules
-a always,exit -F dir=/etc/apparmor.d/ -F perm=wa -k mac
-a never,exit -F path=/tmp/excluded -F perm=wa
-a always,exit -F arch=b64 -S chmod -F path=/etc/hosts -k no-perm
`

	var errs multierr.Errors
	rules.parse(content, &errs)
	require.NoError(t, errs.Deduplicate())
	// -w rules are still reported as files, unchanged
	require.Len(t, rules.Files.Data, 3)

	type watch struct {
		path, keyname, typ string
		permissions        []any
	}
	got := []watch{}
	for _, raw := range rules.Watches.Data {
		w := raw.(*mqlAuditdRuleWatch)
		got = append(got, watch{w.Path.Data, w.Keyname.Data, w.Type.Data, w.Permissions.Data})
	}
	assert.Equal(t, []watch{
		{"/etc/shadow", "identity", "watch", []any{"w", "a"}},
		{"/etc/passwd", "", "watch", []any{"r", "w", "x", "a"}},
		{"/etc/sudoers.d", "scope", "watch", []any{"w", "a"}},
		{"/usr/bin/kmod", "modules", "path", []any{"x"}},
		{"/etc/apparmor.d", "mac", "dir", []any{"w", "a"}},
	}, got)
}

func TestAuditdSyscallKeyFromField(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	// the form auditctl -l prints
	content := "-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change\n"

	var errs multierr.Errors
	rules.parse(content, &errs)
	require.NoError(t, errs.Deduplicate())
	require.Len(t, rules.Syscalls.Data, 1)

	r := rules.Syscalls.Data[0].(*mqlAuditdRuleSyscall)
	assert.Equal(t, "time-change", r.Keyname.Data)
}

func TestAuditdSyscallPrependAndReversedAction(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	content := `
-A always,exit -F arch=b64 -S execve -k exec
-a exit,always -F arch=b64 -S mount -k mounts
`

	var errs multierr.Errors
	rules.parse(content, &errs)
	require.NoError(t, errs.Deduplicate())
	assert.Empty(t, rules.Controls.Data)
	require.Len(t, rules.Syscalls.Data, 2)

	for _, raw := range rules.Syscalls.Data {
		r := raw.(*mqlAuditdRuleSyscall)
		assert.Equal(t, "always", r.Action.Data, r.Keyname.Data)
		assert.Equal(t, "exit", r.List.Data, r.Keyname.Data)
	}
}

func TestAuditdRuleParsingMultibytePath(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	rules := &mqlAuditdRules{MqlRuntime: runtime}

	content := "-w /srv/données -p wa -k data\n"

	var errs multierr.Errors
	rules.parse(content, &errs)
	require.NoError(t, errs.Deduplicate())
	require.Len(t, rules.Files.Data, 1)

	f := rules.Files.Data[0].(*mqlAuditdRuleFile)
	assert.Equal(t, "/srv/données", f.Path.Data)
	assert.Equal(t, "wa", f.Permissions.Data)
	assert.Equal(t, "data", f.Keyname.Data)
}

func TestNaturalCompare(t *testing.T) {
	names := []string{"a.rules", "99-finalize.rules", "10-b.rules", "1-first.rules", "9-a.rules", "01-first.rules"}
	slices.SortFunc(names, naturalCompare)
	assert.Equal(t, []string{"01-first.rules", "1-first.rules", "9-a.rules", "10-b.rules", "99-finalize.rules", "a.rules"}, names)
}

func TestAuditdConfigTypedFields(t *testing.T) {
	cfg := &mqlAuditdConfig{}

	t.Run("absent keys report auditd's built-in defaults", func(t *testing.T) {
		params := map[string]any{}
		n, err := cfg.maxLogFile(params)
		require.NoError(t, err)
		assert.Equal(t, int64(0), n)
		n, err = cfg.numLogs(params)
		require.NoError(t, err)
		assert.Equal(t, int64(0), n)

		for _, fn := range []func(map[string]any) (string, error){cfg.maxLogFileAction, cfg.spaceLeftAction, cfg.adminSpaceLeftAction, cfg.diskFullAction} {
			v, err := fn(params)
			require.NoError(t, err)
			assert.Equal(t, "ignore", v)
		}
		v, _ := cfg.diskErrorAction(params)
		assert.Equal(t, "syslog", v)
		v, _ = cfg.actionMailAcct(params)
		assert.Equal(t, "root", v)
	})

	t.Run("configured values", func(t *testing.T) {
		params := map[string]any{
			"max_log_file":            "32",
			"num_logs":                "5",
			"max_log_file_action":     "keep_logs",
			"space_left_action":       "email",
			"admin_space_left_action": "single",
			"disk_full_action":        "halt",
			"disk_error_action":       "suspend",
			"action_mail_acct":        "auditors",
		}
		n, err := cfg.maxLogFile(params)
		require.NoError(t, err)
		assert.Equal(t, int64(32), n)
		n, _ = cfg.numLogs(params)
		assert.Equal(t, int64(5), n)
		v, _ := cfg.maxLogFileAction(params)
		assert.Equal(t, "keep_logs", v)
		v, _ = cfg.spaceLeftAction(params)
		assert.Equal(t, "email", v)
		v, _ = cfg.adminSpaceLeftAction(params)
		assert.Equal(t, "single", v)
		v, _ = cfg.diskFullAction(params)
		assert.Equal(t, "halt", v)
		v, _ = cfg.diskErrorAction(params)
		assert.Equal(t, "suspend", v)
		v, _ = cfg.actionMailAcct(params)
		assert.Equal(t, "auditors", v)
	})

	t.Run("a non-numeric size is an error, not a default", func(t *testing.T) {
		_, err := cfg.maxLogFile(map[string]any{"max_log_file": "8M"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "max_log_file")
	})
}

func TestAuditdConfigTypedFieldsMissingFile(t *testing.T) {
	runtime := newAuditdRulesTestRuntime(t)
	raw, err := CreateResource(runtime, "auditd.config", map[string]*llx.RawData{})
	require.NoError(t, err)
	cfg := raw.(*mqlAuditdConfig)

	// a missing auditd.conf must not read as "configured at the defaults"
	assert.Error(t, cfg.GetMaxLogFile().Error)
	assert.Error(t, cfg.GetSpaceLeftAction().Error)
}

func TestParseAuditctlStatus(t *testing.T) {
	t.Run("numeric output", func(t *testing.T) {
		res, err := parseAuditctlStatus(`enabled 2
failure 1
pid 812
rate_limit 0
backlog_limit 8192
lost 3
backlog 0
backlog_wait_time 60000
backlog_wait_time_actual 0
loginuid_immutable 0 unlocked
`)
		require.NoError(t, err)
		assert.Equal(t, map[string]int64{
			"enabled": 2, "failure": 1, "pid": 812, "rate_limit": 0,
			"backlog_limit": 8192, "lost": 3, "backlog": 0,
		}, res)
	})

	t.Run("interpreted output from auditctl -i", func(t *testing.T) {
		res, err := parseAuditctlStatus("enabled enabled+immutable\nfailure panic\npid 1\nrate_limit 0\nbacklog_limit 64\nlost 0\nbacklog 0\n")
		require.NoError(t, err)
		assert.Equal(t, int64(2), res["enabled"])
		assert.Equal(t, int64(2), res["failure"])
	})

	t.Run("incomplete output", func(t *testing.T) {
		_, err := parseAuditctlStatus("enabled 1\n")
		require.Error(t, err)
	})
}

func TestInitAuditdStatus(t *testing.T) {
	newRuntime := func(cmd *mock.Command) *plugin.Runtime {
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
			Commands: map[string]*mock.Command{"auditctl -s": cmd},
		}))
		require.NoError(t, err)
		return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	}

	t.Run("reports the kernel audit status", func(t *testing.T) {
		args, _, err := initAuditdStatus(newRuntime(&mock.Command{
			Stdout: "enabled 1\nfailure 1\npid 812\nrate_limit 0\nbacklog_limit 8192\nlost 0\nbacklog 0\n",
		}), map[string]*llx.RawData{})
		require.NoError(t, err)
		assert.Equal(t, int64(1), args["enabled"].Value)
		assert.Equal(t, int64(8192), args["backlogLimit"].Value)
	})

	t.Run("an unprivileged scan errors instead of reporting zeros", func(t *testing.T) {
		_, _, err := initAuditdStatus(newRuntime(&mock.Command{
			Stderr:     "Error sending status request (Operation not permitted)",
			ExitStatus: 1,
		}), map[string]*llx.RawData{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Operation not permitted")
	})
}
