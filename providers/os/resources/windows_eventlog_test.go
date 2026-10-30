// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

func dwordItem(key string, n int64) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{Key: key, Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: n}}
}

func szItem(key, s string) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{Key: key, Value: registry.RegistryKeyValue{Kind: registry.SZ, String: s}}
}

func TestRegistryItemInt(t *testing.T) {
	t.Run("DWORD value", func(t *testing.T) {
		n, ok := registryItemInt(dwordItem("MaxSize", 196608))
		assert.True(t, ok)
		assert.Equal(t, int64(196608), n)
	})

	t.Run("string decimal (Group Policy form)", func(t *testing.T) {
		n, ok := registryItemInt(szItem("Retention", "0"))
		assert.True(t, ok)
		assert.Equal(t, int64(0), n)
	})

	t.Run("string hex 0xFFFFFFFF", func(t *testing.T) {
		n, ok := registryItemInt(szItem("Retention", "0xFFFFFFFF"))
		assert.True(t, ok)
		assert.Equal(t, int64(0xFFFFFFFF), n)
	})

	t.Run("string -1", func(t *testing.T) {
		n, ok := registryItemInt(szItem("Retention", "-1"))
		assert.True(t, ok)
		assert.Equal(t, int64(-1), n)
	})

	t.Run("non-numeric string", func(t *testing.T) {
		_, ok := registryItemInt(szItem("Retention", "nope"))
		assert.False(t, ok)
	})
}

func TestLookupInt(t *testing.T) {
	items := map[string]registry.RegistryKeyItem{
		"maxsize":   dwordItem("MaxSize", 32768),
		"retention": szItem("Retention", "0"),
	}

	n, ok := lookupInt(items, "maxsize")
	assert.True(t, ok)
	assert.Equal(t, int64(32768), n)

	_, ok = lookupInt(items, "missing")
	assert.False(t, ok)
}

func TestResolveMaxSizeKB(t *testing.T) {
	dword := func(v int64) map[string]registry.RegistryKeyItem {
		return map[string]registry.RegistryKeyItem{"maxsize": dwordItem("MaxSize", v)}
	}
	empty := map[string]registry.RegistryKeyItem{}

	t.Run("Group Policy wins and is already in KB", func(t *testing.T) {
		n, ok := resolveMaxSizeKB(dword(196608), dword(20480*1024), dword(1024*1024))
		assert.True(t, ok)
		assert.Equal(t, int64(196608), n)
	})

	t.Run("the classic channel configuration is in bytes", func(t *testing.T) {
		n, ok := resolveMaxSizeKB(empty, dword(20480*1024), empty)
		assert.True(t, ok)
		assert.Equal(t, int64(20480), n)
	})

	// Measured on a live host: Microsoft-Windows-PowerShell/Operational
	// carries MaxSize 0xf00000 under WINEVT and nothing under
	// Services\EventLog, so without this source it reported the documented
	// 20480 default instead of its real 15360.
	t.Run("a modern channel resolves through WINEVT", func(t *testing.T) {
		n, ok := resolveMaxSizeKB(empty, empty, dword(15728640))
		assert.True(t, ok)
		assert.Equal(t, int64(15360), n)
	})

	t.Run("a classic log never reaches WINEVT", func(t *testing.T) {
		// Services\EventLog says 20 MB, WINEVT says 1 MB; the classic source wins
		n, ok := resolveMaxSizeKB(empty, dword(20480*1024), dword(1024*1024))
		assert.True(t, ok)
		assert.Equal(t, int64(20480), n)
	})

	// The registry holds overrides only. Measured on a live host:
	// Microsoft-Windows-WinRM/Operational has no MaxSize value anywhere and
	// runs at the 1052672 bytes its manifest declares, so a miss has to be
	// reported rather than resolved, or the caller never consults the one
	// source that knows the manifest value.
	t.Run("nothing configured is a miss, not a default", func(t *testing.T) {
		n, ok := resolveMaxSizeKB(empty, empty, empty)
		assert.False(t, ok)
		assert.Equal(t, int64(0), n)

		n, ok = resolveMaxSizeKB(nil, nil, nil)
		assert.False(t, ok)
		assert.Equal(t, int64(0), n)
	})
}

func TestResolveRegistryRetention(t *testing.T) {
	keys := func(items ...registry.RegistryKeyItem) map[string]registry.RegistryKeyItem {
		res := map[string]registry.RegistryKeyItem{}
		for _, it := range items {
			res[strings.ToLower(it.Key)] = it
		}
		return res
	}
	none := keys()

	tests := []struct {
		name                     string
		policy, service, channel map[string]registry.RegistryKeyItem
		want                     string
		ok                       bool
	}{
		// EventLog.admx Channel_Log_Retention_*: enabledValue <string>1</string>
		// is "Retain old events". Read as the legacy period it was one second
		// of retention, reported as a log that overwrites by age.
		{name: "policy Retain old events enabled", policy: keys(szItem("Retention", "1")), service: keys(dwordItem("Retention", 0)), want: retentionNeverOverwrite, ok: true},
		{name: "policy Retain old events disabled", policy: keys(szItem("Retention", "0")), service: keys(dwordItem("Retention", -1)), want: retentionOverwriteAsNeeded, ok: true},
		// Channel_Log_AutoBackup_*: <string>1</string> archives the full log
		{name: "policy back up log automatically", policy: keys(szItem("AutoBackupLogFiles", "1")), service: keys(dwordItem("Retention", 0)), want: retentionNeverOverwrite, ok: true},
		{name: "policy back up disabled alone says nothing", policy: keys(szItem("AutoBackupLogFiles", "0")), service: keys(dwordItem("Retention", -1)), want: retentionNeverOverwrite, ok: true},
		{name: "policy retain disabled, back up enabled", policy: keys(szItem("Retention", "0"), szItem("AutoBackupLogFiles", "1")), want: retentionNeverOverwrite, ok: true},

		{name: "service overwrite as needed", policy: none, service: keys(dwordItem("Retention", 0)), want: retentionOverwriteAsNeeded, ok: true},
		{name: "service never overwrite sentinel", service: keys(dwordItem("Retention", 0xFFFFFFFF)), want: retentionNeverOverwrite, ok: true},
		{name: "service never overwrite signed", service: keys(dwordItem("Retention", -1)), want: retentionNeverOverwrite, ok: true},
		// Limit-EventLog -OverflowAction OverwriteOlder -RetentionDays 7 writes
		// 604800; measured on Windows 10 22H2 the log stays LogMode Circular.
		{name: "service positive period runs circular", service: keys(dwordItem("Retention", 604800)), want: retentionOverwriteAsNeeded, ok: true},
		// measured on Windows 10 22H2: Retention 0 with AutoBackupLogFiles 1 is LogMode AutoBackup
		{name: "service auto backup", service: keys(dwordItem("Retention", 0), dwordItem("AutoBackupLogFiles", 1)), want: retentionNeverOverwrite, ok: true},
		{name: "service auto backup off", service: keys(dwordItem("Retention", 0), dwordItem("AutoBackupLogFiles", 0)), want: retentionOverwriteAsNeeded, ok: true},

		// The WINEVT key is a flag, not a period: 1 must not read as one second.
		{name: "channel retain flag", channel: keys(dwordItem("Retention", 1)), want: retentionNeverOverwrite, ok: true},
		{name: "channel overwrite flag", channel: keys(dwordItem("Retention", 0)), want: retentionOverwriteAsNeeded, ok: true},
		{name: "channel auto backup flag", channel: keys(dwordItem("Retention", 0), dwordItem("AutoBackup", 1)), want: retentionNeverOverwrite, ok: true},
		{name: "a classic log never reaches WINEVT", service: keys(dwordItem("Retention", 0)), channel: keys(dwordItem("Retention", 1)), want: retentionOverwriteAsNeeded, ok: true},

		// No source carries a behavior: a miss, never the Windows default, so a
		// channel whose manifest retains its events cannot read as overwriting.
		{name: "nothing configured", policy: none, service: none, channel: none, ok: false},
		{name: "nil keys", ok: false},
		{name: "unparsable policy value", policy: keys(szItem("Retention", "yes")), ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := resolveRegistryRetention(tt.policy, tt.service, tt.channel)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// preloadedEventlog builds a channel whose registry sources are already read,
// so the field accessors run without a connection. A nil state with a nil
// stateErr means the live state was never needed; reaching for it would
// dereference the absent runtime and fail the test.
func preloadedEventlog(registered bool, policy, service, channel map[string]registry.RegistryKeyItem, state *windows.EventLogChannel, stateErr error) *mqlWindowsEventlog {
	w := &mqlWindowsEventlog{Name: plugin.TValue[string]{Data: "mqltest-channel", State: plugin.StateIsSet}}
	w.policy, w.service, w.channel = policy, service, channel
	w.registered = registered
	w.loaded.Store(true)
	if state != nil {
		w.state = state
		w.stateLoaded.Store(true)
	}
	w.stateErr = stateErr
	return w
}

// Measured on Windows 10 22H2 and Windows 11 25H2: a channel name nothing
// registered read as maxSizeKB 20480, retention overwrite_as_needed and
// overwriteAsNeeded true, while the live fields errored. Every field must
// fail the same way, without running the command.
func TestEventlogNonexistentChannel(t *testing.T) {
	w := preloadedEventlog(false, nil, nil, nil, nil, nil)

	_, err := w.maxSizeKB()
	assert.ErrorIs(t, err, llx.ErrNotFound)
	_, err = w.retention()
	assert.ErrorIs(t, err, llx.ErrNotFound)
	_, err = w.overwriteAsNeeded()
	assert.ErrorIs(t, err, llx.ErrNotFound)
	_, err = w.enabled()
	assert.ErrorIs(t, err, llx.ErrNotFound)
	_, err = w.recordCount()
	assert.ErrorIs(t, err, llx.ErrNotFound)
}

func TestEventlogRetentionSources(t *testing.T) {
	retain := map[string]registry.RegistryKeyItem{"retention": dwordItem("Retention", -1)}
	period := map[string]registry.RegistryKeyItem{"retention": dwordItem("Retention", 604800)}
	policyRetain := map[string]registry.RegistryKeyItem{"retention": szItem("Retention", "1")}
	noCommands := errors.New("failed to read the Event Log channel: this connection cannot run commands")

	// Measured on Windows 11 25H2: Services\EventLog\Application Retention -1
	// left the channel Circular. The live LogMode is what Windows does.
	t.Run("the live log mode wins over the registry", func(t *testing.T) {
		w := preloadedEventlog(true, policyRetain, retain, nil, &windows.EventLogChannel{LogMode: "Circular"}, nil)
		got, err := w.retention()
		assert.NoError(t, err)
		assert.Equal(t, retentionOverwriteAsNeeded, got)
		overwrites, err := w.overwriteAsNeeded()
		assert.NoError(t, err)
		assert.True(t, overwrites)
	})

	t.Run("a live retaining channel", func(t *testing.T) {
		w := preloadedEventlog(true, nil, period, nil, &windows.EventLogChannel{LogMode: "Retain"}, nil)
		got, err := w.retention()
		assert.NoError(t, err)
		assert.Equal(t, retentionNeverOverwrite, got)
	})

	t.Run("without commands the registry answers", func(t *testing.T) {
		w := preloadedEventlog(true, nil, retain, nil, nil, noCommands)
		got, err := w.retention()
		assert.NoError(t, err)
		assert.Equal(t, retentionNeverOverwrite, got)
		overwrites, err := w.overwriteAsNeeded()
		assert.NoError(t, err)
		assert.False(t, overwrites)
	})

	t.Run("an unrecognized live mode falls back to the registry", func(t *testing.T) {
		w := preloadedEventlog(true, policyRetain, nil, nil, &windows.EventLogChannel{LogMode: ""}, nil)
		got, err := w.retention()
		assert.NoError(t, err)
		assert.Equal(t, retentionNeverOverwrite, got)
	})

	// No source knows the behavior: the error, not the Windows default.
	t.Run("nothing to read is an error", func(t *testing.T) {
		w := preloadedEventlog(true, nil, nil, nil, nil, noCommands)
		_, err := w.retention()
		assert.ErrorIs(t, err, noCommands)
		_, err = w.overwriteAsNeeded()
		assert.ErrorIs(t, err, noCommands)

		w = preloadedEventlog(true, nil, nil, nil, &windows.EventLogChannel{LogMode: "Whatever"}, nil)
		_, err = w.retention()
		assert.Error(t, err)
	})
}

func TestEventlogMaxSizeKBSources(t *testing.T) {
	noCommands := errors.New("failed to read the Event Log channel: this connection cannot run commands")

	// Measured on Windows 10 22H2 and Windows 11 25H2: a policy MaxSize of
	// 32768 KB written to the registry left Application at 20971520 bytes.
	t.Run("the live size wins over the policy", func(t *testing.T) {
		policy := map[string]registry.RegistryKeyItem{"maxsize": dwordItem("MaxSize", 32768)}
		w := preloadedEventlog(true, policy, nil, nil, &windows.EventLogChannel{MaximumSizeInBytes: 20971520}, nil)
		n, err := w.maxSizeKB()
		assert.NoError(t, err)
		assert.Equal(t, int64(20480), n)
	})

	t.Run("without commands the registry answers", func(t *testing.T) {
		w := preloadedEventlog(true, nil, map[string]registry.RegistryKeyItem{"maxsize": dwordItem("MaxSize", 33554432)}, nil, nil, noCommands)
		n, err := w.maxSizeKB()
		assert.NoError(t, err)
		assert.Equal(t, int64(32768), n)
	})

	t.Run("the manifest size comes from the live channel", func(t *testing.T) {
		w := preloadedEventlog(true, nil, nil, map[string]registry.RegistryKeyItem{}, &windows.EventLogChannel{MaximumSizeInBytes: 1052672}, nil)
		n, err := w.maxSizeKB()
		assert.NoError(t, err)
		assert.Equal(t, int64(1028), n)
	})

	// This used to read 20480 KB, a size nobody configured.
	t.Run("no source is an error, not the 20 MB default", func(t *testing.T) {
		w := preloadedEventlog(true, nil, nil, nil, nil, noCommands)
		_, err := w.maxSizeKB()
		assert.ErrorIs(t, err, noCommands)

		w = preloadedEventlog(true, nil, nil, nil, &windows.EventLogChannel{}, nil)
		_, err = w.maxSizeKB()
		assert.Error(t, err)
	})
}

func TestDecodeLogMode(t *testing.T) {
	tests := []struct {
		mode string
		want string
		ok   bool
	}{
		{mode: "Circular", want: retentionOverwriteAsNeeded, ok: true},
		{mode: "circular", want: retentionOverwriteAsNeeded, ok: true},
		// Both of these keep the events: Retain refuses new ones once full,
		// AutoBackup archives the log and starts a new one. Neither overwrites.
		{mode: "Retain", want: retentionNeverOverwrite, ok: true},
		{mode: "AutoBackup", want: retentionNeverOverwrite, ok: true},
		{mode: " Retain ", want: retentionNeverOverwrite, ok: true},
		// An unrecognized or absent mode must not resolve to anything, so the
		// caller falls through to the documented default rather than guessing.
		{mode: "", ok: false},
		{mode: "Whatever", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			got, ok := decodeLogMode(tt.mode)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
