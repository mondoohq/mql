// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// Registry locations that describe an Event Log channel. The live state the
// Event Log service reports for the channel wins over them where the two can
// disagree; the registry is read for the overrides it holds, as the fallback
// for a connection that cannot run commands, and to tell a channel that does
// not exist from one left at its defaults.
const (
	eventlogPolicyPathFmt  = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\%s`
	eventlogServicePathFmt = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\%s`
	// The WINEVT channel key is where a modern provider channel such as
	// Microsoft-Windows-PowerShell/Operational is configured. The classic
	// logs keep their configuration under Services\EventLog, so reading only
	// that key resolved every modern channel to the documented default and
	// reported a size nobody had set.
	eventlogChannelPathFmt = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\%s`
)

// Decoded Retention behaviors. The Event Log service since Windows Vista has
// no "overwrite events older than N days" mode: a channel either overwrites
// as needed or keeps its events, refusing new ones or archiving the full log.
const (
	retentionOverwriteAsNeeded = "overwrite_as_needed"
	retentionNeverOverwrite    = "never_overwrite"
)

// neverOverwriteRetention is the legacy Retention sentinel (0xFFFFFFFF) that
// selects "do not overwrite events"; it can also appear as -1 from a signed
// reading.
const neverOverwriteRetention int64 = 0xFFFFFFFF

type mqlWindowsEventlogInternal struct {
	lock    sync.Mutex
	loaded  atomic.Bool
	loadErr error
	// each map is value name (lower-cased) -> registry item for one key
	policy  map[string]registry.RegistryKeyItem
	service map[string]registry.RegistryKeyItem
	channel map[string]registry.RegistryKeyItem
	// registered is whether the channel has a Services\EventLog or a WINEVT
	// channel key. Every channel Get-WinEvent -ListLog enumerates has one of
	// the two, so a name with neither does not exist.
	registered bool
	// the live channel state is a command rather than a registry read, so it
	// is cached separately: the registry-backed fields must keep resolving on
	// a connection that cannot run commands
	stateLoaded atomic.Bool
	stateErr    error
	state       *windows.EventLogChannel
}

func (w *mqlWindowsEventlog) id() (string, error) {
	return "windows.eventlog/" + w.Name.Data, nil
}

func initWindowsEventlog(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// the channel is selected purely by name; the field accessors read the
	// registry lazily, so there is nothing to pre-fetch here
	return args, nil, nil
}

// readKey reads a single registry key and returns its values keyed by the
// lower-cased value name, and whether the key exists. A missing key yields an
// empty map rather than an error, so resolution can fall through to the next
// source.
func (w *mqlWindowsEventlog) readKey(path string) (map[string]registry.RegistryKeyItem, bool, error) {
	o, err := CreateResource(w.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, false, err
	}
	key := o.(*mqlRegistrykey)

	entries, err := key.getEntries()
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return map[string]registry.RegistryKeyItem{}, false, nil
		}
		return nil, false, err
	}

	res := make(map[string]registry.RegistryKeyItem, len(entries))
	for i := range entries {
		res[strings.ToLower(entries[i].Key)] = entries[i]
	}
	if len(res) > 0 {
		return res, true, nil
	}

	// A key without values still exists. Only this case costs the extra
	// existence check.
	exists := key.GetExists()
	if exists.Error != nil {
		return nil, false, exists.Error
	}
	return res, exists.Data, nil
}

// load reads the policy and effective registry keys exactly once and caches
// them so every field shares a single set of registry reads.
func (w *mqlWindowsEventlog) load() error {
	if w.loaded.Load() {
		return nil
	}
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.loaded.Load() || w.loadErr != nil {
		return w.loadErr
	}

	policy, _, err := w.readKey(fmt.Sprintf(eventlogPolicyPathFmt, w.Name.Data))
	if err != nil {
		w.loadErr = err
		return err
	}
	service, serviceExists, err := w.readKey(fmt.Sprintf(eventlogServicePathFmt, w.Name.Data))
	if err != nil {
		w.loadErr = err
		return err
	}
	channel, channelExists, err := w.readKey(fmt.Sprintf(eventlogChannelPathFmt, w.Name.Data))
	if err != nil {
		w.loadErr = err
		return err
	}

	w.policy = policy
	w.service = service
	w.channel = channel
	w.registered = serviceExists || channelExists
	w.loaded.Store(true)
	return nil
}

// errNoSuchChannel is the error for a channel name the target does not know.
// A policy that names a channel with a typo must fail rather than read a size
// or a retention mode nobody configured.
func errNoSuchChannel(name string) error {
	return llx.NotFound(fmt.Errorf("there is no Event Log channel named %q", name))
}

// loadRegistered loads the registry sources and fails for a channel that
// does not exist.
func (w *mqlWindowsEventlog) loadRegistered() error {
	if err := w.load(); err != nil {
		return err
	}
	if !w.registered {
		return errNoSuchChannel(w.Name.Data)
	}
	return nil
}

// registryItemInt extracts an int64 from a registry item, accepting both the
// DWORD form (effective channel config) and the string form ("0", "1",
// "0xFFFFFFFF") that the Group Policy keys use.
func registryItemInt(item registry.RegistryKeyItem) (int64, bool) {
	switch v := item.GetRawValue().(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return 0, false
		}
		// base 0 handles 0x-prefixed hex and plain decimal, including -1
		if n, err := strconv.ParseInt(s, 0, 64); err == nil {
			return n, true
		}
		if n, err := strconv.ParseUint(s, 0, 64); err == nil {
			return int64(n), true
		}
	}
	return 0, false
}

// resolveMaxSizeKB picks the maximum log size in KB out of the three registry
// sources, policy first, for a target whose live channel state is out of
// reach, and reports whether any of them carried a value at all. Pure
// function for unit testing.
//
// The registry holds overrides only. A channel left at the size its manifest
// declares has no value in any of these keys, which is why a miss here is
// reported rather than resolved to a default.
func resolveMaxSizeKB(policy, service, channel map[string]registry.RegistryKeyItem) (int64, bool) {
	// the Group Policy MaxSize is already expressed in KB
	if n, ok := lookupInt(policy, "maxsize"); ok {
		return n, true
	}
	// the effective Services\EventLog MaxSize is in bytes
	if n, ok := lookupInt(service, "maxsize"); ok {
		return n / 1024, true
	}
	// a modern provider channel is not under Services\EventLog at all; it is
	// configured under WINEVT, also in bytes. Without this source every modern
	// channel resolved to the documented default and reported a size nobody
	// had set. A classic log resolves above and never reaches here.
	if n, ok := lookupInt(channel, "maxsize"); ok {
		return n / 1024, true
	}
	return 0, false
}

func (w *mqlWindowsEventlog) maxSizeKB() (int64, error) {
	if err := w.loadRegistered(); err != nil {
		return 0, err
	}

	// The size the channel itself reports is what Windows applies, including
	// the size its manifest declares, which is in no registry key at all. A
	// Group Policy MaxSize written to the registry is not applied until the
	// Event Log service picks it up: measured on Windows 10 and 11, a policy
	// MaxSize of 32768 KB left the channel at 20971520 bytes in both
	// Get-WinEvent and wevtutil gl.
	state, stateErr := w.loadState()
	if stateErr == nil && state.MaximumSizeInBytes > 0 {
		return state.MaximumSizeInBytes / 1024, nil
	}

	// A connection that cannot run commands falls back to the registry.
	if n, ok := resolveMaxSizeKB(w.policy, w.service, w.channel); ok {
		return n, nil
	}

	// No source reports a size, and a manifest can declare any.
	if stateErr != nil {
		return 0, stateErr
	}
	return 0, fmt.Errorf("the Event Log channel %q reported no maximum size", w.Name.Data)
}

// decodeLogMode maps the effective LogMode Windows reports for a channel to a
// behavior, and reports whether it was recognized. AutoBackup archives the log
// when it is full and starts a new one, so like Retain it does not overwrite.
func decodeLogMode(mode string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "circular":
		return retentionOverwriteAsNeeded, true
	case "autobackup", "retain":
		return retentionNeverOverwrite, true
	default:
		return "", false
	}
}

// decodePolicyRetention maps the Group Policy values under
// Policies\Microsoft\Windows\EventLog\<channel> to a behavior, and reports
// whether either is set. EventLog.admx writes both as strings: Retention "1"
// is "Retain old events" (do not overwrite) and "0" overwrites as needed;
// AutoBackupLogFiles "1" archives the full log instead of overwriting it.
// Neither is the legacy period in seconds of the Services\EventLog key, so
// reading the policy "1" as a period reported a channel that keeps its events
// as one that overwrites them.
func decodePolicyRetention(policy map[string]registry.RegistryKeyItem) (string, bool) {
	ret, hasRet := lookupInt(policy, "retention")
	backup, hasBackup := lookupInt(policy, "autobackuplogfiles")
	switch {
	case hasRet && ret != 0, hasBackup && backup != 0:
		return retentionNeverOverwrite, true
	case hasRet:
		return retentionOverwriteAsNeeded, true
	default:
		return "", false
	}
}

// decodeServiceRetention maps the classic Services\EventLog\<log> values to a
// behavior, and reports whether either is set. Retention is the legacy period
// in seconds: 0 overwrites as needed and 0xFFFFFFFF (or -1) never overwrites.
// A positive period is what Limit-EventLog -OverflowAction OverwriteOlder
// writes, but the Event Log service has no by-days mode and runs that log
// circular (Get-WinEvent reports LogMode Circular, wevtutil gl retention
// false), so it overwrites as needed. AutoBackupLogFiles 1 archives the full
// log, which the service reports as LogMode AutoBackup.
func decodeServiceRetention(service map[string]registry.RegistryKeyItem) (string, bool) {
	ret, hasRet := lookupInt(service, "retention")
	backup, hasBackup := lookupInt(service, "autobackuplogfiles")
	switch {
	case hasBackup && backup != 0:
		return retentionNeverOverwrite, true
	case hasRet && (ret < 0 || ret == neverOverwriteRetention):
		return retentionNeverOverwrite, true
	case hasRet:
		return retentionOverwriteAsNeeded, true
	default:
		return "", false
	}
}

// decodeChannelRetention maps the WINEVT channel values to a behavior, and
// reports whether either is set. This key does not use the legacy seconds
// encoding of the classic logs: Retention is a flag, 0 for "overwrite events
// as needed" and non-zero for "do not overwrite events", and AutoBackup is a
// flag for archiving the full log.
func decodeChannelRetention(channel map[string]registry.RegistryKeyItem) (string, bool) {
	ret, hasRet := lookupInt(channel, "retention")
	backup, hasBackup := lookupInt(channel, "autobackup")
	switch {
	case hasRet && ret != 0, hasBackup && backup != 0:
		return retentionNeverOverwrite, true
	case hasRet:
		return retentionOverwriteAsNeeded, true
	default:
		return "", false
	}
}

// resolveRegistryRetention picks the retention behavior out of the registry
// sources, policy first, for a target whose live channel state is out of
// reach. Pure function for unit testing.
func resolveRegistryRetention(policy, service, channel map[string]registry.RegistryKeyItem) (string, bool) {
	if mode, ok := decodePolicyRetention(policy); ok {
		return mode, true
	}
	if mode, ok := decodeServiceRetention(service); ok {
		return mode, true
	}
	return decodeChannelRetention(channel)
}

// resolveRetention reports the retention behavior of the channel.
//
// The LogMode the Event Log service reports is the answer whenever it can be
// read, because the registry disagrees with it: a positive Services\EventLog
// Retention reads as a period but the log runs circular, a policy Retention
// "1" written to the registry left the channel Circular on Windows 10 and 11,
// and on Windows 11 a Services\EventLog Retention of -1 did not change the
// channel at all. The registry is the fallback for a connection that cannot
// run commands.
func (w *mqlWindowsEventlog) resolveRetention() (string, error) {
	if err := w.loadRegistered(); err != nil {
		return "", err
	}

	state, stateErr := w.loadState()
	if stateErr == nil {
		if mode, ok := decodeLogMode(state.LogMode); ok {
			return mode, nil
		}
	}

	if mode, ok := resolveRegistryRetention(w.policy, w.service, w.channel); ok {
		return mode, nil
	}

	// Nothing reports a behavior. A modern channel's manifest can declare
	// either one, so there is no default that is safe to assume.
	if stateErr != nil {
		return "", stateErr
	}
	return "", fmt.Errorf("the Event Log channel %q reported an unrecognized log mode %q", w.Name.Data, state.LogMode)
}

func (w *mqlWindowsEventlog) retention() (string, error) {
	return w.resolveRetention()
}

// overwriteAsNeeded is derived from the same resolution retention uses, so the
// two can never disagree about the same channel.
func (w *mqlWindowsEventlog) overwriteAsNeeded() (bool, error) {
	behavior, err := w.resolveRetention()
	if err != nil {
		return false, err
	}
	return behavior == retentionOverwriteAsNeeded, nil
}

// lookupInt returns the int64 value of a registry item from the given key map.
func lookupInt(items map[string]registry.RegistryKeyItem, name string) (int64, bool) {
	item, ok := items[name]
	if !ok {
		return 0, false
	}
	return registryItemInt(item)
}

// loadState reads the live channel state exactly once and caches it, so a
// query that reads whether the channel is enabled, where it writes, and how
// many events it holds costs a single remote command.
//
// It is separate from load because it is a command rather than a registry
// read: a connection that cannot run commands still resolves the registry
// sources of maxSizeKB, retention and overwriteAsNeeded.
func (w *mqlWindowsEventlog) loadState() (*windows.EventLogChannel, error) {
	if w.stateLoaded.Load() {
		return w.state, nil
	}
	// A name the registry does not know is reported as such, the same way
	// for every field. When the registry cannot be read, the command decides.
	if err := w.load(); err != nil {
		log.Debug().Err(err).Str("channel", w.Name.Data).Msg("could not read the Event Log channel registry keys, reading the channel through the command")
	} else if !w.registered {
		return nil, errNoSuchChannel(w.Name.Data)
	}

	w.lock.Lock()
	defer w.lock.Unlock()
	if w.stateLoaded.Load() || w.stateErr != nil {
		return w.state, w.stateErr
	}

	stdout, err := runWindowsPowerShell(w.MqlRuntime, windows.EventLogChannelScript(w.Name.Data),
		"read the Event Log channel "+w.Name.Data)
	if err != nil {
		w.stateErr = err
		return nil, err
	}

	state, err := windows.ParseEventLogChannel(stdout)
	if err != nil {
		w.stateErr = err
		return nil, err
	}

	w.state = state
	w.stateLoaded.Store(true)
	return state, nil
}

func (w *mqlWindowsEventlog) enabled() (bool, error) {
	state, err := w.loadState()
	if err != nil {
		return false, err
	}
	return state.IsEnabled, nil
}

func (w *mqlWindowsEventlog) logFilePath() (string, error) {
	state, err := w.loadState()
	if err != nil {
		return "", err
	}
	return state.ExpandedLogFilePath(), nil
}

func (w *mqlWindowsEventlog) isClassicLog() (bool, error) {
	state, err := w.loadState()
	if err != nil {
		return false, err
	}
	return state.IsClassicLog, nil
}

func (w *mqlWindowsEventlog) recordCount() (int64, error) {
	state, err := w.loadState()
	if err != nil {
		return 0, err
	}
	return state.RecordCount, nil
}
