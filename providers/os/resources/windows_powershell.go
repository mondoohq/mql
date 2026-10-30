// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// Registry locations that back the PowerShell logging policy. These are GPO-only
// values under the PowerShell policy key; there is no effective fallback, so
// when a value is absent the corresponding field is null (distinguishable from
// an explicit 0).
//
// The lockdown state is not a policy value: PowerShell reads __PSLockdownPolicy
// as a machine-scoped environment variable, which lives in the Session Manager
// environment key.
const (
	powershellPolicyPath        = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell`
	powershellScriptBlockPath   = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
	powershellTranscriptionPath = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`
	powershellModuleLoggingPath = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`
	powershellModuleNamesPath   = powershellModuleLoggingPath + `\ModuleNames`
	powershellEnvironmentPath   = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	powershellLockdownValue     = "__PSLockdownPolicy"
)

// Windows Lockdown Policy (WLDP) state flags, as PowerShell interprets the
// __PSLockdownPolicy fall-back value. Audit is checked before enforcement,
// mirroring PowerShell's own precedence.
const (
	wldpLockdownUmciEnforceFlag int64 = 0x4
	wldpLockdownUmciAuditFlag   int64 = 0x8
)

func (r *mqlWindowsPowershell) id() (string, error) {
	return "windows.powershell", nil
}

func (r *mqlWindowsPowershellScriptBlockLogging) id() (string, error) {
	return "windows.powershell.scriptBlockLogging", nil
}

func (r *mqlWindowsPowershellModuleLogging) id() (string, error) {
	return "windows.powershell.moduleLogging", nil
}

func (r *mqlWindowsPowershellTranscription) id() (string, error) {
	return "windows.powershell.transcription", nil
}

// readPowershellEntries reads a single registry key and returns its value
// entries with their original names. A missing key yields an empty slice rather
// than an error, so absent values resolve to null.
func readPowershellEntries(runtime *plugin.Runtime, path string) ([]registry.RegistryKeyItem, error) {
	o, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}

	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		// a missing key is expected (e.g. no Group Policy configured); treat it
		// as empty so absent values resolve to null
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}
	return entries, nil
}

// readPowershellKey reads a single registry key and returns its values keyed by
// the lower-cased value name. A missing key yields an empty map rather than an
// error, so absent values resolve to null.
func readPowershellKey(runtime *plugin.Runtime, path string) (map[string]registry.RegistryKeyItem, error) {
	entries, err := readPowershellEntries(runtime, path)
	if err != nil {
		return nil, err
	}

	res := make(map[string]registry.RegistryKeyItem, len(entries))
	for i := range entries {
		res[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return res, nil
}

// powershellKeyExists reports whether a registry key is present. It is what
// separates "the policy names no module" from "the policy was never configured"
// for the ModuleNames subkey, which are indistinguishable from an empty value
// list alone.
func powershellKeyExists(runtime *plugin.Runtime, path string) (bool, error) {
	o, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return false, err
	}
	exists := o.(*mqlRegistrykey).GetExists()
	if exists.Error != nil {
		return false, exists.Error
	}
	return exists.Data, nil
}

// powershellBoolPtr returns a pointer to the boolean interpretation of a
// registry DWORD (true for any non-zero value), or nil when the value name is
// absent. Returning a pointer keeps "not configured" (nil) distinguishable from
// an explicit false. Pure function for unit testing.
func powershellBoolPtr(items map[string]registry.RegistryKeyItem, name string) *bool {
	if it, ok := items[strings.ToLower(name)]; ok {
		v := it.Value.Number != 0
		return &v
	}
	return nil
}

// powershellStringPtr returns a pointer to the string value of a registry value,
// or nil when the value name is absent. Returning a pointer keeps "not
// configured" (nil) distinguishable from an explicit empty string. Pure function
// for unit testing.
func powershellStringPtr(items map[string]registry.RegistryKeyItem, name string) *string {
	if it, ok := items[strings.ToLower(name)]; ok {
		v := it.Value.String
		return &v
	}
	return nil
}

// powershellModuleNames returns the module names a Module Logging policy selects.
// Group Policy writes one registry value per module under the ModuleNames
// subkey, using the module name as the value name (the well-known wildcard entry
// "*" selects every module), so the names are read from the value names rather
// than their data. The result is sorted so the list is stable across reads.
// Pure function for unit testing.
func powershellModuleNames(entries []registry.RegistryKeyItem) []string {
	names := make([]string, 0, len(entries))
	for i := range entries {
		if entries[i].Key == "" {
			continue
		}
		names = append(names, entries[i].Key)
	}
	sort.Strings(names)
	return names
}

// powershellLockdownPolicy returns the numeric __PSLockdownPolicy value, or nil
// when the value is absent or does not parse as a number. Machine environment
// variables are stored as strings, but the value is sometimes written as a
// DWORD, so both are accepted. Pure function for unit testing.
func powershellLockdownPolicy(items map[string]registry.RegistryKeyItem) *int64 {
	it, ok := items[strings.ToLower(powershellLockdownValue)]
	if !ok {
		return nil
	}

	switch it.Value.Kind {
	case registry.DWORD, registry.QWORD:
		v := it.Value.Number
		return &v
	}

	raw := strings.TrimSpace(it.Value.String)
	if raw == "" {
		return nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		// the value is present but is not a number PowerShell could convert, so
		// nothing can be said about the lockdown state
		return nil
	}
	return &v
}

// powershellLanguageMode maps a __PSLockdownPolicy state bitmask to the language
// mode PowerShell runs sessions in. Enforcement runs sessions in
// ConstrainedLanguage; audit records what would have been blocked without
// restricting the session, so it stays FullLanguage. Pure function for unit
// testing.
func powershellLanguageMode(state int64) string {
	if state&wldpLockdownUmciAuditFlag != 0 {
		return "FullLanguage"
	}
	if state&wldpLockdownUmciEnforceFlag != 0 {
		return "ConstrainedLanguage"
	}
	return "FullLanguage"
}

// Each singleton sub-resource below shares its name with the dotted path that
// reaches it, so querying `windows.powershell.transcription.enabled` resolved
// the resource instead of the field. See initWindowsSingletonChild.
func initWindowsPowershellScriptBlockLogging(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsSingletonChild(runtime, args, "windows.powershell",
		func(r plugin.Resource) *plugin.TValue[*mqlWindowsPowershellScriptBlockLogging] {
			return r.(*mqlWindowsPowershell).GetScriptBlockLogging()
		})
}

func initWindowsPowershellModuleLogging(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsSingletonChild(runtime, args, "windows.powershell",
		func(r plugin.Resource) *plugin.TValue[*mqlWindowsPowershellModuleLogging] {
			return r.(*mqlWindowsPowershell).GetModuleLogging()
		})
}

func initWindowsPowershellTranscription(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsSingletonChild(runtime, args, "windows.powershell",
		func(r plugin.Resource) *plugin.TValue[*mqlWindowsPowershellTranscription] {
			return r.(*mqlWindowsPowershell).GetTranscription()
		})
}

func (r *mqlWindowsPowershell) scriptBlockLogging() (*mqlWindowsPowershellScriptBlockLogging, error) {
	items, err := readPowershellKey(r.MqlRuntime, powershellScriptBlockPath)
	if err != nil {
		return nil, err
	}

	o, err := CreateResource(r.MqlRuntime, "windows.powershell.scriptBlockLogging", map[string]*llx.RawData{
		"__id":              llx.StringData("windows.powershell.scriptBlockLogging"),
		"enabled":           llx.BoolDataPtr(powershellBoolPtr(items, "EnableScriptBlockLogging")),
		"invocationLogging": llx.BoolDataPtr(powershellBoolPtr(items, "EnableScriptBlockInvocationLogging")),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsPowershellScriptBlockLogging), nil
}

func (r *mqlWindowsPowershell) moduleLogging() (*mqlWindowsPowershellModuleLogging, error) {
	items, err := readPowershellKey(r.MqlRuntime, powershellModuleLoggingPath)
	if err != nil {
		return nil, err
	}

	o, err := CreateResource(r.MqlRuntime, "windows.powershell.moduleLogging", map[string]*llx.RawData{
		"__id":    llx.StringData("windows.powershell.moduleLogging"),
		"enabled": llx.BoolDataPtr(powershellBoolPtr(items, "EnableModuleLogging")),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsPowershellModuleLogging), nil
}

func (r *mqlWindowsPowershellModuleLogging) moduleNames() ([]any, error) {
	entries, err := readPowershellEntries(r.MqlRuntime, powershellModuleNamesPath)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		// an empty value list is either a policy that names no module or a
		// subkey that was never created; only the latter is "not configured"
		exists, err := powershellKeyExists(r.MqlRuntime, powershellModuleNamesPath)
		if err != nil {
			return nil, err
		}
		if !exists {
			r.ModuleNames.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
	}

	return strSliceToAny(powershellModuleNames(entries)), nil
}

func (r *mqlWindowsPowershell) transcription() (*mqlWindowsPowershellTranscription, error) {
	items, err := readPowershellKey(r.MqlRuntime, powershellTranscriptionPath)
	if err != nil {
		return nil, err
	}

	o, err := CreateResource(r.MqlRuntime, "windows.powershell.transcription", map[string]*llx.RawData{
		"__id":                   llx.StringData("windows.powershell.transcription"),
		"enabled":                llx.BoolDataPtr(powershellBoolPtr(items, "EnableTranscripting")),
		"outputDirectory":        llx.StringDataPtr(powershellStringPtr(items, "OutputDirectory")),
		"enableInvocationHeader": llx.BoolDataPtr(powershellBoolPtr(items, "EnableInvocationHeader")),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsPowershellTranscription), nil
}

func (r *mqlWindowsPowershell) executionPolicy() (string, error) {
	items, err := readPowershellKey(r.MqlRuntime, powershellPolicyPath)
	if err != nil {
		return "", err
	}
	v := powershellStringPtr(items, "ExecutionPolicy")
	if v == nil {
		// the value is absent: set the field null so callers can distinguish
		// "not configured" from an explicit empty string. GetOrCompute respects
		// a field that the resolver sets proactively.
		r.ExecutionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

func (r *mqlWindowsPowershell) lockdownPolicy() (int64, error) {
	items, err := readPowershellKey(r.MqlRuntime, powershellEnvironmentPath)
	if err != nil {
		return 0, err
	}
	v := powershellLockdownPolicy(items)
	if v == nil {
		// no lockdown value is set, which is the default. Reporting 0 here would
		// claim the host was explicitly opted out of lockdown, so report null.
		r.LockdownPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *v, nil
}

func (r *mqlWindowsPowershell) languageMode() (string, error) {
	// derive from the already-resolved lockdownPolicy field so a query for both
	// reads the environment key once and the two fields stay consistent
	raw := r.GetLockdownPolicy()
	if raw.Error != nil {
		return "", raw.Error
	}
	if raw.State&plugin.StateIsNull != 0 {
		// without a lockdown value nothing can be said about the language mode:
		// an App Control or AppLocker policy may still constrain the session
		r.LanguageMode.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return powershellLanguageMode(raw.Data), nil
}
