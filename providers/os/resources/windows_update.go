// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/updates"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// registry paths backing windows.update.config
const (
	wuPolicyKey      = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
	wuPolicyAUKey    = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
	wuResultsDetect  = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect`
	wuResultsDownld  = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Download`
	wuResultsInstall = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install`
	wufbPolicyState  = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState`
	wuRebootCBS      = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`
	wuRebootAU       = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
	cbsPackagesKey   = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`
)

// LastSuccessTime values are stored in UTC as "yyyy-MM-dd HH:mm:ss".
const wuTimeLayout = "2006-01-02 15:04:05"

func (w *mqlWindowsUpdate) id() (string, error) {
	return "windows.update", nil
}

func (c *mqlWindowsUpdateConfig) id() (string, error) {
	return "windows.update.config", nil
}

func (p *mqlWindowsUpdatePolicy) id() (string, error) {
	return "windows.update.policy", nil
}

func (e *mqlWindowsUpdateEntry) id() (string, error) {
	switch {
	case e.UpdateId.Data != "":
		return "windows.update.entry/" + e.UpdateId.Data, nil
	case e.KbId.Data != "":
		return "windows.update.entry/" + e.KbId.Data, nil
	default:
		return "windows.update.entry/" + e.Title.Data, nil
	}
}

// readRegistryKey returns the values of a registry key as a name->item map
// (lower-cased keys). A missing key yields an empty map and read==true; a read
// failure (e.g. no registry access on a filesystem connection) yields
// read==false so callers can distinguish "not configured" from "unknown".
func (w *mqlWindowsUpdate) readRegistryKey(path string) (items map[string]registry.RegistryKeyItem, read bool) {
	items = map[string]registry.RegistryKeyItem{}
	o, err := CreateResource(w.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("windows.update> could not create registrykey resource")
		return items, false
	}
	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			// key is absent, but the registry was readable
			return items, true
		}
		log.Debug().Err(err).Str("path", path).Msg("windows.update> could not read registry key")
		return items, false
	}
	for i := range entries {
		items[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return items, true
}

func (w *mqlWindowsUpdate) registryKeyExists(path string) bool {
	o, err := CreateResource(w.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return false
	}
	exists := o.(*mqlRegistrykey).GetExists()
	if exists.Error != nil {
		return false
	}
	return exists.Data
}

func regString(items map[string]registry.RegistryKeyItem, name string) string {
	if it, ok := items[strings.ToLower(name)]; ok {
		return it.Value.String
	}
	return ""
}

func regInt(items map[string]registry.RegistryKeyItem, name string) int64 {
	if it, ok := items[strings.ToLower(name)]; ok {
		return it.Value.Number
	}
	return 0
}

func regHas(items map[string]registry.RegistryKeyItem, name string) bool {
	_, ok := items[strings.ToLower(name)]
	return ok
}

// intPtrData maps a nullable int into MQL data, emitting null when the value
// was not configured.
func intPtrData(v *int64) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.IntData(*v)
}

func parseWULastSuccessTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	t, err := time.ParseInLocation(wuTimeLayout, s, time.UTC)
	if err != nil {
		return nil
	}
	return &t
}

func formatWULastError(code int64) string {
	if code == 0 {
		return ""
	}
	return fmt.Sprintf("0x%X", uint32(code))
}

// deriveCatalogSource determines the effective update source from the raw
// registry signals. Order matters: an explicitly disabled agent wins, then
// WSUS, then Windows Update for Business, then direct Windows Update.
//
// noAutoUpdate is the modern way a host turns automatic updates off, and it is
// checked alongside the legacy AUOptions == 1 encoding. AUOptions has not had
// a value of 1 since Windows XP, so on any host this provider runs against
// that test alone never fired and a host with automatic updates switched off
// reported itself as pulling from Windows Update.
func deriveCatalogSource(read bool, useWUServer bool, wsusServerURL string, auOptions int64, noAutoUpdate bool, wufbConfigured bool) string {
	if !read {
		return "unknown"
	}
	if auOptions == 1 || noAutoUpdate {
		return "disabled"
	}
	if useWUServer && wsusServerURL != "" {
		return "wsus"
	}
	if wufbConfigured && wsusServerURL == "" {
		return "windowsUpdateForBusiness"
	}
	return "windowsUpdate"
}

// windows.update.config and windows.update.policy share their names with the
// dotted paths that reach them, so `windows.update.config.catalogSource`
// resolved the resource instead of the field and reported null for every
// setting. See initWindowsSingletonChild.
func initWindowsUpdateConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsSingletonChild(runtime, args, "windows.update",
		func(r plugin.Resource) *plugin.TValue[*mqlWindowsUpdateConfig] {
			return r.(*mqlWindowsUpdate).GetConfig()
		})
}

func initWindowsUpdatePolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsSingletonChild(runtime, args, "windows.update",
		func(r plugin.Resource) *plugin.TValue[*mqlWindowsUpdatePolicy] {
			return r.(*mqlWindowsUpdate).GetPolicy()
		})
}

func (w *mqlWindowsUpdate) config() (*mqlWindowsUpdateConfig, error) {
	policy, okPolicy := w.readRegistryKey(wuPolicyKey)
	au, okAU := w.readRegistryKey(wuPolicyAUKey)
	detect, okDetect := w.readRegistryKey(wuResultsDetect)
	download, _ := w.readRegistryKey(wuResultsDownld)
	install, _ := w.readRegistryKey(wuResultsInstall)
	wufb, okWufb := w.readRegistryKey(wufbPolicyState)

	// "read" is true when we were able to query the registry at all, even if
	// the keys are absent (a default direct-Windows-Update host has no policy
	// keys). It is false only when the registry could not be read.
	read := okPolicy || okAU || okDetect || okWufb

	wsusServerURL := regString(policy, "WUServer")
	wsusStatusServerURL := regString(policy, "WUStatusServer")
	useWUServer := regInt(au, "UseWUServer") == 1
	auOptions := regInt(au, "AUOptions")
	noAutoUpdate := regInt(au, "NoAutoUpdate") == 1

	// wufbPolicyState names the key, not a value inside it. Reading a value of
	// that name found nothing on any host: Server 2019, 2022 and 2025 carry
	// the key with a dozen values (DeferQualityUpdates, BranchReadinessLevel,
	// IsWUfBConfigured and the rest) and none of them is called PolicyState,
	// while Server 2016 has no such key at all. So the Windows Update for
	// Business branch below was unreachable and policyState reported a
	// constant 0 that no host had set.
	//
	// IsWUfBConfigured is the flag the key actually carries, and it is the
	// whole of what this key says about enrollment, so policyState and the
	// catalogSource gate are deliberately the same reading rather than two
	// values that happen to coincide. wufbConfigured is derived from
	// policyState to keep that explicit: an absent key is not enrollment, and
	// neither is the flag being present and 0.
	policyState := regIntPtr(wufb, "IsWUfBConfigured")
	wufbConfigured := policyState != nil && *policyState == 1

	catalogSource := deriveCatalogSource(read, useWUServer, wsusServerURL, auOptions, noAutoUpdate, wufbConfigured)

	rebootPending := w.registryKeyExists(wuRebootCBS) || w.registryKeyExists(wuRebootAU)

	o, err := CreateResource(w.MqlRuntime, "windows.update.config", map[string]*llx.RawData{
		"__id":                 llx.StringData("windows.update.config"),
		"catalogSource":        llx.StringData(catalogSource),
		"wsusServerUrl":        llx.StringData(wsusServerURL),
		"wsusStatusServerUrl":  llx.StringData(wsusStatusServerURL),
		"useWUServer":          llx.BoolData(useWUServer),
		"auOptions":            llx.IntData(auOptions),
		"lastDetectionSuccess": llx.TimeDataPtr(parseWULastSuccessTime(regString(detect, "LastSuccessTime"))),
		"lastDetectionError":   llx.StringData(formatWULastError(regInt(detect, "LastError"))),
		"lastDownloadSuccess":  llx.TimeDataPtr(parseWULastSuccessTime(regString(download, "LastSuccessTime"))),
		"lastInstallSuccess":   llx.TimeDataPtr(parseWULastSuccessTime(regString(install, "LastSuccessTime"))),
		"rebootPending":        llx.BoolData(rebootPending),
		"policyState":          intPtrData(policyState),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsUpdateConfig), nil
}

func (c *mqlWindowsUpdateConfig) service() (*mqlService, error) {
	o, err := NewResource(c.MqlRuntime, "service", map[string]*llx.RawData{
		"name": llx.StringData("wuauserv"),
	})
	if err != nil {
		// the wuauserv service can't be resolved (e.g. it doesn't exist):
		// mark the field null rather than surfacing the error.
		c.Service.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return o.(*mqlService), nil
}

// windowsUpdatePolicyValues holds the Windows Update for Business / Automatic
// Updates group policy settings extracted from the registry. Nil pointers mean
// the corresponding policy value is not configured.
type windowsUpdatePolicyValues struct {
	automaticUpdatesEnabled                bool
	noAutoUpdate                           *bool
	scheduledInstallDay                    *int64
	scheduledInstallTime                   *int64
	noAutoRebootWithLoggedOnUsers          *bool
	managePreviewBuilds                    *int64
	deferFeatureUpdates                    *bool
	deferFeatureUpdatesPeriodInDays        *int64
	deferQualityUpdates                    *bool
	deferQualityUpdatesPeriodInDays        *int64
	allowTemporaryEnterpriseFeatureControl *bool
	allowOptionalContent                   *int64
	disablePauseUXAccess                   *bool
}

// computeWindowsUpdatePolicy maps the raw registry values from the
// WindowsUpdate policy key and its AU subkey into the policy settings. It is
// pure so it can be unit tested without a live registry.
func computeWindowsUpdatePolicy(policy, au map[string]registry.RegistryKeyItem) windowsUpdatePolicyValues {
	return windowsUpdatePolicyValues{
		// Automatic Updates is "enabled" only when NoAutoUpdate is explicitly
		// present and set to 0; an absent value is the unmanaged default.
		automaticUpdatesEnabled:                regHas(au, "NoAutoUpdate") && regInt(au, "NoAutoUpdate") == 0,
		noAutoUpdate:                           regBoolPtr(au, "NoAutoUpdate"),
		scheduledInstallDay:                    regIntPtr(au, "ScheduledInstallDay"),
		scheduledInstallTime:                   regIntPtr(au, "ScheduledInstallTime"),
		noAutoRebootWithLoggedOnUsers:          regBoolPtr(au, "NoAutoRebootWithLoggedOnUsers"),
		managePreviewBuilds:                    regIntPtr(policy, "ManagePreviewBuildsPolicyValue"),
		deferFeatureUpdates:                    regBoolPtr(policy, "DeferFeatureUpdates"),
		deferFeatureUpdatesPeriodInDays:        regIntPtr(policy, "DeferFeatureUpdatesPeriodInDays"),
		deferQualityUpdates:                    regBoolPtr(policy, "DeferQualityUpdates"),
		deferQualityUpdatesPeriodInDays:        regIntPtr(policy, "DeferQualityUpdatesPeriodInDays"),
		allowTemporaryEnterpriseFeatureControl: regBoolPtr(policy, "AllowTemporaryEnterpriseFeatureControl"),
		allowOptionalContent:                   regIntPtr(policy, "SetAllowOptionalContent"),
		disablePauseUXAccess:                   regBoolPtr(policy, "SetDisablePauseUXAccess"),
	}
}

func (w *mqlWindowsUpdate) policy() (*mqlWindowsUpdatePolicy, error) {
	policy, okPolicy := w.readRegistryKey(wuPolicyKey)
	au, okAU := w.readRegistryKey(wuPolicyAUKey)

	// readRegistryKey returns true when the registry was queryable at all, even
	// when the key is simply absent (the default on an unmanaged host). When
	// neither key could be read the registry connection itself is broken, so
	// surface that rather than silently reporting an unconfigured policy.
	if !okPolicy && !okAU {
		return nil, errors.New("windows.update.policy: could not read the Windows Update policy registry keys")
	}

	v := computeWindowsUpdatePolicy(policy, au)

	o, err := CreateResource(w.MqlRuntime, "windows.update.policy", map[string]*llx.RawData{
		"__id":                                   llx.StringData("windows.update.policy"),
		"automaticUpdatesEnabled":                llx.BoolData(v.automaticUpdatesEnabled),
		"noAutoUpdate":                           llx.BoolDataPtr(v.noAutoUpdate),
		"scheduledInstallDay":                    intPtrData(v.scheduledInstallDay),
		"scheduledInstallTime":                   intPtrData(v.scheduledInstallTime),
		"noAutoRebootWithLoggedOnUsers":          llx.BoolDataPtr(v.noAutoRebootWithLoggedOnUsers),
		"managePreviewBuilds":                    intPtrData(v.managePreviewBuilds),
		"deferFeatureUpdates":                    llx.BoolDataPtr(v.deferFeatureUpdates),
		"deferFeatureUpdatesPeriodInDays":        intPtrData(v.deferFeatureUpdatesPeriodInDays),
		"deferQualityUpdates":                    llx.BoolDataPtr(v.deferQualityUpdates),
		"deferQualityUpdatesPeriodInDays":        intPtrData(v.deferQualityUpdatesPeriodInDays),
		"allowTemporaryEnterpriseFeatureControl": llx.BoolDataPtr(v.allowTemporaryEnterpriseFeatureControl),
		"allowOptionalContent":                   intPtrData(v.allowOptionalContent),
		"disablePauseUXAccess":                   llx.BoolDataPtr(v.disablePauseUXAccess),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsUpdatePolicy), nil
}

func (w *mqlWindowsUpdate) installed() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)
	if conn.Capabilities().Has(shared.Capability_RunCommand) {
		return w.installedFromWUA(conn)
	}
	// No command execution available (e.g. a snapshot scan): fall back to the
	// Component Based Servicing package store in the registry.
	return w.installedFromCBS()
}

// installedFromWUA reads the Windows Update Agent install history via the COM
// API, keeping only succeeded installations, de-duplicated by KB (or update
// identity when a KB is not present).
func (w *mqlWindowsUpdate) installedFromWUA(conn shared.Connection) ([]any, error) {
	cmd, err := conn.RunCommand(powershell.Encode(windows.WINDOWS_QUERY_UPDATE_HISTORY))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("failed to retrieve update history: %s", string(stderr))
	}

	history, err := windows.ParseWindowsUpdateHistory(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	entries := windows.FilterInstalledHistory(history)
	res := make([]any, 0, len(entries))
	for i := range entries {
		e := entries[i]
		mqlEntry, err := w.newEntry(map[string]*llx.RawData{
			"updateId":       llx.StringData(e.UpdateID),
			"kbId":           llx.StringData(windows.ParseKBID(e.Title)),
			"title":          llx.StringData(e.Title),
			"classification": llx.StringData(windows.ClassifyUpdate(e.Categories, e.Title)),
			"severity":       llx.StringData(""),
			"supportUrl":     llx.StringData(e.SupportUrl),
			"cveIds":         llx.ArrayData([]any{}, types.String),
			"date":           llx.TimeDataPtr(powershell.PSJsonTimestamp(e.Date)),
			"operation":      llx.StringData(windows.OperationName(e.Operation)),
			"rebootRequired": llx.BoolData(false),
			"categories":     llx.ArrayData(strSliceToAny(e.Categories), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEntry)
	}
	return res, nil
}

// installedFromCBS enumerates installed packages from the Component Based
// Servicing store in the registry. This path needs no command execution, so
// it backs connections (such as snapshot scans) that cannot run PowerShell —
// it is effective wherever the registry is readable.
func (w *mqlWindowsUpdate) installedFromCBS() ([]any, error) {
	o, err := CreateResource(w.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(cbsPackagesKey),
	})
	if err != nil {
		log.Debug().Err(err).Msg("windows.update> could not access CBS package store")
		return []any{}, nil
	}
	children := o.(*mqlRegistrykey).GetChildren()
	if children.Error != nil {
		log.Debug().Err(children.Error).Msg("windows.update> could not list CBS packages")
		return []any{}, nil
	}

	seen := map[string]struct{}{}
	res := []any{}
	for i := range children.Data {
		childPath, ok := children.Data[i].(string)
		if !ok {
			continue
		}
		name := childPath
		if idx := strings.LastIndex(childPath, `\`); idx >= 0 {
			name = childPath[idx+1:]
		}

		kbID := windows.ParseKBID(name)
		if kbID == "" {
			// CBS holds thousands of component packages; without a KB there is
			// nothing actionable to report as an installed update.
			continue
		}

		items, _ := w.readRegistryKey(childPath)
		if regInt(items, "CurrentState") != windows.CBSStateInstalled {
			continue
		}

		if _, ok := seen[kbID]; ok {
			continue
		}
		seen[kbID] = struct{}{}

		mqlEntry, err := w.newEntry(map[string]*llx.RawData{
			"updateId":       llx.StringData(name),
			"kbId":           llx.StringData(kbID),
			"title":          llx.StringData(name),
			"classification": llx.StringData(windows.ClassifyUpdate(nil, name)),
			"severity":       llx.StringData(""),
			"supportUrl":     llx.StringData(""),
			"cveIds":         llx.ArrayData([]any{}, types.String),
			"date":           llx.TimeDataPtr(nil),
			"operation":      llx.StringData("Installation"),
			"rebootRequired": llx.BoolData(false),
			"categories":     llx.ArrayData([]any{}, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEntry)
	}
	return res, nil
}

func (w *mqlWindowsUpdate) available() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		// The agent's "what is available" view is a live query; there is no
		// registry/filesystem source for it.
		log.Debug().Msg("windows.update> cannot search for available updates without command execution")
		return []any{}, nil
	}

	// reuse the shared Windows Update Agent search behind os.update, but with
	// the broader "available" criteria (drivers included, hidden excluded).
	//
	// Searched offline (online=false): the search answers from the cache of
	// the agent's last detection instead of running a new one against
	// Windows Update/WSUS, which can take minutes. That makes the result only
	// as fresh as the last detection; windows.update.config.lastDetectionSuccess
	// is the freshness signal, and callers that need a guaranteed-current
	// answer must check it (or trigger a detection themselves) rather than
	// assume this call just performed one. os.update (WindowsUpdateManager,
	// same query builder) stays online because it drives patch-state
	// reporting, where a stale cache would under- or over-report what is
	// actually outstanding.
	wuUpdates, err := updates.SearchWindowsUpdates(conn, updates.WindowsUpdateCriteriaAvailable, false)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(wuUpdates))
	for i := range wuUpdates {
		u := wuUpdates[i]
		// KBArticleIDs are bare numbers (e.g. "5034441"); normalize to "KB…".
		kbID := ""
		if len(u.KBArticleIDs) > 0 {
			kbID = windows.ParseKBID("KB" + u.KBArticleIDs[0])
		}

		mqlEntry, err := w.newEntry(map[string]*llx.RawData{
			"updateId":       llx.StringData(u.UpdateID),
			"kbId":           llx.StringData(kbID),
			"title":          llx.StringData(u.Title),
			"classification": llx.StringData(windows.ClassifyUpdate(u.Categories, u.Title)),
			"severity":       llx.StringData(u.MsrcSeverity),
			"supportUrl":     llx.StringData(u.SupportUrl),
			"cveIds":         llx.ArrayData(strSliceToAny(u.CveIDs), types.String),
			"date":           llx.TimeDataPtr(nil),
			"operation":      llx.StringData(""),
			"rebootRequired": llx.BoolData(u.RebootRequired),
			"categories":     llx.ArrayData(strSliceToAny(u.Categories), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEntry)
	}
	return res, nil
}

func (w *mqlWindowsUpdate) newEntry(args map[string]*llx.RawData) (*mqlWindowsUpdateEntry, error) {
	id := firstNonEmptyStringArg(args, "updateId", "kbId", "title")
	args["__id"] = llx.StringData("windows.update.entry/" + id)

	o, err := CreateResource(w.MqlRuntime, "windows.update.entry", args)
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsUpdateEntry), nil
}

// firstNonEmptyStringArg returns the first non-empty string value among the
// given keys. It uses a comma-ok assertion so a nil or non-string value never
// panics.
func firstNonEmptyStringArg(args map[string]*llx.RawData, keys ...string) string {
	for _, k := range keys {
		v, ok := args[k]
		if !ok || v == nil {
			continue
		}
		if s, ok := v.Value.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func strSliceToAny(in []string) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}
