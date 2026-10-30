// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"strconv"
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

	// Windows 10 and later no longer write the registry result times, so ask
	// the Windows Update Agent when commands can run. The registry is only
	// the fallback when the agent cannot be asked.
	var wua *windows.WUAResults
	if conn, ok := w.MqlRuntime.Connection.(shared.Connection); ok && conn.Capabilities().Has(shared.Capability_RunCommand) {
		res, err := w.readWUAResults(conn)
		if err != nil {
			log.Debug().Err(err).Msg("windows.update.config> could not read Windows Update Agent results, using registry")
		} else {
			wua = res
		}
	}
	lastDetection, lastInstall := wuResultTimes(wua,
		parseWULastSuccessTime(regString(detect, "LastSuccessTime")),
		parseWULastSuccessTime(regString(install, "LastSuccessTime")))

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
		"lastDetectionSuccess": llx.TimeDataPtr(lastDetection),
		"lastDetectionError":   llx.StringData(wuDetectionError(wua, formatWULastError(regInt(detect, "LastError")))),
		"lastDownloadSuccess":  llx.TimeDataPtr(parseWULastSuccessTime(regString(download, "LastSuccessTime"))),
		"lastInstallSuccess":   llx.TimeDataPtr(lastInstall),
		"rebootPending":        llx.BoolData(rebootPending),
		"policyState":          intPtrData(policyState),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsUpdateConfig), nil
}

// wuResultTimes picks the last detection and install times. Once the Windows
// Update Agent answered, its values are used as they are, including a nil
// for "never": the registry keys Windows 10 and later stopped writing can
// still hold a value frozen years ago, and reporting that would make a host
// that never detected look like one that detected long ago.
//
// The detection time is the later of the agent's own last search and the
// newest successful scan of an OS update service in the event log, because
// Update Orchestrator scans only show up in the log.
func wuResultTimes(wua *windows.WUAResults, regDetection, regInstall *time.Time) (detection, install *time.Time) {
	if wua != nil {
		return laterTime(wua.LastSearchSuccess, wua.LastScanSuccess), wua.LastInstallationSuccess
	}
	return regDetection, regInstall
}

// wuDetectionError picks the last detection error. Once the Windows Update
// Agent query answered, the error is the code of the newest failed scan of an
// OS update service, but only while that failure is newer than the last
// successful detection (the later of the agent's search and the event log
// scan); a host that never succeeded reports its failure. Otherwise it is
// empty. The registry value only backs the case where the query failed.
func wuDetectionError(wua *windows.WUAResults, regError string) string {
	if wua == nil {
		return regError
	}
	if wua.LastScanFailure == nil {
		return ""
	}
	if success := laterTime(wua.LastSearchSuccess, wua.LastScanSuccess); success != nil && !wua.LastScanFailure.After(*success) {
		return ""
	}
	return wua.LastScanFailureCode
}

// laterTime returns the later of two optional times, nil only when both are nil.
func laterTime(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.After(*a):
		return b
	default:
		return a
	}
}

// readWUAResults runs WINDOWS_QUERY_WUA_RESULTS and parses its output.
func (w *mqlWindowsUpdate) readWUAResults(conn shared.Connection) (*windows.WUAResults, error) {
	cmd, err := conn.RunCommand(powershell.Encode(windows.WINDOWS_QUERY_WUA_RESULTS))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(io.LimitReader(cmd.Stderr, 1024))
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = fmt.Sprintf("exit status %d", cmd.ExitStatus)
		}
		return nil, fmt.Errorf("failed to read windows update agent results: %s", msg)
	}
	return windows.ParseWUAResults(cmd.Stdout)
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
		mqlEntry, err := w.newEntry(updateEntryInstalled, e.RevisionNumber, map[string]*llx.RawData{
			"updateId":       llx.StringData(e.UpdateID),
			"kbId":           llx.StringData(windows.ParseKBID(e.Title)),
			"title":          llx.StringData(e.Title),
			"classification": llx.StringData(windows.ClassifyUpdate(e.Classification, e.Title)),
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

// installedFromCBS enumerates installed updates from the Component Based
// Servicing store of an offline target (snapshot, disk image, mounted
// volume), which cannot run PowerShell. The package keys come from the
// SOFTWARE hive and the KB from each package's servicing manifest, since the
// key name does not carry it for the cumulative and hotpatch updates. Loading
// the hive requires the scanner to run on Windows; elsewhere, or when the hive
// cannot be read, the list is empty.
func (w *mqlWindowsUpdate) installedFromCBS() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)
	if !conn.Capabilities().Has(shared.Capability_File) {
		return []any{}, nil
	}
	fi, err := conn.FileInfo(registry.SoftwareRegPath)
	if err != nil {
		log.Debug().Err(err).Msg("windows.update> could not find SOFTWARE registry file")
		return []any{}, nil
	}
	reader, unload, err := windows.LoadOfflineCBSReader(fi.Path, conn.FileSystem())
	if err != nil {
		log.Debug().Err(err).Msg("windows.update> could not load SOFTWARE registry file")
		return []any{}, nil
	}
	defer unload()
	updates, err := windows.InstalledCBSUpdates(reader)
	if err != nil {
		log.Debug().Err(err).Msg("windows.update> could not list CBS packages")
		return []any{}, nil
	}

	res := make([]any, 0, len(updates))
	for _, u := range updates {
		mqlEntry, err := w.newEntry(updateEntryInstalled, 0, cbsEntryArgs(u))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEntry)
	}
	return res, nil
}

// cbsEntryArgs maps a CBS update onto the fields of a windows.update.entry.
// The manifest's release type ("Security Update") is not the vocabulary of the
// Windows Update Agent ("Security Updates"), so the classification is derived
// from a title that leads with it.
func cbsEntryArgs(u windows.CBSUpdate) map[string]*llx.RawData {
	title := strings.TrimSpace(u.ReleaseType + " (" + u.KB + ")")
	return map[string]*llx.RawData{
		"updateId":       llx.StringData(u.PackageName),
		"kbId":           llx.StringData(u.KB),
		"title":          llx.StringData(title),
		"classification": llx.StringData(windows.ClassifyUpdate("", title)),
		"severity":       llx.StringData(""),
		"supportUrl":     llx.StringData(""),
		"cveIds":         llx.ArrayData([]any{}, types.String),
		"date":           llx.TimeDataPtr(u.InstalledOn),
		"operation":      llx.StringData("Installation"),
		"rebootRequired": llx.BoolData(false),
		"categories":     llx.ArrayData([]any{}, types.String),
	}
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

		mqlEntry, err := w.newEntry(updateEntryAvailable, u.RevisionNumber, map[string]*llx.RawData{
			"updateId":       llx.StringData(u.UpdateID),
			"kbId":           llx.StringData(kbID),
			"title":          llx.StringData(u.Title),
			"classification": llx.StringData(windows.ClassifyUpdate(u.Classification, u.Title)),
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

// Lists a windows.update.entry belongs to. The same update can sit in both at
// once (a driver the agent installed and still offers), so the list is part
// of the entry's identity.
const (
	updateEntryInstalled = "installed"
	updateEntryAvailable = "available"
)

func (w *mqlWindowsUpdate) newEntry(list string, revision int, args map[string]*llx.RawData) (*mqlWindowsUpdateEntry, error) {
	id := firstNonEmptyStringArg(args, "updateId", "kbId", "title")
	args["__id"] = llx.StringData(updateEntryID(list, id, revision))

	o, err := CreateResource(w.MqlRuntime, "windows.update.entry", args)
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsUpdateEntry), nil
}

// updateEntryID builds the cache identity of a windows.update.entry. An update
// is identified by its UpdateID and revision, and the list it was read from is
// part of the key: an installed history record and an available search result
// for the same update carry different values (the install date and operation
// against none), and CreateResource hands back the first one cached for a
// repeated id.
func updateEntryID(list string, id string, revision int) string {
	return "windows.update.entry/" + list + "/" + id + "/" + strconv.Itoa(revision)
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
