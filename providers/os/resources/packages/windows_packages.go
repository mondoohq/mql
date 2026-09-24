// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

const (
	installScopeMachine = "machine"
	installScopeUser    = "user"
)

// Compiled once: reused for each root the appx search walks.
var appxManifestPattern = regexp.MustCompile(".*/[Aa]ppx[Mm]anifest.xml")

// ProcessorArchitecture Enum
// https://learn.microsoft.com/en-us/uwp/api/windows.system.processorarchitecture
// https://learn.microsoft.com/en-us/dotnet/api/system.reflection.processorarchitecture?redirectedfrom=MSDN&view=netframework-4.8
// Microsoft.Windows.Appx.PackageManager.Commands.AppxPackage
// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/um/appxpackaging.idl#L60-L67
const (
	WinArchX86     = 0
	WinArchArm     = 5
	WinArchX64     = 9
	WinArchNeutral = 11
	WinArchArm64   = 12
	// The Arm64 processor architecture emulating the X86 architecture
	WinArchX86OnArm64 = 14
)

// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ff357803(v=vs.85)
var (
	wsusClassificationGUID = map[string]WSUSClassification{ //nolint:unused
		"5c9376ab-8ce6-464a-b136-22113dd69801": Application,
		"434de588-ed14-48f5-8eed-a15e09a991f6": Connectors,
		"e6cf1350-c01b-414d-a61f-263d14d133b4": CriticalUpdates,
		"e0789628-ce08-4437-be74-2495b842f43b": DefinitionUpdates,
		"e140075d-8433-45c3-ad87-e72345b3607":  DeveloperKits,
		"b54e7d24-7add-428f-8b75-90a396fa584f": FeaturePacks,
		"9511D615-35B2-47BB-927F-F73D8E9260BB": Guidance,
		"0fa1201d-4330-4fa8-8ae9-b877473b6441": SecurityUpdates,
		"68c5b0a3-d1a6-4553-ae49-01d3a7827828": ServicePacks,
		"b4832bd8-e735-4761-8daf-37f882276dab": Tools,
		"28bc880e-0592-4cbf-8f95-c79b17911d5f": UpdateRollups,
		"cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83": Updates,
		"ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0": Drivers,
		"8c3fcc84-7410-4a95-8b89-a166a0190486": Defender,
	}

	appxArchitecture = map[int]string{
		WinArchNeutral:    "neutral",
		WinArchX86:        "x86",
		WinArchX64:        "x64",
		WinArchArm64:      "arm64",
		WinArchArm:        "arm",
		WinArchX86OnArm64: "x86onarm",
	}

	sqlGDRUpdateRegExp = regexp.MustCompile(`^GDR.\d+.+SQL.Server.\d+.\(KB\d+\)`)
	exchangeCURegExp   = regexp.MustCompile(`^Microsoft Exchange Server.\d+.+Update.\d+$`)
	sqlHotfixRegExp    = regexp.MustCompile(`^Hotfix.+SQL.Server`)
	// Find the database engine package and use version as a reference for the update
	msSqlServiceRegexp = regexp.MustCompile(`^SQL Server \d+ Database Engine Services$`)
)

type WSUSClassification int

const (
	Application WSUSClassification = iota
	Connectors
	CriticalUpdates
	DefinitionUpdates
	DeveloperKits
	FeaturePacks
	Guidance
	SecurityUpdates
	ServicePacks
	Tools
	UpdateRollups
	Updates
	Drivers
	Defender
)

// installedAppsScript reads the machine-wide Uninstall keys plus the calling
// identity's own HKCU, then extends the same read to every other user profile
// Windows knows about (HKLM\...\ProfileList) whose hive is currently live
// under HKEY_USERS. A profile with no active logon session has no live hive to
// read remotely -- reaching NTUSER.DAT would mean `reg load`/`reg unload` on
// the target for a session this code does not own, so that case is simply
// skipped rather than attempted. This is why an unattended/SYSTEM scan over a
// remote connection still only sees software installed while a user was
// logged in; the local native path (getLocalInstalledApps) additionally loads
// NTUSER.DAT for logged-off users via a function-scoped userHiveHandler,
// unloaded again as soon as that profile's two key reads are done (see
// getProfileInstalledApps).
//
// Each entry carries the InstallScope ("machine" or "user") and InstallUser
// (SID, "user" entries only) it was read under, computed here rather than
// inferred later from PSPath so the Go parser needs no path parsing.
//
// The calling identity's own SID is checked against the well-known service
// SIDs (S-1-5-18/19/20): when cnquery runs as LocalSystem (an SCCM/Intune
// agent), HKCU IS S-1-5-18's hive, not a real user's, so its entries are
// tagged "machine" with no user rather than "user"/S-1-5-18.
//
// The Get-ItemProperty read below carries -ErrorAction SilentlyContinue:
// without it, a user logging off between the Test-Path probe and the read,
// or a restrictive ACL on another user's live hive, makes that one read fail
// and the WHOLE script exit non-zero (PowerShell's non-interactive host
// reports failure once any error reaches the error stream), which fails
// getInstalledApps for the entire asset over one vanished hive. Scoped to
// this one call only -- every other statement here should still surface a
// real failure.
const installedAppsScript = `
$callingSid = $null
try { $callingSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value } catch {}
$wellKnownSystemSids = @{ 'S-1-5-18' = $true; 'S-1-5-19' = $true; 'S-1-5-20' = $true }
$callingIsSystem = $callingSid -and $wellKnownSystemSids.ContainsKey($callingSid)
$hkcuScope = 'user'
$hkcuSid = $callingSid
if ($callingIsSystem) { $hkcuScope = 'machine'; $hkcuSid = '' }

$skipSids = @{ 'S-1-5-18' = $true; 'S-1-5-19' = $true; 'S-1-5-20' = $true; '.DEFAULT' = $true }
if ($callingSid) { $skipSids[$callingSid] = $true }

$roots = New-Object System.Collections.Generic.List[object]
$roots.Add(@{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Scope = 'machine'; Sid = '' })
$roots.Add(@{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Scope = $hkcuScope; Sid = $hkcuSid })
$roots.Add(@{ Path = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Scope = 'machine'; Sid = '' })
$roots.Add(@{ Path = 'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Scope = $hkcuScope; Sid = $hkcuSid })

$plKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', $false)
if ($plKey) {
    try {
        foreach ($sid in $plKey.GetSubKeyNames()) {
            if ($skipSids.ContainsKey($sid)) { continue }
            if (-not (Test-Path "Registry::HKEY_USERS\$sid")) { continue }
            $roots.Add(@{ Path = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope = 'user'; Sid = $sid })
            $roots.Add(@{ Path = "Registry::HKEY_USERS\$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope = 'user'; Sid = $sid })
        }
    } finally { $plKey.Close() }
}

$roots | Where-Object { Test-Path $_.Path } | ForEach-Object {
    $scope = $_.Scope
    $sid = $_.Sid
    Get-ItemProperty $_.Path -ErrorAction SilentlyContinue |
    Select-Object -Property DisplayName,DisplayVersion,Publisher,EstimatedSize,InstallSource,UninstallString,InstallLocation,InstallDate,PSPath,
      @{Name='InstallScope';Expression={$scope}}, @{Name='InstallUser';Expression={$sid}}
} | ConvertTo-Json -Compress
`

// We need to fill in the path collected from the registry
const dotNetClrVersionScript = `
((Get-Item "%sclr.dll").VersionInfo).ProductVersion
`

// dotNetClr2VersionScript resolves the servicing build of the CLR 2.0 runtime
// that backs .NET Framework 3.5. CLR 2.0 has no clr.dll; its assemblies live
// under %WINDIR%\Microsoft.NET\Framework[64]\v2.0.50727. Some files there stay
// pinned to older builds for side-by-side compatibility, so we take the highest
// 2.0.50727.<build> across every assembly in that directory to reflect the
// actual patch level.
const dotNetClr2VersionScript = `
$paths = @(
  "$env:WINDIR\Microsoft.NET\Framework64\v2.0.50727",
  "$env:WINDIR\Microsoft.NET\Framework\v2.0.50727"
)
$best = ''
$bestBuild = -1
foreach ($p in $paths) {
  if (Test-Path $p) {
    Get-ChildItem -Path $p -Filter *.dll -ErrorAction SilentlyContinue | ForEach-Object {
      $pv = $_.VersionInfo.ProductVersion
      if ($pv -match '^2\.0\.50727\.(\d+)') {
        $b = [int]$Matches[1]
        if ($b -gt $bestBuild) { $bestBuild = $b; $best = ($pv -split '\s+')[0] }
      }
    }
  }
}
$best
`

var (
	WINDOWS_QUERY_HOTFIXES      = `Get-HotFix | Select-Object -Property Status, Description, HotFixId, Caption, InstalledOn, InstalledBy | ConvertTo-Json`
	WINDOWS_QUERY_APPX_PACKAGES = `Get-AppxPackage -AllUsers | Select Name, PackageFullName, Architecture, Version, Publisher, InstallLocation | ConvertTo-Json`
)

type winAppxPackages struct {
	Name            string `json:"Name"`
	FullName        string `json:"PackageFullName"`
	Architecture    int    `json:"Architecture"`
	Version         string `json:"Version"`
	Publisher       string `json:"Publisher"`
	InstallLocation string `json:"InstallLocation"`
	// can directly set it to the architecture string, the pwsh script returns it as int (Architecture)
	arch string `json:"-"`
}

func (p winAppxPackages) toPackage(platform *inventory.Platform) Package {
	if p.arch == "" {
		arch, ok := appxArchitecture[p.Architecture]
		if !ok {
			log.Warn().Int("arch", p.Architecture).Msg("unknown architecture value for windows appx package")
			arch = "unknown"
		}
		p.arch = arch
	}

	pkg := createPackage(p.Name, p.Version, "windows/appx", p.arch, p.Publisher, p.InstallLocation, platform)
	// Get-AppxPackage -AllUsers reports no per-user owner: an appx package can
	// be provisioned for every profile or installed by one user, and nothing
	// in its output distinguishes the two. Reported as "machine" rather than
	// left empty, since it IS enumerated once for the whole machine, but this
	// is not the same attribution guarantee the Uninstall-registry-derived
	// packages above carry.
	pkg.InstallScope = installScopeMachine

	return *pkg
}

// Good read: https://www.wintips.org/view-installed-apps-and-packages-in-windows-10-8-1-8-from-powershell/
func ParseWindowsAppxPackages(platform *inventory.Platform, input io.Reader) ([]Package, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	var appxPackages []winAppxPackages

	// handle case where no packages are installed
	if len(data) == 0 {
		return []Package{}, nil
	}

	err = json.Unmarshal(data, &appxPackages)
	if err != nil {
		return nil, err
	}

	pkgs := make([]Package, 0, len(appxPackages))
	for _, p := range appxPackages {
		if p.Name == "" {
			continue
		}
		pkgs = append(pkgs, p.toPackage(platform))
	}
	return pkgs, nil
}

type PowershellWinHotFix struct {
	Status      string `json:"Status"`
	Description string `json:"Description"`
	HotFixId    string `json:"HotFixId"`
	Caption     string `json:"Caption"`
	InstalledOn struct {
		Value    string `json:"value"`
		DateTime string `json:"DateTime"`
	} `json:"InstalledOn"`
	InstalledBy string `json:"InstalledBy"`
}

func (hf PowershellWinHotFix) InstalledOnTime() *time.Time {
	return powershell.PSJsonTimestamp(hf.InstalledOn.Value)
}

func ParseWindowsHotfixes(input io.Reader) ([]PowershellWinHotFix, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	// for empty result set do not get the '{}', therefore lets abort here
	if len(data) == 0 {
		return []PowershellWinHotFix{}, nil
	}

	var powershellWinHotFixPkgs []PowershellWinHotFix
	err = json.Unmarshal(data, &powershellWinHotFixPkgs)
	if err != nil {
		return nil, err
	}

	return powershellWinHotFixPkgs, nil
}

// psLongDateLayouts are the shapes ConvertTo-Json writes into InstalledOn.DateTime.
// Windows PowerShell 5.1 renders the invariant/en-US long date; PowerShell 7
// serializes DateTime as ISO-8601 instead. On a localized host neither matches
// (German renders "Mittwoch, 12. August 2026 00:00:00"), which is why the
// caller falls back rather than treating a parse failure as an error.
var psLongDateLayouts = []string{
	"Monday, January 2, 2006 3:04:05 PM",
	"Monday, 02 January 2006 15:04:05",
	time.RFC3339,
}

// installedOnDate returns the calendar day Get-HotFix reports for this entry, at
// UTC midnight — the same shape parseWinInstallDate produces for the registry
// path, so both Windows package sources agree.
//
// Why this is not just InstalledOnTime(): Win32_QuickFixEngineering's InstalledOn
// is a DATE, which Get-HotFix renders at the host's LOCAL midnight, and
// ConvertTo-Json then serializes as an epoch-UTC instant. Publishing that instant
// makes every host at a positive UTC offset report the previous day — a hotfix
// Windows itself reports installed on the 9th reads as the 8th from Berlin
// (22:00Z) or Tokyo (15:00Z). Fixtures captured on UTC boxes cannot show this,
// because there local midnight and UTC midnight are the same instant.
//
// Recovering a local calendar day from an instant needs the host's UTC offset,
// which is not in the payload, so this reads it from the two places it does
// appear, in order of how explicit they are:
//
//  1. InstalledOn.DateTime, which is the local rendering. Authoritative when the
//     host's locale is one we can parse.
//  2. The epoch instant, when it sits exactly on a real UTC-offset boundary away
//     from a midnight (whole hours, or the :30/:45 offsets India, Nepal, the
//     Chathams and others use). "Exactly" is what keeps this from mangling a
//     genuine timestamp: an afternoon install at 14:37 local has minutes nobody's
//     offset can explain, so it is left alone rather than rounded into the next
//     day.
//
// Anything else keeps the raw instant. Offsets beyond ±12h (UTC+13/+14) on a
// locale we cannot parse still read one day early; recovering those needs the
// host's timezone, which this payload does not carry.
func (hf PowershellWinHotFix) installedOnDate() time.Time {
	if hf.InstalledOn.DateTime != "" {
		for _, layout := range psLongDateLayouts {
			if t, err := time.Parse(layout, hf.InstalledOn.DateTime); err == nil {
				return utcMidnight(t)
			}
		}
	}

	t := hf.InstalledOnTime()
	if t == nil {
		// No InstalledOn, or a value PSJsonTimestamp could not read. The zero
		// time is what fillPackageArgs turns into a real MQL null, so the
		// consumer sees "unknown" rather than a fabricated date.
		return time.Time{}
	}
	// A non-positive epoch is a sentinel, not a date: /Date(0)/ would otherwise
	// publish 1970-01-01, and llx renders any time with Unix() <= 0 as a duration
	// string rather than a timestamp. rpm_packages.go guards the same way.
	if t.Unix() <= 0 {
		return time.Time{}
	}

	utc := t.UTC()
	if offset, ok := offsetFromMidnight(utc); ok {
		return utcMidnight(utc.Add(offset))
	}
	return utc
}

// utcMidnight keeps only the calendar day of t, at 00:00 UTC.
func utcMidnight(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// offsetFromMidnight reports the UTC offset that would put t at a local midnight,
// if t sits exactly on a boundary a real timezone uses. Sub-minute components or
// minutes outside {0, 30, 45} mean t carries a time of day rather than a date, so
// no offset is claimed.
func offsetFromMidnight(t time.Time) (time.Duration, bool) {
	if t.Second() != 0 || t.Nanosecond() != 0 {
		return 0, false
	}
	switch t.Minute() {
	case 0, 30, 45:
	default:
		return 0, false
	}
	sinceMidnight := time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute
	if sinceMidnight == 0 {
		return 0, true // already a UTC midnight
	}
	// Ahead of UTC: local midnight serialized to the PREVIOUS UTC day, so the
	// day rolls forward. Behind UTC: it serialized later the same UTC day.
	if forward := 24*time.Hour - sinceMidnight; forward <= 12*time.Hour {
		return forward, true
	}
	if sinceMidnight <= 12*time.Hour {
		return 0, true // same UTC calendar day already
	}
	return 0, false
}

func HotFixesToPackages(hotfixes []PowershellWinHotFix) []Package {
	pkgs := make([]Package, len(hotfixes))
	for i := range hotfixes {
		// Defense-in-depth — Get-HotFix's Description is typically a short
		// string like "Update" / "Security Update", but it comes through the
		// same PowerShell→JSON path as the registry packages, so apply the
		// same sanitization so a stray control character can't corrupt the
		// downstream SBOM projection.
		pkg := Package{
			Name:        sanitizePackageField(hotfixes[i].HotFixId),
			Description: sanitizePackageField(hotfixes[i].Description),
			Format:      "windows/hotfix",
			// A hotfix has no per-user concept: Get-HotFix reports it once for
			// the whole machine, like appx. Leaving this empty would break the
			// .lr contract that empty installScope means "no such concept" —
			// every other Windows package source now sets it.
			InstallScope: installScopeMachine,
		}
		pkg.InstallDate = hotfixes[i].installedOnDate()
		pkgs[i] = pkg
	}
	return pkgs
}

type WinPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform

	// injectedHotfixes, when non-nil, is Get-HotFix's already-parsed outcome
	// handed down by the resource layer (packages.go's list(), via
	// SetHotfixes below), which reads it off windows.hotfixes's own MQL
	// field cache. List() uses it instead of running Get-HotFix itself, so
	// the query executes once per scan rather than twice when both
	// packages.list and windows.hotfixes are resolved on the same
	// connection. Left nil (the zero value, and always the case outside the
	// resource layer, e.g. in tests that construct a WinPkgManager
	// directly), List() behaves exactly as it always has: a fresh, lenient
	// Get-HotFix run of its own.
	//
	// A pointer to the slice, not the slice itself, so an injected EMPTY
	// result (a host with genuinely no hotfixes) is distinguishable from
	// "nothing was injected."
	injectedHotfixes *[]PowershellWinHotFix
}

// SetHotfixes injects Get-HotFix's already-parsed outcome, so List() reuses
// it instead of running Get-HotFix itself. See injectedHotfixes.
func (w *WinPkgManager) SetHotfixes(hotfixes []PowershellWinHotFix) {
	w.injectedHotfixes = &hotfixes
}

func (w *WinPkgManager) Name() string {
	return "Windows Package Manager"
}

func (w *WinPkgManager) Format() string {
	return "win"
}

func (w *WinPkgManager) getLocalInstalledApps() ([]Package, error) {
	callingSid := currentUserSID()

	pkgs := []string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"HKCU\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
	}
	packages := []Package{}
	for _, r := range pkgs {
		arch := archForRegistryPath(r, w.platform.Arch)
		scope, user := installScopeForRegistryPath(r, callingSid)
		view := registryView(r)
		children, err := registry.GetNativeRegistryKeyChildren(r)
		if err != nil {
			continue
		}
		for _, c := range children {
			p, uninstallString, err := getPackageFromRegistryKey(c, w.platform, arch)
			if err != nil {
				return nil, err
			}
			if p == nil {
				continue
			}
			p.InstallScope = scope
			p.InstallUser = user
			p.regDedupKey = registryDedupKey(view, uninstallString, c.Name)
			packages = append(packages, *p)
		}
	}

	// Every other user's profile: the HKCU read above only ever reflects the
	// identity running the scan, so an unattended/SYSTEM scan never sees
	// software a user installed into their own profile
	// (%LOCALAPPDATA%\Programs installers such as VS Code's per-user setup,
	// Cursor, Postman, GitHub Desktop) without this. callingSid is skipped
	// here since its Uninstall entries were already read above via HKCU.
	packages = append(packages, w.getPerProfileInstalledApps(callingSid)...)

	// Collapse duplicate reads of the very same physical registry key. This
	// matters even when callingSid resolved fine (a Wow6432Node vs native
	// pair are always two separate loop iterations above), but it is the
	// ONLY safety net when it didn't: an empty callingSid (osuser.Current
	// failed) is never equal to any real profile SID, so the skip in
	// getPerProfileInstalledApps above does not fire, and the calling
	// user's own live hive gets read a second time here via
	// HKEY_USERS\<realSid> -- the same key HKCU already read above, just
	// under a root that knows the concrete SID HKCU could not attribute.
	packages = mergeDedupedRegistryPackages(packages)

	// Google Update (Omaha) tracks the authoritative version for the
	// products it manages (Chrome, Drive, Earth, GCPW, ...) independently of
	// Add/Remove Programs, whose DisplayVersion can go stale. See
	// applyOmahaVersions.
	omahaVersions := buildOmahaVersions(omahaClientsNativeRoots, registry.GetNativeRegistryKeyChildren, registry.GetNativeRegistryKeyItems)
	applyOmahaVersions(packages, omahaVersions, w.platform)

	applyM365ChannelQualifier(packages, w.platform, w.m365ChannelFromNativeRegistry)

	// These are the .NET Framework packages
	// They do not show up in the general apps or features list, so we need to discover them separately
	dotNetFramework, err := w.getDotNetFramework()
	if err != nil {
		log.Debug().Err(err).Msg("could not get .NET Framework packages from registry")
	} else {
		packages = append(packages, dotNetFramework...)
	}
	return packages, nil
}

// currentUserSID returns the SID of the identity running this process. On
// Windows, os/user.User.Uid IS the SID (there is no separate numeric uid), so
// this is how getLocalInstalledApps attributes its HKCU read to a specific
// user and how it excludes that same user's profile from the per-profile
// enumeration below (their entries were already read via HKCU). Returns ""
// on any error rather than failing the scan over an attribution detail.
func currentUserSID() string {
	u, err := osuser.Current()
	if err != nil {
		log.Debug().Err(err).Msg("could not determine current user SID")
		return ""
	}
	return u.Uid
}

// wellKnownSystemSIDs are service accounts and the profile template whose
// registry hives are never a signal for user-installed software: LocalSystem,
// LocalService, NetworkService, and the ".DEFAULT" hive new profiles are
// copied from.
var wellKnownSystemSIDs = map[string]struct{}{
	"S-1-5-18": {},
	"S-1-5-19": {},
	"S-1-5-20": {},
	".DEFAULT": {},
}

// isWellKnownSystemSID matches case-insensitively: numeric SIDs have no case,
// but the ".DEFAULT" template hive has been observed as ".Default" in some
// registry listings.
func isWellKnownSystemSID(sid string) bool {
	_, ok := wellKnownSystemSIDs[strings.ToUpper(sid)]
	return ok
}

// profileListPath is where Windows records every user profile on the host,
// keyed by SID.
const profileListPath = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// validSIDPattern matches a well-formed Windows SID: "S-1-" followed by two or
// more dash-separated numeric components. Windows leaves a "<sid>.bak"
// subkey under ProfileList after a temp-profile event (the profile service
// renames the original key aside while it repairs a corrupted one), and that
// suffix would otherwise be treated as part of the SID and handed to `reg
// load` as a target, which fails or — worse — targets the wrong hive. Every
// real SID this code ever compares against (S-1-5-18/19/20, a profile's own
// SID) matches this shape; a ".bak" or any other decorated subkey name does
// not.
var validSIDPattern = regexp.MustCompile(`^S-1-\d+(-\d+)+$`)

func isValidSID(sid string) bool {
	return validSIDPattern.MatchString(sid)
}

// windowsProfile is one entry under profileListPath: a user's SID and the
// on-disk path their profile (and NTUSER.DAT) live at.
type windowsProfile struct {
	SID  string
	Path string
}

// nativeRegistryReader is the subset of the registry package's native Windows
// registry API used to enumerate profiles and read a live per-user hive. It
// exists so that logic can be unit-tested with a fake: the real
// implementation only does anything useful on a Windows build, and even there
// requires a live registry to read from.
type nativeRegistryReader interface {
	Children(path string) ([]registry.RegistryKeyChild, error)
	Items(path string) ([]registry.RegistryKeyItem, error)
	IsUserHiveLoaded(sid string) bool
}

// defaultNativeRegistryReader delegates to the registry package's native
// Windows registry API.
type defaultNativeRegistryReader struct{}

func (defaultNativeRegistryReader) Children(path string) ([]registry.RegistryKeyChild, error) {
	return registry.GetNativeRegistryKeyChildren(path)
}

func (defaultNativeRegistryReader) Items(path string) ([]registry.RegistryKeyItem, error) {
	return registry.GetNativeRegistryKeyItems(path)
}

func (defaultNativeRegistryReader) IsUserHiveLoaded(sid string) bool {
	return registry.IsUserHiveLoaded(sid)
}

// userHiveHandler is the subset of *registry.RegistryHandler used to load and
// read one profile's NTUSER.DAT hive: LoadUserHive, the two hive readers, and
// UnloadSubkeys to release it again. Abstracted (rather than used directly)
// so getProfileInstalledApps' loaded-hive branch can be unit-tested with a
// fake: the real RegistryHandler only does anything on a Windows build (see
// registry/registryhandler_unix.go), so without this seam that branch could
// never execute in CI.
type userHiveHandler interface {
	LoadUserHive(sid, filepath string) error
	GetUserHiveKeyChildren(sid, path string) ([]registry.RegistryKeyChild, error)
	GetUserHiveKeyItems(sid, path string) ([]registry.RegistryKeyItem, error)
	UnloadSubkeys() error
}

// newDefaultUserHiveHandler creates a fresh, function-scoped RegistryHandler
// for a single profile read. Deliberately NOT the connection-scoped handler
// registrykey.go shares across a whole scan (UserHiveRegistryHandler, kept
// loaded until the connection closes): loading a logged-off user's NTUSER.DAT
// takes an exclusive lock on that file for as long as it stays mounted, and a
// scan can walk hundreds of stale profiles on a terminal server. Holding all
// of them for the scan's duration blocks that user from logging back on (they
// get a temporary profile instead). getProfileInstalledApps only needs two
// key reads per profile, so it loads through a handler of its own and unloads
// immediately after — the same pattern getFsInstalledApps already uses for
// the offline SOFTWARE hive.
func newDefaultUserHiveHandler() userHiveHandler {
	return registry.NewRegistryHandler()
}

// expandWindowsEnvPercent expands "%VAR%"-style Windows environment
// references. ProfileImagePath is stored as REG_EXPAND_SZ (e.g.
// "%SystemDrive%\Users\alice"), and the registry API here returns its raw,
// unexpanded string — expansion is left to whoever consumes an
// REG_EXPAND_SZ value. Left unexpanded, "%SystemDrive%\Users\alice\NTUSER.DAT"
// is not a valid path, `reg load` fails on it, and the whole profile is
// silently skipped (getProfileInstalledApps treats a load failure as
// skip-with-debug-log, not a scan failure). Safe to call on a plain SZ value
// too: a string with no "%...%" token passes through unchanged.
func expandWindowsEnvPercent(s string) string {
	return os.ExpandEnv(winEnvPercentPattern.ReplaceAllString(s, "${$1}"))
}

var winEnvPercentPattern = regexp.MustCompile(`%([^%]+)%`)

// listWindowsProfiles enumerates every user profile Windows knows about,
// skipping the well-known service SIDs and the .DEFAULT template hive: none
// of them represent a real user who could have installed software into their
// own profile. A subkey whose name is not a well-formed SID — most commonly a
// "<sid>.bak" leftover from a temp-profile repair — is skipped too, rather
// than stripped and used: `reg load` on a mis-parsed path fails or targets the
// wrong hive. A profile with no recorded ProfileImagePath is skipped as well,
// since there is nothing to enumerate or load a hive from.
//
// LOCAL-NATIVE ONLY. ProfileImagePath is REG_EXPAND_SZ and is expanded against
// this process's environment (expandWindowsEnvPercent), which is correct only
// because the process runs on the scanned host. The remote PowerShell path
// enumerates profiles inside the script, and the offline filesystem path reads
// the machine hive only; neither must be routed through here without resolving
// %SystemDrive% and friends from the target instead.
func listWindowsProfiles(reader nativeRegistryReader) []windowsProfile {
	children, err := reader.Children(profileListPath)
	if err != nil {
		log.Debug().Err(err).Msg("could not enumerate Windows user profiles")
		return nil
	}

	profiles := make([]windowsProfile, 0, len(children))
	for _, c := range children {
		sid := c.Name
		if isWellKnownSystemSID(sid) {
			continue
		}
		if !isValidSID(sid) {
			log.Debug().Str("sid", sid).Msg("skipping ProfileList entry whose name is not a valid SID")
			continue
		}
		items, err := reader.Items(c.Path + "\\" + c.Name)
		if err != nil {
			log.Debug().Err(err).Str("sid", sid).Msg("could not read Windows profile registry entry")
			continue
		}
		path := ""
		for _, i := range items {
			if i.Key == "ProfileImagePath" {
				path = expandWindowsEnvPercent(i.Value.String)
			}
		}
		if path == "" {
			continue
		}
		profiles = append(profiles, windowsProfile{SID: sid, Path: path})
	}
	return profiles
}

// getPerProfileInstalledApps enumerates the Uninstall entries under every
// other user's registry hive: the live HKEY_USERS\<sid> hive for a user with
// an active logon session, or NTUSER.DAT loaded on demand (through a
// function-scoped userHiveHandler, see newDefaultUserHiveHandler) for one who
// is not. This is the only way an unattended/SYSTEM scan sees software a user
// installed into their own profile, since HKCU always reflects the scanning
// identity rather than the asset's actual users.
//
// skipSid excludes one SID from enumeration: the calling identity's own
// profile, whose Uninstall entries the HKCU read in getLocalInstalledApps
// already reported. A profile whose hive cannot be read (locked, missing
// NTUSER.DAT) is skipped with a debug log, never a failure.
func (w *WinPkgManager) getPerProfileInstalledApps(skipSid string) []Package {
	return w.getPerProfileInstalledAppsWith(skipSid, defaultNativeRegistryReader{}, newDefaultUserHiveHandler)
}

func (w *WinPkgManager) getPerProfileInstalledAppsWith(skipSid string, reader nativeRegistryReader, newHiveHandler func() userHiveHandler) []Package {
	packages := []Package{}
	for _, p := range listWindowsProfiles(reader) {
		if p.SID == skipSid {
			continue
		}
		pkgs, err := w.getProfileInstalledApps(p, reader, newHiveHandler)
		if err != nil {
			log.Debug().Err(err).Str("sid", p.SID).Msg("could not read installed apps from user profile")
			continue
		}
		packages = append(packages, pkgs...)
	}
	return packages
}

// getProfileInstalledApps reads the Uninstall keys (and their Wow6432Node
// sibling) from one user's registry hive: directly under HKEY_USERS\<sid> if
// the user is logged in, otherwise from NTUSER.DAT loaded on demand through a
// handler newHiveHandler creates for this call alone. That handler's hive is
// unloaded (deferred) as soon as this function's two key reads are done,
// never held for the rest of the scan — see newDefaultUserHiveHandler for why
// that matters at fleet/terminal-server scale.
//
// Scope and user are derived through installScopeForRegistryPath, the same
// function the direct HKLM/HKCU reads in getLocalInstalledApps use, rather
// than hardcoded here, so there is one place that decides what a registry
// root means for install scope.
func (w *WinPkgManager) getProfileInstalledApps(p windowsProfile, reader nativeRegistryReader, newHiveHandler func() userHiveHandler) ([]Package, error) {
	subpaths := []string{
		`Software\Microsoft\Windows\CurrentVersion\Uninstall`,
		`Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	live := reader.IsUserHiveLoaded(p.SID)
	var rh userHiveHandler
	if !live {
		if p.Path == "" {
			// No live session and no on-disk profile path to load NTUSER.DAT
			// from. Not a failure, just nothing more we can do for this
			// profile.
			return nil, nil
		}
		ntuserDat := strings.TrimRight(p.Path, `\`) + `\NTUSER.DAT`
		rh = newHiveHandler()
		defer func() {
			if err := rh.UnloadSubkeys(); err != nil {
				log.Debug().Err(err).Str("sid", p.SID).Msg("could not unload user registry hive")
			}
		}()
		if err := rh.LoadUserHive(p.SID, ntuserDat); err != nil {
			return nil, err
		}
	}

	packages := []Package{}
	for _, sp := range subpaths {
		arch := archForRegistryPath(sp, w.platform.Arch)
		hivePath := `HKEY_USERS\` + p.SID + `\` + sp
		scope, user := installScopeForRegistryPath(hivePath, "")
		view := registryView(sp)

		var children []registry.RegistryKeyChild
		var err error
		if live {
			children, err = reader.Children(hivePath)
		} else {
			children, err = rh.GetUserHiveKeyChildren(p.SID, sp)
		}
		if err != nil {
			continue
		}
		for _, c := range children {
			var items []registry.RegistryKeyItem
			var itemsErr error
			if live {
				items, itemsErr = reader.Items(c.Path + "\\" + c.Name)
			} else {
				items, itemsErr = rh.GetUserHiveKeyItems(p.SID, sp+`\`+c.Name)
			}
			if itemsErr != nil {
				log.Debug().Err(itemsErr).Str("path", c.Path).Msg("could not read registry key children")
				continue
			}
			pkg, uninstallString := getPackageFromRegistryKeyItems(items, w.platform, arch)
			if pkg == nil {
				continue
			}
			pkg.InstallScope = scope
			pkg.InstallUser = user
			pkg.regDedupKey = registryDedupKey(view, uninstallString, c.Name)
			packages = append(packages, *pkg)
		}
	}
	return packages, nil
}

// getDotNetFramework returns the installed .NET Framework runtime packages.
//
// .NET Framework 3.5 (CLR 2.0) and 4.x (CLR 4.0) install side-by-side, so we
// probe both registry keys independently and emit a package for each runtime
// that is present, rather than letting the highest version hide the other.
//
// Registry and version probes run over the active connection via PowerShell, so
// this works for remote connections (e.g. SSH) as well as a local Windows host.
//
// This is called from exactly one enumeration path per connection type
// (getLocalInstalledApps for a local Windows host, getInstalledApps for remote
// connections), so the returned packages are not duplicated.
func (w *WinPkgManager) getDotNetFramework() ([]Package, error) {
	packages := []Package{}

	// Both probes read a single machine-wide HKLM key (NDP\v4\Full,
	// NDP\v3.5); neither has a per-user concept. Tagged here, once, rather
	// than in each probe, so the two stay in sync automatically.
	if pkg, err := w.getDotNetFramework4x(); err != nil {
		log.Debug().Err(err).Msg("could not get .NET Framework 4.x runtime")
	} else if pkg != nil {
		pkg.InstallScope = installScopeMachine
		packages = append(packages, *pkg)
	}

	if pkg, err := w.getDotNetFramework35(); err != nil {
		log.Debug().Err(err).Msg("could not get .NET Framework 3.5 runtime")
	} else if pkg != nil {
		pkg.InstallScope = installScopeMachine
		packages = append(packages, *pkg)
	}

	if len(packages) == 0 {
		return nil, nil
	}
	return packages, nil
}

// getDotNetFramework4x reports the installed .NET Framework 4.x runtime, sourcing
// its build from clr.dll (the CLR 4.x runtime) under the registered install path.
func (w *WinPkgManager) getDotNetFramework4x() (*Package, error) {
	// https://learn.microsoft.com/en-us/dotnet/framework/install/how-to-determine-which-versions-are-installed#net-framework-45-and-later-versions
	const dotNet45plus = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full"

	items, err := w.readRegistryItems(dotNet45plus)
	if err != nil {
		return nil, fmt.Errorf("could not read registry key %q: %w", dotNet45plus, err)
	}

	installLocation := ""
	for _, i := range items {
		if i.Key == "InstallPath" {
			installLocation = i.Value.String
		}
	}
	if installLocation == "" {
		return nil, nil
	}

	dotNetRuntimeScript := fmt.Sprintf(dotNetClrVersionScript, installLocation)
	version, err := w.runPwshVersion(dotNetRuntimeScript)
	if err != nil {
		return nil, err
	}
	if version == "" {
		return nil, nil
	}

	return createPackage("Microsoft .NET Framework", version, "windows/app", w.platform.Arch, "Microsoft", installLocation, w.platform), nil
}

// getDotNetFramework35 reports the installed .NET Framework 3.5 runtime. It is
// detected independently of 4.x (they run side-by-side) via the NDP\v3.5 key,
// and its build is sourced from the CLR 2.0 assemblies rather than clr.dll,
// which does not exist for CLR 2.0.
func (w *WinPkgManager) getDotNetFramework35() (*Package, error) {
	// https://learn.microsoft.com/en-us/dotnet/framework/install/how-to-determine-which-versions-are-installed#use-registry-editor-older-framework-versions
	const dotNet35 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5"

	items, err := w.readRegistryItems(dotNet35)
	if err != nil {
		return nil, fmt.Errorf("could not read registry key %q: %w", dotNet35, err)
	}

	installed := false
	installLocation := ""
	for _, i := range items {
		switch i.Key {
		case "Install":
			installed = i.Value.Number == 1
		case "InstallPath":
			installLocation = i.Value.String
		}
	}
	if !installed {
		return nil, nil
	}

	version, err := w.runPwshVersion(dotNetClr2VersionScript)
	if err != nil {
		return nil, err
	}
	if version == "" {
		return nil, nil
	}

	return createPackage("Microsoft .NET Framework", version, "windows/app", w.platform.Arch, "Microsoft", installLocation, w.platform), nil
}

// runPwshVersion runs a PowerShell script that emits a single version string and
// returns its trimmed, single-line result.
func (w *WinPkgManager) runPwshVersion(script string) (string, error) {
	cmd, err := w.conn.RunCommand(powershell.Encode(script))
	if err != nil {
		return "", fmt.Errorf("could not run powershell command")
	}

	if cmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(cmd.Stderr)
		if err != nil {
			return "", err
		}
		return "", errors.New("failed to retrieve .NET Framework version: " + string(stderr))
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	// for empty result set do not get the '{}', therefore lets abort here
	if len(data) == 0 {
		return "", nil
	}
	version := strings.TrimSpace(string(data))
	version = strings.ReplaceAll(version, "\n", "")
	version = strings.ReplaceAll(version, "\r", "")
	return version, nil
}

// readRegistryItems reads the values of a single registry key over the active
// connection. It probes via PowerShell (rather than the Windows-only native
// registry API) so it works for remote connections such as SSH as well as a
// local Windows host. A missing key makes the probe exit non-zero, which is
// reported as an empty result rather than an error.
func (w *WinPkgManager) readRegistryItems(path string) ([]registry.RegistryKeyItem, error) {
	cmd, err := w.conn.RunCommand(powershell.Encode(registry.GetRegistryKeyItemScript(path)))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, nil
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, nil
	}
	return registry.ParsePowershellRegistryKeyItems(strings.NewReader(string(data)))
}

func (w *WinPkgManager) getInstalledApps() ([]Package, error) {
	if w.conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		return w.getLocalInstalledApps()
	}

	if w.conn.Type() == shared.Type_FileSystem || w.conn.Type() == shared.Type_Device {
		return w.getFsInstalledApps()
	}

	cmd, err := w.conn.RunCommand(powershell.Encode(installedAppsScript))
	if err != nil {
		return nil, fmt.Errorf("could not read app package list")
	}

	if cmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(cmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve installed apps: " + string(stderr))
	}

	packages, err := ParseWindowsAppPackages(w.platform, cmd.Stdout)
	if err != nil {
		return nil, err
	}

	// Google Update (Omaha) tracks the authoritative version for the
	// products it manages independently of Add/Remove Programs. See
	// applyOmahaVersions. A read failure here is logged and skipped rather
	// than failing the whole scan, the same policy readRegistryItems and
	// getDotNetFramework use for an optional, best-effort registry probe.
	if omahaVersions, err := w.getOmahaVersionsRemote(); err != nil {
		log.Debug().Err(err).Msg("could not read Google Update (Omaha) product versions")
	} else {
		applyOmahaVersions(packages, omahaVersions, w.platform)
	}

	applyM365ChannelQualifier(packages, w.platform, w.m365ChannelFromPowershell)

	// The .NET Framework runtimes don't appear in the Uninstall registry keys,
	// so we discover them separately here as well (the local path does the same
	// in getLocalInstalledApps).
	dotNetFramework, err := w.getDotNetFramework()
	if err != nil {
		log.Debug().Err(err).Msg("could not get .NET Framework packages from registry")
	} else {
		packages = append(packages, dotNetFramework...)
	}

	return packages, nil
}

func (w *WinPkgManager) getAppxPackages() ([]Package, error) {
	canRunCmd := w.conn.Capabilities().Has(shared.Capability_RunCommand)
	// we always prefer to use the powershell command to get the appx packages, fallback to filesystem if not possible
	if !canRunCmd && (w.conn.Type() == shared.Type_FileSystem || w.conn.Type() == shared.Type_Device) {
		return w.getFsAppxPackages()
	}

	b, err := windows.Version(w.platform.Version)
	if err != nil {
		return nil, err
	}

	// only win 10+ are compatible with app x packages
	if b.Build > 10240 {
		return w.getPwshAppxPackages()
	}

	return []Package{}, nil
}

func (w *WinPkgManager) getPwshAppxPackages() ([]Package, error) {
	cmd, err := w.conn.RunCommand(powershell.Wrap(WINDOWS_QUERY_APPX_PACKAGES))
	if err != nil {
		return nil, fmt.Errorf("could not read appx package list")
	}
	return ParseWindowsAppxPackages(w.platform, cmd.Stdout)
}

func (w *WinPkgManager) getFsInstalledApps() ([]Package, error) {
	rh := registry.NewRegistryHandler()
	defer func() {
		err := rh.UnloadSubkeys()
		if err != nil {
			log.Debug().Err(err).Msg("could not unload registry subkeys")
		}
	}()
	fi, err := w.conn.FileInfo(registry.SoftwareRegPath)
	if err != nil {
		log.Debug().Err(err).Msg("could not find SOFTWARE registry key file")
		return nil, err
	}
	err = rh.LoadSubkey(registry.Software, fi.Path)
	if err != nil {
		log.Debug().Err(err).Msg("could not load SOFTWARE registry key file")
		return nil, err
	}
	pkgs := []string{
		"Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
	}
	packages := []Package{}
	for _, r := range pkgs {
		arch := archForRegistryPath(r, w.platform.Arch)
		children, err := rh.GetNativeRegistryKeyChildren(registry.Software, r)
		if err != nil {
			continue
		}
		for _, c := range children {
			p, _, err := getPackageFromRegistryKey(c, w.platform, arch)
			if err != nil {
				return nil, err
			}
			if p == nil {
				continue
			}
			// The offline/filesystem path only ever loads the machine
			// SOFTWARE hive (per-user hives live in each profile's own
			// NTUSER.DAT, which this path does not locate or load), so every
			// package it reports is unambiguously machine-scope.
			p.InstallScope = installScopeMachine
			packages = append(packages, *p)
		}
	}

	// Google Update (Omaha) tracks the authoritative version for the
	// products it manages independently of Add/Remove Programs. See
	// applyOmahaVersions. Read through the already-loaded SOFTWARE hive,
	// same as the Uninstall keys above.
	omahaVersions := buildOmahaVersions(omahaClientsOfflineSubpaths,
		func(p string) ([]registry.RegistryKeyChild, error) {
			return rh.GetNativeRegistryKeyChildren(registry.Software, p)
		},
		// The children come back carrying a FULLY-QUALIFIED Path -- the
		// handler resolved the hive root into it -- so the per-subkey read
		// must go through the package-level reader, NOT back through the
		// handler, which would resolve the root onto it a second time and
		// produce HKLM\TmpReg_SOFTWARE\HKLM\TmpReg_SOFTWARE\... Every read
		// would then miss, and buildOmahaVersions would silently return an
		// empty map on every offline scan. getPackageFromRegistryKey reads
		// the Uninstall subkeys the same way, for the same reason.
		registry.GetNativeRegistryKeyItems,
	)
	applyOmahaVersions(packages, omahaVersions, w.platform)

	applyM365ChannelQualifier(packages, w.platform, func() string {
		return w.m365ChannelFromHive(rh)
	})

	msSqlHotfixes := findMsSqlHotfixes(packages)
	if len(msSqlHotfixes) > 0 {
		packages = updateMsSqlPackages(packages, msSqlHotfixes[len(msSqlHotfixes)-1])
	}

	return packages, nil
}

func (w *WinPkgManager) getFsAppxPackages() ([]Package, error) {
	if !w.conn.Capabilities().Has(shared.Capability_FindFile) {
		return nil, errors.New("find file is not supported for your platform")
	}
	fs := w.conn.FileSystem()
	fsSearch, ok := fs.(shared.FileSearch)
	if !ok {
		return nil, errors.New("find file is not supported for your platform")
	}

	paths := map[string]int{
		filepath.Join("Windows", "SystemApps"):        1,
		filepath.Join("Program Files", "WindowsApps"): 1,
		"Windows": 1,
	}
	appxPaths := map[string]struct{}{}
	for p, depth := range paths {
		res, err := fsSearch.Find(p, appxManifestPattern, "f", nil, &depth)
		if err != nil {
			continue
		}
		for _, r := range res {
			appxPaths[r] = struct{}{}
		}
	}
	log.Debug().Int("amount", len(appxPaths)).Msg("found appx manifest files")

	pkgs := []Package{}
	afs := &afero.Afero{Fs: fs}
	for p := range appxPaths {
		res, err := afs.ReadFile(p)
		if err != nil {
			log.Debug().Err(err).Str("path", p).Msg("could not read appx manifest")
			continue
		}
		winAppxPkg, err := parseAppxManifest(res)
		if err != nil {
			log.Debug().Err(err).Str("path", p).Msg("could not parse appx manifest")
			continue
		}
		if winAppxPkg.Name == "" {
			continue
		}
		pkg := winAppxPkg.toPackage(w.platform)
		pkgs = append(pkgs, pkg)

	}
	return pkgs, nil
}

func parseAppxManifest(input []byte) (winAppxPackages, error) {
	manifest := &AppxManifest{}
	err := xml.Unmarshal(input, manifest)
	if err != nil {
		return winAppxPackages{}, err
	}
	pkg := winAppxPackages{
		Name:      manifest.Identity.Name,
		Version:   manifest.Identity.Version,
		Publisher: manifest.Identity.Publisher,
		arch:      manifest.Identity.ProcessorArchitecture,
	}
	return pkg, nil
}

// getPackageFromRegistryKey reads one Uninstall subkey's values and returns
// the package it describes plus its raw UninstallString -- the second return
// is not part of the Package itself, only an ingredient callers combine with
// the registry view and key leaf into a dedup key (see registryDedupKey) for
// mergeDedupedRegistryPackages.
func getPackageFromRegistryKey(key registry.RegistryKeyChild, platform *inventory.Platform, arch string) (*Package, string, error) {
	items, err := registry.GetNativeRegistryKeyItems(key.Path + "\\" + key.Name)
	if err != nil {
		log.Debug().Err(err).Str("path", key.Path).Msg("could not read registry key children")
		return nil, "", err
	}
	pkg, uninstallString := getPackageFromRegistryKeyItems(items, platform, arch)
	return pkg, uninstallString, nil
}

// getPackageFromRegistryKeyItems parses one Uninstall subkey's values into a
// package. The uninstallString return is the value that identifies the
// PHYSICAL registry entry (see getPackageFromRegistryKey); it is not stored
// on Package since it is not itself something a consumer queries, only a
// dedup ingredient.
func getPackageFromRegistryKeyItems(children []registry.RegistryKeyItem, platform *inventory.Platform, arch string) (*Package, string) {
	var uninstallString string
	var displayName string
	var displayVersion string
	var publisher string
	var installLocation string

	for _, i := range children {
		switch i.Key {
		case "UninstallString":
			uninstallString = i.Value.String
		case "DisplayName":
			displayName = i.Value.String
		case "DisplayVersion":
			displayVersion = i.Value.String
		case "Publisher":
			publisher = i.Value.String
		case "InstallLocation":
			installLocation = i.Value.String
		}
	}

	if uninstallString == "" {
		return nil, ""
	}

	// TODO: We need to figure out why we have empty displayNames.
	// this is common in windows but we need to verify it is a windows
	// issue and not an mql issue.
	if displayName == "" {
		log.Debug().Msg("ignored package since display name is missing")
		return nil, ""
	}

	// For shared registry paths (like HKCU) where WOW64 redirection doesn't apply,
	// fall back to checking install paths for "Program Files (x86)".
	if arch == platform.Arch {
		if detected := archFromInstallPath(installLocation, uninstallString); detected != "" {
			arch = detected
		}
	}

	pkg := createPackage(displayName, displayVersion, "windows/app", arch, publisher, installLocation, platform)

	return pkg, uninstallString
}

// archForRegistryPath returns "x86" for Wow6432Node registry paths (32-bit apps on 64-bit Windows),
// or the platform architecture for regular paths.
func archForRegistryPath(path string, platformArch string) string {
	if strings.Contains(path, "Wow6432Node") {
		return "x86"
	}
	return platformArch
}

// registryView returns "wow6432" for a path under the Wow6432Node
// redirection, "native" otherwise. The two views hold genuinely different
// physical registry keys even for the same product code -- a burn-bundle
// entry under Wow6432Node and its companion MSI entry under the native key
// (see normalizeDotNetPackedVersion) -- so a dedup key that folds them
// together loses one of the two rows. Independent of registry ROOT (HKLM vs
// HKCU vs HKEY_USERS<sid>): the same product installed per-machine and
// per-user still keeps separate wow/native identities.
func registryView(path string) string {
	if strings.Contains(path, "Wow6432Node") {
		return "wow6432"
	}
	return "native"
}

// registryDedupKey identifies the physical Windows registry key a package was
// read from: its view (native vs Wow6432Node), its UninstallString, and the
// Uninstall subkey's own leaf name (a product GUID or app-chosen string).
// Deliberately root-agnostic (HKCU and its HKEY_USERS\<sid> twin, or a bare
// key path and its PSPath rendering, produce the SAME key) and deliberately
// excludes install scope/user: those two describe WHO can see the entry, not
// WHICH physical entry it is, and folding them in is what let a SID lookup
// failure double-report the same key under two different (scope, user)
// pairs. See mergeDedupedRegistryPackages and ParseWindowsAppPackages' own
// (PSPath-based) equivalent for the remote path.
func registryDedupKey(view, uninstallString, leaf string) string {
	return view + "|" + uninstallString + "|" + leaf
}

// mergeDedupedRegistryPackages collapses packages that share a
// registryDedupKey: the exact same physical registry key read twice through
// different roots, most commonly the calling user's own live hive read once
// via HKCU and a second time via its HKEY_USERS\<sid> twin (this happens
// whenever osuser.Current fails, since an empty callingSid never matches a
// real profile SID and so is never skipped from per-profile enumeration).
// When two entries collide, the one carrying a concrete InstallUser wins over
// one with an empty user, since the empty one is exactly the attribution
// failure this is compensating for. A package with no dedup key (offline
// path, appx, .NET Framework, hotfixes -- none of which have a registry-key
// identity in this sense) is never merged. Order of first appearance is
// preserved.
func mergeDedupedRegistryPackages(pkgs []Package) []Package {
	out := make([]Package, 0, len(pkgs))
	seen := map[string]int{}
	for _, p := range pkgs {
		if p.regDedupKey == "" {
			out = append(out, p)
			continue
		}
		if idx, dup := seen[p.regDedupKey]; dup {
			if out[idx].InstallUser == "" && p.InstallUser != "" {
				out[idx] = p
			}
			continue
		}
		seen[p.regDedupKey] = len(out)
		out = append(out, p)
	}
	return out
}

// hkeyUsersSidPattern captures the SID segment of a path of the form
// "HKEY_USERS\<sid>\...", the shape a live per-user hive read uses.
var hkeyUsersSidPattern = regexp.MustCompile(`(?i)HKEY_USERS\\([^\\]+)`)

// sidFromHiveUsersPath extracts the SID a HKEY_USERS\<sid>\... path carries.
// Returns "" for a path with no such segment.
func sidFromHiveUsersPath(path string) string {
	m := hkeyUsersSidPattern.FindStringSubmatch(path)
	if m == nil {
		return ""
	}
	return m[1]
}

// installScopeForRegistryPath derives a package's install scope from the
// registry root it was read under, mirroring how archForRegistryPath derives
// architecture: HKLM is machine-wide; HKCU and HKEY_USERS\<sid> are visible
// only to one user. For a bare HKCU root the SID is whoever is running the
// scan (callingSid, may be ""); for a HKEY_USERS\<sid> root the SID is read
// out of the path itself. Wow6432Node siblings of either root carry the same
// scope as their parent, since the suffix only affects architecture.
//
// A SID that turns out to be a well-known service account (S-1-5-18/19/20)
// is reported as machine scope with no user, in both branches. When cnquery
// runs as LocalSystem (an SCCM/Intune-pushed agent), HKCU IS S-1-5-18's own
// hive, not a real user's: entries there are software SYSTEM itself
// installed, not evidence of a per-user install nobody else can see.
// Reporting them as installScope=user/installUser=S-1-5-18 would be
// misleading in exactly the way this whole feature exists to avoid.
func installScopeForRegistryPath(path, callingSid string) (scope, user string) {
	if sid := sidFromHiveUsersPath(path); sid != "" {
		if isWellKnownSystemSID(sid) {
			return installScopeMachine, ""
		}
		return installScopeUser, sid
	}
	if strings.HasPrefix(path, "HKCU") || strings.Contains(path, "HKEY_CURRENT_USER") {
		if isWellKnownSystemSID(callingSid) {
			return installScopeMachine, ""
		}
		return installScopeUser, callingSid
	}
	return installScopeMachine, ""
}

// archFromInstallPath returns "x86" if any of the given paths contain "Program Files (x86)",
// indicating a 32-bit application. Returns empty string if architecture cannot be determined.
// The "Program Files (x86)" directory name is constant across all Windows language editions.
func archFromInstallPath(paths ...string) string {
	for _, p := range paths {
		if strings.Contains(p, "Program Files (x86)") {
			return "x86"
		}
	}
	return ""
}

// returns installed appx packages as well as hot fixes
func (w *WinPkgManager) List() ([]Package, error) {
	pkgs := []Package{}
	appPkgs, err := w.getInstalledApps()
	if err != nil {
		return nil, errors.Wrap(err, "could not read app package list")
	}
	// The .NET runtime installers write no InstallLocation, so their registry
	// entries arrive here with no files and reach the SBOM with no evidence
	// path at all. Recover the directory from the dotnet layout, confirmed on
	// the target before it is attached (windows_dotnet_paths.go).
	if w.conn.Capabilities().Has(shared.Capability_File) {
		fillDotNetInstallPaths(w.conn.FileSystem(), appPkgs)
	}
	pkgs = append(pkgs, appPkgs...)

	appxPackages, err := w.getAppxPackages()
	if err != nil {
		return nil, errors.Wrap(err, "could not read appx package list")
	}
	pkgs = append(pkgs, appxPackages...)

	canRunCmd := w.conn.Capabilities().Has(shared.Capability_RunCommand)
	if !canRunCmd {
		log.Debug().Msg("cannot run command on windows, skipping hotfixes list")
		// Collapse even on this early return: the .NET runtime's two
		// Add/Remove-Programs entries per install (see collapsePackages)
		// come from the app-listing path above, which ran regardless of
		// RunCommand capability.
		return collapsePackages(pkgs), nil
	}

	// hotfixes. When the resource layer already resolved windows.hotfixes on
	// this connection, it hands the outcome down via SetHotfixes (see
	// injectedHotfixes and packages.go's injectWindowsHotfixes), and that is
	// reused here instead of a second Get-HotFix run -- not cheap, a fresh
	// PowerShell process that walks the CBS package store. Absent an
	// injection, this runs its own query exactly as it always has: exit
	// status is deliberately ignored, since a single broken QFE entry that
	// makes PowerShell exit non-zero while still printing valid JSON must
	// not fail the whole package inventory (an empty or failed package list
	// closes vulnerability findings upstream). windows.hotfixes is strict
	// about exit status; this fallback path is not, and never has been.
	var hotfixes []PowershellWinHotFix
	if w.injectedHotfixes != nil {
		hotfixes = *w.injectedHotfixes
	} else {
		cmd, err := w.conn.RunCommand(powershell.Wrap(WINDOWS_QUERY_HOTFIXES))
		if err != nil {
			return nil, errors.Wrap(err, "could not fetch hotfixes")
		}
		hotfixes, err = ParseWindowsHotfixes(cmd.Stdout)
		if err != nil {
			return nil, errors.Wrapf(err, "could not parse hotfix results")
		}
	}
	hotfixAsPkgs := HotFixesToPackages(hotfixes)

	msSqlHotfixes := findMsSqlHotfixes(appPkgs)
	msSqlGdrPackages := findMsSqlGdrUpdates(appPkgs)
	// MS only allows GDR or Hotfixes/CU, no need to check which one takes precedence
	if len(msSqlGdrPackages) > 0 {
		pkgs = updateMsSqlPackages(pkgs, msSqlGdrPackages[len(msSqlGdrPackages)-1])
	}
	if len(msSqlHotfixes) > 0 {
		pkgs = updateMsSqlPackages(pkgs, msSqlHotfixes[len(msSqlHotfixes)-1])
	}

	exchangeCU := findExchangeCU(pkgs)
	if exchangeCU != nil {
		pkgs = updateExchangePackage(pkgs, *exchangeCU)
	}

	pkgs = append(pkgs, hotfixAsPkgs...)
	// Collapse rows that every version normalization above (.NET's
	// normalizeDotNetPackedVersion, Omaha's applyOmahaVersions) has made
	// indistinguishable. See collapsePackages.
	return collapsePackages(pkgs), nil
}

func ParseWindowsAppPackages(platform *inventory.Platform, input io.Reader) ([]Package, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	// for empty result set do not get the '{}', therefore lets abort here
	if len(data) == 0 {
		return []Package{}, nil
	}

	type powershellUninstallEntry struct {
		DisplayName     string `json:"DisplayName"`
		DisplayVersion  string `json:"DisplayVersion"`
		Publisher       string `json:"Publisher"`
		InstallSource   string `json:"InstallSource"`
		EstimatedSize   int    `json:"EstimatedSize"`
		UninstallString string `json:"UninstallString"`
		InstallLocation string `json:"InstallLocation"`
		// InstallDate is the YYYYMMDD value set by most MSI installers.
		// Many entries omit it (especially per-user installs and
		// non-MSI publishers) — parseWinInstallDate returns the zero
		// time in that case.
		InstallDate string `json:"InstallDate"`
		PSPath      string `json:"PSPath"`
		// InstallScope and InstallUser are computed by installedAppsScript
		// itself (see its doc comment), not derived from PSPath here.
		InstallScope string `json:"InstallScope"`
		InstallUser  string `json:"InstallUser"`
	}

	var entries []powershellUninstallEntry
	err = json.Unmarshal(data, &entries)
	if err != nil {
		return nil, err
	}

	pkgs := []Package{}
	// seen dedupes an entry that was read twice through two different registry
	// roots for the very same physical key -- most commonly the calling
	// identity's own profile, read once via the plain HKCU root and again,
	// when its hive happens to be live, via its HKEY_USERS\<sid> twin the
	// script also enumerates. Keyed on the PHYSICAL registry entry: registry
	// view (native vs Wow6432Node) + UninstallString (the value that actually
	// identifies a product's own uninstall record) + the Uninstall subkey's
	// own leaf name from PSPath -- root-agnostic and, deliberately, WITHOUT
	// InstallScope/InstallUser. Two DIFFERENT registry entries can legitimately
	// compute to the identical purl (a .NET runtime's burn-bundle entry and
	// its companion MSI entry both normalize to the same name, version and
	// arch -- see normalizeDotNetPackedVersion) or land under the same leaf in
	// two different views (an HKLM entry and its Wow6432Node sibling), so the
	// key must distinguish view and never fold on name/version/arch/purl
	// alone. Conversely, folding scope/user INTO the key under-merges: if
	// $callingSid is empty (WindowsIdentity lookup failed, swallowed by
	// installedAppsScript's try/catch), the HKCU entry (user="") and its
	// HKEY_USERS twin (user=<sid>) would never collide and every
	// caller-installed app would be reported twice. When two entries do
	// collide, the one with a concrete InstallUser is kept over one with an
	// empty user, so a successful SID resolution on either root wins.
	seen := map[string]int{}
	for i := range entries {
		entry := entries[i]
		if entry.UninstallString == "" {
			continue
		}

		// TODO: We need to figure out why we have empty displayNames.
		// this is common in windows but we need to verify it is a windows
		// issue and not an mql issue.
		if entry.DisplayName == "" {
			continue
		}

		arch := archForRegistryPath(entry.PSPath, platform.Arch)
		if arch == platform.Arch {
			if detected := archFromInstallPath(entry.InstallLocation, entry.UninstallString); detected != "" {
				arch = detected
			}
		}
		pkg := createPackage(entry.DisplayName, entry.DisplayVersion, "windows/app", arch, entry.Publisher, entry.InstallLocation, platform)
		pkg.InstallDate = parseWinInstallDate(entry.InstallDate)
		pkg.InstallScope = entry.InstallScope
		pkg.InstallUser = entry.InstallUser

		dedupKey := registryDedupKey(registryView(entry.PSPath), entry.UninstallString, registryPathLeaf(entry.PSPath))
		if idx, dup := seen[dedupKey]; dup {
			if pkgs[idx].InstallUser == "" && pkg.InstallUser != "" {
				pkgs[idx] = *pkg
			}
			continue
		}
		seen[dedupKey] = len(pkgs)
		pkgs = append(pkgs, *pkg)
	}

	return pkgs, nil
}

// registryPathLeaf returns the final path segment of a registry path or
// PSPath -- the Uninstall subkey's own name (typically a product GUID or an
// app-chosen string) -- which identifies the physical registry entry
// regardless of which root alias (HKCU:\, Registry::HKEY_USERS\<sid>\..., a
// PowerShell PSPath's "provider::" prefix) was used to read it.
func registryPathLeaf(path string) string {
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// parseWinInstallDate converts the YYYYMMDD string set by most MSI
// installers into a UTC time.Time at midnight. Returns the zero time on
// empty input or any parse failure — typical registry entries from
// per-user installs and many non-MSI publishers omit the field.
func parseWinInstallDate(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	// Standard MSI format is YYYYMMDD (8 digits).
	t, err := time.Parse("20060102", raw)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (win *WinPkgManager) Available() (map[string]PackageUpdate, error) {
	return map[string]PackageUpdate{}, nil
}

func (win *WinPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	// not yet implemented
	return nil, nil
}

// findMsSqlHotfixes returns a list of hotfixes that are related to Microsoft SQL Server
// The list is sorted by the hotfix id
func findMsSqlHotfixes(packages []Package) []Package {
	sqlHotfixes := []Package{}
	for _, p := range packages {
		if sqlHotfixRegExp.MatchString(p.Name) {
			sqlHotfixes = append(sqlHotfixes, p)
		}
	}
	slices.SortFunc(sqlHotfixes, func(a, b Package) int {
		return strings.Compare(a.Version, b.Version)
	})
	return sqlHotfixes
}

// findMsSqlGdrUpdates returns a list of GDR updates that are related to Microsoft SQL Server
// The list is sorted by the GDR update id
func findMsSqlGdrUpdates(packages []Package) []Package {
	sqlGdrUpdates := []Package{}
	for _, p := range packages {
		if sqlGDRUpdateRegExp.MatchString(p.Name) {
			sqlGdrUpdates = append(sqlGdrUpdates, p)
		}
	}
	slices.SortFunc(sqlGdrUpdates, func(a, b Package) int {
		return strings.Compare(a.Version, b.Version)
	})
	return sqlGdrUpdates
}

// updateMsSqlPackages updates the version of the SQL Server packages to the latest hotfix version
func updateMsSqlPackages(pkgs []Package, latestMsSqlUpdate Package) []Package {
	currentVersion := ""
	for _, pkg := range pkgs {
		if msSqlServiceRegexp.MatchString(pkg.Name) {
			currentVersion = pkg.Version
			break
		}
	}
	// Without the Database Engine Services package there is no anchor version to
	// match the other SQL Server packages against, so there is nothing to stamp.
	// Bailing here also avoids a footgun below: strings.Replace with an empty
	// `old` prepends `new` to the string, which would corrupt the PURL of any
	// "SQL Server" product bundle entry that carries an empty DisplayVersion
	// (e.g. "16.0.1150.1pkg:windows/windows/Microsoft%20SQL%20Server%202022...").
	if currentVersion == "" {
		return pkgs
	}
	// MSI registers SP-era SQL Server hotfix DisplayVersions with the SP level
	// baked into the minor component (13.3.x for SP3, etc.). Microsoft's
	// canonical product version uses .0 in the minor and encodes the SP in the
	// build component instead — that's the form MSRC publishes and the form
	// advisory consumers expect. Normalize before stamping so the engine
	// package version compares correctly against advisory ranges.
	normalizedVersion := normalizeMsSqlVersion(latestMsSqlUpdate.Version)
	log.Debug().Str("currentVersion", currentVersion).Str("normalizedVersion", normalizedVersion).Msg("Updating SQL Server packages")

	// Find other SQL Server packages and update them to the latest hotfix version
	for i, pkg := range pkgs {
		if strings.Contains(pkg.Name, "SQL Server") && pkg.Version == currentVersion {
			pkgs[i].Version = normalizedVersion
			log.Debug().Str("package", pkg.Name).Str("version", normalizedVersion).Msg("Updated SQL Server package")
			// Replace only the version component (`@<version>`) so we never
			// rewrite a matching substring elsewhere in the PURL (name, arch).
			pkgs[i].PUrl = strings.Replace(pkgs[i].PUrl, "@"+currentVersion, "@"+normalizedVersion, 1)
		}
	}
	return pkgs
}

// dotNetSuffixedRelease captures the release from the ".NET installer" family of
// DisplayNames, which carry it after a " - " separator and before the optional
// preview/arch tail:
//
//	Microsoft .NET Runtime - 8.0.30 (arm64)                    -> 8.0.30
//	Microsoft .NET Desktop Runtime - 6.0.36 (x64)              -> 6.0.36
//	Microsoft ASP.NET Core Runtime - 10.0.0 Preview 3 (arm64)  -> 10.0.0
//	Microsoft .NET Core Runtime - 3.1.32 (x64)                 -> 3.1.32
//	Microsoft .NET Host FX Resolver - 8.0.15 (arm64)           -> 8.0.15
//	Microsoft .NET Targeting Pack - 8.0.15 (arm64)             -> 8.0.15
//
// Anchored on "Microsoft .NET " / "Microsoft ASP.NET Core " so it only ever sees
// Microsoft's own .NET installer entries. Entries with no " - <release>" —
// "Microsoft .NET Toolset 8.0.408 (arm64)", the Microsoft.NET.Workload.* and
// Microsoft.NET.Sdk.* manifests — are deliberately not matched: they encode
// their versions on schemes of their own and nothing here needs them.
var dotNetSuffixedRelease = regexp.MustCompile(`^Microsoft (?:ASP\.NET Core|\.NET) [A-Za-z. ]*- (\d+(?:\.\d+)*)`)

// aspNetCoreSharedFrameworkRelease captures the release from the ASP.NET Core
// runtime's other DisplayName shape, which carries it in the middle with the
// hyphen optional. Both spellings occur on the same host:
//
//	Microsoft ASP.NET Core 8.0.28 - Shared Framework (x86)
//	Microsoft ASP.NET Core 8.0.15 Shared Framework (arm64)
//
// Its sibling "Microsoft ASP.NET Core 8.0.15 Targeting Pack (arm64)" is a
// different component and does not match.
var aspNetCoreSharedFrameworkRelease = regexp.MustCompile(`^Microsoft ASP\.NET Core (\d+(?:\.\d+)*) (?:- )?Shared Framework\b`)

// windowsDesktopRuntimeRelease matches the WPF/WinForms runtime, which Microsoft
// registers under the "Windows Desktop Runtime" name rather than the ".NET"
// brand — so it matches neither of the patterns above, and its packed MSI
// version would otherwise never be recovered. Verified on the VM:
//
//	BUNDLE  Microsoft Windows Desktop Runtime - 8.0.30 (arm64)  8.0.30.36323
//	msi     Microsoft Windows Desktop Runtime - 8.0.30 (arm64)  64.120.56881
//
// The separator is optional because Microsoft dropped it at 10.0. Both
// punctuations are live in one fleet inventory:
//
//	Microsoft Windows Desktop Runtime - 8.0.29 (x64)
//	Microsoft Windows Desktop Runtime 10.0.10 (x64)
//
// Anchored on the full product name rather than folded into the general
// pattern above: making the separator optional there would also match
// "Microsoft ASP.NET Core 8.0.15 Targeting Pack", which must stay untouched.
var windowsDesktopRuntimeRelease = regexp.MustCompile(`^Microsoft Windows Desktop Runtime (?:- )?(\d+(?:\.\d+)*)`)

// normalizeDotNetPackedVersion rewrites the DisplayVersion of a .NET installer
// entry to the release its own DisplayName carries.
//
// The .NET runtime installers register up to two Add/Remove-Programs entries for
// a single installed runtime, and only one of them carries a version a human or
// an advisory would recognise. Verified on a clean Windows 11 ARM64 VM with
// Microsoft's own dotnet-runtime-win-arm64.exe (8.0.30):
//
//	DisplayName                              DisplayVersion  written by
//	Microsoft .NET Runtime - 8.0.30 (arm64)  8.0.30.36317    the burn bundle
//	Microsoft .NET Runtime - 8.0.30 (arm64)  64.120.56788    the MSI
//
// The second is the MSI ProductVersion, which Windows Installer constrains to
// major<=255, minor<=255, build<=65535. .NET packs the release to fit —
// first component = major*8 — so the value shares no scale with anything:
//
//	.NET 2.1.30 -> 16.120.30411     .NET 6.0.36  -> 48.144.23141
//	.NET 3.1.32 -> 24.192.31915     .NET 8.0.30  -> 64.120.56788
//	.NET 5.0.17 -> 40.68.31213      .NET 10.0.10 -> 80.40.55332
//
// Installing the STANDALONE MSI rather than the bundle — what a managed
// Intune/SCCM rollout does — registers only the second entry. Verified on the
// same VM: after `msiexec /i dotnet-runtime-8.0.30-win-arm64.msi /qn` the host
// has one entry, at 64.120.56788. On such a host the DisplayName is the only
// place the real release appears at all, which is why this cannot be left to a
// consumer to work around.
//
// Applied to BOTH entries, not just the packed one, so that a bundle-installed
// host reports the runtime ONCE. The two entries describe a single install, and
// leaving the bundle's 8.0.30.36317 alongside a repaired 8.0.30 would give them
// different versions, hence different PURLs, hence two package rows and two
// findings carrying the same CVEs for one runtime. Collapsing both onto the
// DisplayName's release makes them identical on x64 — where both entries are
// registered under the same arch — so they converge instead of duplicating.
//
// The build component dropped from the bundle entry (…36317) costs nothing:
// every MSRC .NET runtime bound is three-component, so it never affected a
// verdict, and 8.0.30 is the version the product calls itself.
//
// The architecture the two entries carry is repaired separately, by
// normalizeDotNetInstallerArch: the bundle entry is registered under
// Wow6432Node and is therefore labelled x86 while the MSI entry is labelled
// with the host's architecture, which would keep the two rows distinct on arch
// -- and, since the arch reaches the PURL, distinct as findings -- even once
// their versions agree.
func normalizeDotNetPackedVersion(name, version string) string {
	if version == "" {
		return version
	}
	for _, re := range dotNetInstallerReleasePatterns {
		if m := re.FindStringSubmatch(name); m != nil {
			return m[1]
		}
	}
	return version
}

// dotNetInstallerReleasePatterns is the set of DisplayNames that identify an
// entry as belonging to the .NET installer family, shared by the version and
// the architecture repair below.
var dotNetInstallerReleasePatterns = []*regexp.Regexp{
	dotNetSuffixedRelease,
	aspNetCoreSharedFrameworkRelease,
	windowsDesktopRuntimeRelease,
}

// dotNetDisplayNameArch captures the architecture Microsoft appends to a .NET
// installer's DisplayName: the "(arm64)" in "Microsoft .NET Runtime - 8.0.30
// (arm64)".
var dotNetDisplayNameArch = regexp.MustCompile(`(?i)\((x86|x64|arm32|arm64)\)\s*$`)

// normalizeDotNetInstallerArch repairs the architecture of a .NET installer
// entry that the registry path mislabels as 32-bit.
//
// A .NET runtime installed from the burn bundle registers twice, and the bundle
// is itself a 32-bit process: its entry lands under Wow6432Node while the MSI
// entry for the SAME runtime lands under the plain HKLM key. archForRegistryPath
// reads Wow6432Node as x86, so the two rows for one install disagree about
// their architecture. Verified on a clean Windows 11 ARM64 VM with Microsoft's
// own dotnet-runtime-win-arm64.exe (8.0.30):
//
//	DisplayName                              registry path   labelled
//	Microsoft .NET Runtime - 8.0.30 (arm64)  Wow6432Node     x86     <- the bundle
//	Microsoft .NET Runtime - 8.0.30 (arm64)  HKLM            arm64   <- the MSI
//
// The DisplayName says what the runtime was actually built for, and it says
// arm64 on both. Once that architecture reaches the PURL -- which it does, see
// createPackage -- the disagreement stops being cosmetic: the two entries get
// different PURLs, so one install becomes two package rows and two findings
// carrying the same CVEs.
//
// The repair is deliberately one-directional. It only ever promotes an x86
// label to the platform's own architecture, and only when the DisplayName
// declares a 64-bit build, so a genuine 32-bit .NET runtime on a 64-bit host
// keeps its x86 label. The platform architecture is used rather than the token
// itself because a 64-bit build on a 64-bit host is built for THAT host, and
// because the token vocabulary ("x64") is not the one platform detection uses.
func normalizeDotNetInstallerArch(name, arch, platformArch string) string {
	if arch != "x86" || platformArch == "" || strings.EqualFold(platformArch, "x86") {
		return arch
	}

	isDotNetInstaller := false
	for _, re := range dotNetInstallerReleasePatterns {
		if re.MatchString(name) {
			isDotNetInstaller = true
			break
		}
	}
	if !isDotNetInstaller {
		return arch
	}

	m := dotNetDisplayNameArch.FindStringSubmatch(name)
	if m == nil {
		return arch
	}
	switch strings.ToLower(m[1]) {
	case "x64", "arm64":
		return platformArch
	}
	return arch
}

// msSqlSpVersionRegex matches the MSI DisplayVersion form for SP-era SQL Server
// (2012=11, 2014=12, 2016=13). The minor component carries the SP level
// (1–4); the build component carries the canonical patch level Microsoft's
// docs and the MSRC OSV both use.
var msSqlSpVersionRegex = regexp.MustCompile(`^(1[1-3])\.([1-4])\.(\d+)\.(\d+)$`)

// normalizeMsSqlVersion rewrites the SP-era MSI DisplayVersion
// `<major>.<SP>.<build>.<rev>` to the canonical Microsoft product version
// `<major>.0.<build>.<rev>` for SQL Server 2012 / 2014 / 2016. Other versions
// (SQL 2017+, which dropped Service Packs in the Modern Servicing Model, plus
// any input the regex doesn't recognize) are returned unchanged.
//
// The conversion is lossless: the SP level can be recovered from the build
// component (4xxx=SP1, 5xxx=SP2, 6xxx=SP3, 7xxx=SP4 for SQL 2016 for
// example), so the .0 form is equally informative and matches what Microsoft
// records in its build-versions tables and what MSRC publishes.
//
// Refs:
//   - https://learn.microsoft.com/troubleshoot/sql/releases/sqlserver-2016/build-versions
//   - https://learn.microsoft.com/troubleshoot/sql/releases/download-and-install-latest-updates
func normalizeMsSqlVersion(version string) string {
	m := msSqlSpVersionRegex.FindStringSubmatch(version)
	if m == nil {
		return version
	}
	return m[1] + ".0." + m[3] + "." + m[4]
}

// sanitizePackageField removes control characters (e.g. \r, \n, \t) from a
// registry-derived string and trims surrounding whitespace. Apply it to ANY
// REG_SZ value that ends up in the Package struct: name + version started the
// problem (control characters there produced invalid purls \u2014 issue #7975),
// but downstream consumers also serialize vendor/publisher and installLocation
// into JSON projections (mondoohq/server's mondoo-sbom-internal-packages
// bundle pulls vendor in alongside name/version/purl), and an unsanitized
// `\r`/`\n` or unpaired quote in any of those fields produces JSON like
// `{"name":"foo","vendor":"bar"description":...}` \u2014 JSON the server cannot
// decode, with the downstream effect that the asset's package_scores get
// silently emptied. The Windows packages provider is the one place that owns
// registry-derived field plumbing, so it is the right layer to sanitize at.
func sanitizePackageField(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// createPackage creates a new package with the given parameters
func createPackage(name, version, format, arch, publisher, installLocation string, platform *inventory.Platform) *Package {
	purlType := purl.TypeWindows
	if format == "windows/appx" {
		purlType = purl.TypeAppx
	}

	// replace non-breaking spaces with regular spaces
	name = strings.ReplaceAll(name, "\u00a0", " ")
	// Windows registry values can carry trailing control characters (e.g. \r\n).
	// Strip them from every REG_SZ field that lands on the Package \u2014 name and
	// version (purl correctness, #7975) and publisher and installLocation
	// (JSON-projection correctness \u2014 these become Vendor and Files[0].Path,
	// and an unsanitized control char in either silently corrupts the SBOM
	// projection the server pulls them out of).
	name = sanitizePackageField(name)
	version = sanitizePackageField(version)
	publisher = sanitizePackageField(publisher)
	installLocation = sanitizePackageField(installLocation)
	// Recover the real release for a .NET installer entry whose DisplayVersion is
	// the packed MSI ProductVersion. Runs before the PURL is built so the PURL,
	// the Version field and everything derived from them agree.
	if format == "windows/app" {
		version = normalizeDotNetPackedVersion(name, version)
		if platform != nil {
			arch = normalizeDotNetInstallerArch(name, arch, platform.Arch)
		}
	}
	// The purl carries the package's OWN architecture, not the host's. Without
	// WithArch, NewPackageURL falls back to platform.Arch, so a 32-bit
	// application on a 64-bit host would report Arch: x86 in the package record
	// and ?arch=x86_64 in its purl -- and the purl is what reaches vulnerability
	// matching. An empty arch still falls back to the platform, which is the
	// best guess available when the registry path told us nothing.
	purlModifiers := []purl.Modifier{}
	if arch != "" {
		purlModifiers = append(purlModifiers, purl.WithArch(arch))
	}
	pkg := &Package{
		Name:    name,
		Version: version,
		Format:  format,
		Arch:    arch,
		Vendor:  publisher,
		PUrl: purl.NewPackageURL(
			platform, purlType, name, version, purlModifiers...,
		).String(),
	}
	if installLocation != "" {
		pkg.Files = []FileRecord{
			{
				Path: installLocation,
			},
		}
		pkg.FilesAvailable = PkgFilesIncluded
	}

	if version != "" {
		cpeWfns, err := cpe.NewPackage2Cpe(publisher, name, version, "", "")
		if err != nil {
			log.Debug().Err(err).Str("name", name).Str("version", version).Msg("could not create cpe for windows app package")
		} else {
			pkg.CPEs = cpeWfns
		}
	}

	return pkg
}

// findExchangeCU returns the installed CU Exchange
// When a SU is installed, the CU is updated to the SU version
// But not the actual Exchange Server version
// We need this package to update the Exchange Server version
func findExchangeCU(packages []Package) *Package {
	for _, p := range packages {
		if exchangeCURegExp.MatchString(p.Name) {
			return &p
		}
	}

	return nil
}

// updateExchangePackage updates the version of the Exchange Server packages to the latest hotfix/security version
func updateExchangePackage(pkgs []Package, latestExchangeCU Package) []Package {
	// Find other SQL Server packages and update them to the latest hotfix version
	for i, pkg := range pkgs {
		if pkg.Name == "Microsoft Exchange Server" {
			currentVersion := pkgs[i].Version
			// Without a current version there is no `@<version>` to swap in the
			// PURL; replacing the empty-anchored `"@"` would target the first `@`
			// and corrupt the PURL, so skip the rewrite entirely.
			if currentVersion == "" {
				continue
			}
			pkgs[i].Version = latestExchangeCU.Version
			log.Debug().Str("package", pkg.Name).Str("version", latestExchangeCU.Version).Msg("Updated Exchange package")
			// Anchor on `@<version>` so we don't rewrite a substring match
			// elsewhere in the PURL.
			pkgs[i].PUrl = strings.Replace(pkgs[i].PUrl, "@"+currentVersion, "@"+latestExchangeCU.Version, 1)
		}
	}
	return pkgs
}

// omahaClientsNativeRoots are the fully-qualified registry paths of Google
// Update's ("Omaha") "Clients" key under both the 32-bit (Wow6432Node) and
// native 64-bit views, for the native local registry path
// (getLocalInstalledApps). See buildOmahaVersions for why an absent view is
// expected rather than an error, and applyOmahaVersions for what the key is
// used for.
var omahaClientsNativeRoots = []string{
	`HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`,
	`HKLM\SOFTWARE\Google\Update\Clients`,
}

// omahaClientsOfflineSubpaths is the same key, relative to the SOFTWARE hive
// root, for the offline/filesystem path (getFsInstalledApps), which reads
// through an already-loaded RegistryHandler rather than a live registry
// root.
var omahaClientsOfflineSubpaths = []string{
	`Wow6432Node\Google\Update\Clients`,
	`Google\Update\Clients`,
}

// omahaClientsScript is the remote-connection (PowerShell) equivalent of
// omahaClientsNativeRoots/omahaClientsOfflineSubpaths: it reads every Omaha
// "Clients" subkey's "name" and "pv" values from both registry views. A
// missing view (Test-Path false) is skipped rather than treated as an error
// -- on every host verified so far only the Wow6432Node view exists.
const omahaClientsScript = `
$result = New-Object System.Collections.Generic.List[object]
foreach ($p in @('HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\*', 'HKLM:\SOFTWARE\Google\Update\Clients\*')) {
  if (Test-Path $p) {
    Get-ItemProperty $p -ErrorAction SilentlyContinue | Select-Object -Property name, pv | ForEach-Object { $result.Add($_) }
  }
}
ConvertTo-Json -Compress -InputObject $result
`

// omahaChildrenFunc and omahaItemsFunc abstract over the two ways this file
// reads a registry key outside a remote PowerShell connection (native
// syscalls vs. an already-loaded offline hive through a RegistryHandler), so
// buildOmahaVersions can serve both getLocalInstalledApps and
// getFsInstalledApps.
type omahaChildrenFunc func(path string) ([]registry.RegistryKeyChild, error)

type omahaItemsFunc func(path string) ([]registry.RegistryKeyItem, error)

// buildOmahaVersions reads every subkey under the given Google Update
// ("Omaha") "Clients" roots and returns a map of Omaha's own product name
// (lowercased, for case-insensitive matching against a package's Name) to
// its authoritative "pv" version. See applyOmahaVersions for how the result
// is used.
//
// A root that fails to enumerate (children returns an error) is skipped
// silently, not treated as a failure: the native 64-bit
// Google\Update\Clients view is legitimately absent on a host that only ever
// installed the 32-bit Google Update service -- every host this was
// verified against.
//
// A subkey with no "name" identifies nothing to match a package against, and
// one whose "pv" is empty or not version-shaped -- observed on a real VM
// where an MSI had registered an Add/Remove-Programs entry without ever
// completing the product's deploy -- is dropped here so it can never reach
// applyOmahaVersions and blank out a package's real DisplayVersion.
func buildOmahaVersions(roots []string, children omahaChildrenFunc, items omahaItemsFunc) map[string]string {
	versions := map[string]string{}
	for _, root := range roots {
		kids, err := children(root)
		if err != nil {
			continue
		}
		for _, c := range kids {
			kidItems, err := items(c.Path + "\\" + c.Name)
			if err != nil {
				continue
			}
			var name, pv string
			for _, it := range kidItems {
				// Value names are compared case-insensitively on purpose.
				// Both registry readers match value names case-sensitively
				// (see RegistryHandler.GetNativeRegistryKeyItems), and a hive
				// restored from a .reg export can carry "Name"/"PV". An exact
				// match would leave both fields empty and silently disable
				// the whole lookup on that host.
				switch strings.ToLower(it.Key) {
				case "name":
					name = it.Value.String
				case "pv":
					pv = it.Value.String
				}
			}
			name = sanitizePackageField(name)
			// The same sanitization every other registry-sourced field gets
			// before it reaches a Package: a REG_SZ can carry trailing
			// control characters, and pv reaches both Version and the purl,
			// where a stray \r corrupts the identity (#7975, #8002).
			pv = sanitizePackageField(pv)
			if name == "" || !usableOmahaVersion(pv) {
				continue
			}
			key := strings.ToLower(name)
			// First root wins. The roots are ordered {Wow6432Node, native},
			// and a host that has both views populated for one product is
			// normally one that went through Google Update's 32->64-bit
			// transition and left the older view behind. Letting the second
			// root overwrite silently would pick by loop order, which is not
			// a rule anyone could reason about; keeping the first is at
			// least stable and is logged when the two disagree.
			if existing, dup := versions[key]; dup {
				if existing != pv {
					log.Debug().Str("name", name).Str("kept", existing).Str("ignored", pv).
						Msg("google update reports two versions for one product, keeping the first")
				}
				continue
			}
			versions[key] = pv
		}
	}
	return versions
}

// omahaClientEntry is one row of omahaClientsScript's JSON output.
type omahaClientEntry struct {
	Name string `json:"name"`
	PV   string `json:"pv"`
}

// parseOmahaClientsOutput turns omahaClientsScript's JSON into the same
// name(lowercased)->pv map buildOmahaVersions produces from a native
// registry read, so the remote and local paths feed applyOmahaVersions
// identically.
func parseOmahaClientsOutput(input io.Reader) (map[string]string, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return map[string]string{}, nil
	}

	var entries []omahaClientEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		// ConvertTo-Json collapses a single-element collection to a bare
		// object rather than a one-element array -- a well-known PowerShell
		// quirk, and the live case on every VM this was verified against,
		// which has exactly one Omaha-managed product installed (Chrome).
		// Retry as a single entry before giving up.
		var single omahaClientEntry
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return nil, err
		}
		entries = []omahaClientEntry{single}
	}

	versions := map[string]string{}
	for _, e := range entries {
		name := sanitizePackageField(e.Name)
		pv := sanitizePackageField(e.PV)
		if name == "" || !usableOmahaVersion(pv) {
			continue
		}
		key := strings.ToLower(name)
		if existing, dup := versions[key]; dup {
			if existing != pv {
				log.Debug().Str("name", name).Str("kept", existing).Str("ignored", pv).
					Msg("google update reports two versions for one product, keeping the first")
			}
			continue
		}
		versions[key] = pv
	}
	return versions, nil
}

// convergeOmahaArch aligns the architecture of an Omaha-managed package that
// is labelled x86 onto the host architecture, but ONLY when the same product
// at the same version is also present at the host architecture.
//
// Google Update is a 32-bit program, so the Add/Remove-Programs entry it
// registers lands under Wow6432Node and archForRegistryPath labels it x86,
// while a 64-bit MSI's own entry for the same install lands in the native
// view and is labelled with the host architecture. Once applyOmahaVersions
// has given both rows the same version they still differ in arch, so their
// purls differ, so collapsePackages keeps both -- and the duplicate this
// whole change exists to remove survives.
//
// The sibling requirement is what keeps this honest. A genuinely 32-bit
// install of a product on a 64-bit host is a real thing, and promoting its
// arch would be inventing a fact about the machine. Requiring a row that
// already claims the host architecture means the evidence for the 64-bit
// install came from the registry, not from this function: all it does is
// decide which of two labels for ONE install to keep. A lone x86 row is
// never touched.
//
// normalizeDotNetInstallerArch repairs the same Wow6432Node mislabelling for
// .NET, from the DisplayName rather than from a sibling, because .NET's
// DisplayName states the architecture and Omaha's product names do not.
func convergeOmahaArch(pkgs []Package, omahaVersions map[string]string, platform *inventory.Platform) {
	if len(omahaVersions) == 0 || platform == nil || platform.Arch == "" || strings.EqualFold(platform.Arch, "x86") {
		return
	}

	// Products that have a row at the host architecture, keyed by everything
	// except arch, so a match is the same install and not merely the same name.
	atHostArch := map[string]struct{}{}
	for i := range pkgs {
		p := &pkgs[i]
		if p.Format != "windows/app" || !strings.EqualFold(p.Arch, platform.Arch) {
			continue
		}
		if _, ok := omahaVersions[strings.ToLower(p.Name)]; !ok {
			continue
		}
		atHostArch[strings.Join([]string{p.Name, p.Version, p.InstallScope, p.InstallUser}, "\x00")] = struct{}{}
	}
	if len(atHostArch) == 0 {
		return
	}

	for i := range pkgs {
		p := &pkgs[i]
		if p.Format != "windows/app" || p.Arch != "x86" {
			continue
		}
		if _, ok := atHostArch[strings.Join([]string{p.Name, p.Version, p.InstallScope, p.InstallUser}, "\x00")]; !ok {
			continue
		}
		p.Arch = platform.Arch
		p.PUrl = purl.NewPackageURL(platform, purl.TypeWindows, p.Name, p.Version, purl.WithArch(p.Arch)).String()
	}
}

// usableOmahaVersion reports whether a Google Update "pv" can be trusted to
// replace a package's DisplayVersion.
//
// Two states are rejected, and the reasoning is the same for both: overwriting
// a real DisplayVersion with a value that identifies nothing is strictly worse
// than leaving it stale, because the stale value at least came from the
// product's own installer.
//
//   - Not version-shaped, including empty. Observed on a real VM where an MSI
//     had registered an Add/Remove-Programs entry without ever completing the
//     product's deploy: the Clients subkey existed with an empty pv.
//   - All-zero ("0.0.0.0" and friends). Google Update registers a product
//     before, and leaves it registered after, an install that never finished
//     or was rolled back. A zero version is version-shaped, so the shape check
//     alone lets it through, and it sorts below every advisory bound -- it
//     would match every advisory for the product whatever is really installed.
func usableOmahaVersion(pv string) bool {
	if !looksLikeVersion(pv) {
		return false
	}
	return strings.Trim(pv, "0.") != ""
}

// getOmahaVersionsRemote is the remote-connection counterpart of
// buildOmahaVersions, run over the active connection via PowerShell rather
// than native syscalls.
func (w *WinPkgManager) getOmahaVersionsRemote() (map[string]string, error) {
	cmd, err := w.conn.RunCommand(powershell.Encode(omahaClientsScript))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		// An absent key is NOT what gets us here: the script guards every
		// root with Test-Path and exits 0 either way. A non-zero status means
		// the script itself could not run -- a parse error, constrained
		// language mode, a transport failure -- and that silently costs every
		// Omaha-managed package on this host its real version. Surface the
		// reason instead of returning an indistinguishable empty result.
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, errors.Newf("google update lookup failed with exit status %d: %s",
			cmd.ExitStatus, strings.TrimSpace(string(stderr)))
	}
	return parseOmahaClientsOutput(cmd.Stdout)
}

// applyOmahaVersions rewrites the Version, PUrl and CPEs of every
// "windows/app" package whose Name Google Update (Omaha) also manages, using
// Omaha's own "pv" in place of Add/Remove Programs' DisplayVersion.
//
// Some Google-managed installers leave a second, stale Add/Remove-Programs
// entry behind whose DisplayVersion never advances past the raw MSI
// ProductVersion the installer originally shipped (observed on a real
// Windows 11 ARM64 host: a Chrome entry frozen at "69.218.16502"), because
// the post-install DisplayVersion rewrite that would normally correct it
// never ran. That entry and the browser's real, correctly-versioned entry
// then carry different DisplayVersions, hence different purls, hence one
// browser install reported as two packages with two sets of findings -- and
// because the frozen value is an opaque MSI ProductVersion, there is no way
// to recover the real version from the stale entry alone.
//
// Google Update tracks the authoritative version independently, under
// HKLM\SOFTWARE\[Wow6432Node\]Google\Update\Clients\<product GUID>: its "pv"
// value IS the real, currently-installed version, and its "name" value
// matches the ARP DisplayName exactly (verified live: "Google Chrome" /
// "153.0.8010.53"). That is what this rewrites onto every matching package,
// so a bundle/MSI-style duplicate this produces converges with its sibling
// the same way normalizeDotNetPackedVersion converges the .NET runtime's two
// entries -- collapsePackages then removes the now-identical row.
//
// Matches on exact, case-insensitive Name equality only, never fuzzy, and
// only when omahaVersions carries a version-shaped, non-empty "pv" for that
// name (see buildOmahaVersions): an app Omaha does not track is left alone,
// and so is one whose Clients entry had an empty "pv" -- observed on the same
// VM for an MSI that registered ARP without ever completing a deploy --
// since blanking a good DisplayVersion would be strictly worse than leaving
// it stale.
func applyOmahaVersions(pkgs []Package, omahaVersions map[string]string, platform *inventory.Platform) {
	if len(omahaVersions) == 0 {
		return
	}
	for i := range pkgs {
		pkg := &pkgs[i]
		if pkg.Format != "windows/app" {
			continue
		}
		// The versions come from HKLM, so they describe the machine-wide
		// install and nothing else. A per-user install of the same product
		// keeps its own Google Update state under HKCU, which is not read
		// here, so stamping the machine version onto a user's row would
		// report that user's browser as the version the MACHINE has.
		//
		// That failure is worse than the bug this function fixes. A host with
		// machine-wide Chrome 153 and a user still on 140 would report 153 for
		// both: a genuinely out-of-date browser, described as patched, with
		// its findings silently cleared. Leaving a user row alone at worst
		// leaves it as accurate as it was before.
		if pkg.InstallScope != installScopeMachine {
			continue
		}
		pv, ok := omahaVersions[strings.ToLower(pkg.Name)]
		if !ok || pv == pkg.Version {
			continue
		}
		pkg.Version = pv
		purlModifiers := []purl.Modifier{}
		if pkg.Arch != "" {
			purlModifiers = append(purlModifiers, purl.WithArch(pkg.Arch))
		}
		pkg.PUrl = purl.NewPackageURL(platform, purl.TypeWindows, pkg.Name, pv, purlModifiers...).String()
		// On failure the OLD CPEs must go. They were built by createPackage
		// from the version we just replaced, so keeping them leaves Version
		// and PUrl saying one version while the CPEs claim another -- and CPE
		// is what some vulnerability matching keys on, so the package would be
		// evaluated against the stale version's advisories. createPackage has
		// the same shape and is safe there only because the field starts empty.
		cpeWfns, err := cpe.NewPackage2Cpe(pkg.Vendor, pkg.Name, pv, "", "")
		if err != nil {
			log.Debug().Err(err).Str("name", pkg.Name).Str("version", pv).Msg("could not create cpe for omaha-versioned windows app package")
			pkg.CPEs = nil
			continue
		}
		pkg.CPEs = cpeWfns
	}

	// Versions alone do not make the two rows collapse: the same install can
	// be labelled x86 in one registry view and with the host architecture in
	// the other. Run after the rewrite, since the sibling match is on version.
	convergeOmahaArch(pkgs, omahaVersions, platform)
}

// collapsePackages collapses package rows that are indistinguishable to
// every downstream consumer of the final list: same format, name, version,
// arch and purl, found under the same install scope and user.
//
// The .NET runtime installers register two Add/Remove-Programs entries for
// one runtime install (the bundle's own entry and the MSI's hidden
// SystemComponent=1 entry) under two separate physical registry keys, which
// registryDedupKey/mergeDedupedRegistryPackages deliberately keep apart --
// that key is scoped to ONE physical registry entry by design (see its own
// doc comment). normalizeDotNetPackedVersion (#10710) then rewrites BOTH
// entries' DisplayVersion to the release their shared DisplayName carries,
// and applyOmahaVersions above does the same for Omaha-managed products.
// Once two rows agree on every field a consumer actually keys on -- and
// every consumer keys on the purl -- keeping both is reporting one install
// twice: two rows, two findings carrying the same CVEs for one thing.
//
// Runs last, after every version normalization (including
// applyOmahaVersions), since normalization is what makes two originally
// distinct rows converge in the first place.
//
// installScope and installUser are part of the key deliberately, even though
// they are almost never what distinguishes two rows for the SAME install:
// #10964 made mql report a package once per user profile it is installed
// for, and two different users each having their own install of the same
// app agree on every other field (name, version, arch, purl) while being
// genuinely two separate installs. Leaving scope/user out of the key would
// silently erase the per-user attribution this file otherwise goes out of
// its way to compute (installScopeForRegistryPath, getPerProfileInstalledApps)
// by collapsing them into one row.
//
// Format, name, version, arch and purl make up the rest of the key because
// together they are exactly what identifies "the same package" everywhere
// else in this file: createPackage builds the purl FROM name, version and
// arch, so purl is redundant with those three in the ordinary case -- it is
// kept in the key anyway because it is the field every actual downstream
// consumer (SBOM export, vulnerability matching) keys on, so two rows that
// somehow disagreed on purl while matching on name/version/arch would not be
// safe to collapse.
//
// That last point is where this key deliberately disagrees with packageID
// (resources/packages.go), which is what becomes a package resource's __id
// and therefore its cache key. packageID is format://name/version/arch, plus
// the SID only when installScope is "user"; it does not include the purl and
// does not distinguish "machine" from "". So this key is strictly the
// stricter of the two: anything it keeps apart, packageID also keeps apart,
// and the reverse does not hold.
//
// Strictly-stricter is the safe direction and it is why nothing is wrong
// today. Two rows that survive this collapse while sharing a packageID would
// collide in the resource cache, and CreateResource returns the cached first
// instance for a repeated id -- the second row would silently report the
// first one's values, which is the very symptom this function exists to
// remove. No current input produces that pair: the only purl qualifier any
// Windows package gets is the Microsoft 365 channel, which is resolved once
// per host and applied uniformly (applyM365ChannelQualifier), so two rows
// agreeing on name/version/arch always agree on purl; and every path through
// this file sets installScope, so it is never "".
//
// It stops being safe the day a purl qualifier is added that varies BETWEEN
// packages on one host rather than being a property of the host. Whoever
// adds one has to widen packageID to match, or narrow this key.
func collapsePackages(pkgs []Package) []Package {
	out := make([]Package, 0, len(pkgs))
	seen := map[string]int{}
	for _, p := range pkgs {
		key := strings.Join([]string{
			p.Format, p.Name, p.Version, p.Arch, p.PUrl, p.InstallScope, p.InstallUser,
		}, "\x00")
		if idx, dup := seen[key]; dup {
			absorbPackageAttribution(&out[idx], p)
			continue
		}
		seen[key] = len(out)
		out = append(out, p)
	}
	return out
}

// absorbPackageAttribution fills in fields the surviving package is missing
// from a duplicate that is about to be dropped.
//
// The two rows describe one install but are not written from one registry
// key, and the two keys carry different amounts of detail: the bundle's entry
// typically has no InstallDate and no InstallLocation while the MSI's twin
// does, or the reverse. Uninstall subkeys are enumerated in key order, which
// is product-GUID order, so WHICH of the two arrives first is arbitrary --
// dropping the later one wholesale would make a package's installDate and its
// SBOM evidence path depend on a GUID.
//
// Only absent fields are filled, never populated ones, so this can add detail
// but can never change an answer the surviving row already gave.
// mergeDedupedRegistryPackages resolves its own collisions on the same
// principle: prefer the better-attributed row over the emptier one.
func absorbPackageAttribution(keep *Package, dup Package) {
	if keep.InstallDate.IsZero() && !dup.InstallDate.IsZero() {
		keep.InstallDate = dup.InstallDate
	}
	if len(keep.Files) == 0 && len(dup.Files) > 0 {
		keep.Files = dup.Files
		keep.FilesAvailable = dup.FilesAvailable
	}
	if keep.Vendor == "" {
		keep.Vendor = dup.Vendor
	}
	if keep.Description == "" {
		keep.Description = dup.Description
	}
	if len(keep.CPEs) == 0 && len(dup.CPEs) > 0 {
		keep.CPEs = dup.CPEs
	}
}
