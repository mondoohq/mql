// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"
)

// PSGetWingetState collects everything needed to judge the Windows Package
// Manager (winget) in one round trip, without running winget itself:
//
//   - MachineArch: the native processor architecture, read from the machine
//     environment in the registry rather than $env:PROCESSOR_ARCHITECTURE,
//     which reports x86 inside a 32-bit PowerShell on a 64-bit host.
//   - Packages: the names of every AppX package the machine knows about: the
//     subkeys of the AppModel package repository (one per staged package full
//     name) plus the directory names under WindowsApps. Either source can be
//     unreadable on its own; the union covers both.
//   - Candidates: every Microsoft.DesktopAppInstaller package found above, with
//     its install folder, whether winget.exe is in it, the product version of
//     that winget.exe, and the text of its AppxManifest.xml.
//   - Policy: the App Installer Group Policy values.
//   - UserSources: the source list winget keeps for the SYSTEM account when it
//     runs outside its package (the way SYSTEM runs it, by path). It is read
//     through Sysnative when that exists, because a 32-bit PowerShell sees
//     SysWOW64 in place of System32.
//
// Every read is best effort; a missing key or file leaves its value null.
//
// File contents are cast to [string]: Get-Content attaches PSPath and other
// note properties to the strings it returns, and ConvertTo-Json in Windows
// PowerShell 5.1 writes such a string as {"value":"...","PSPath":...}.
const PSGetWingetState = `
$ErrorActionPreference = 'SilentlyContinue'
$arch = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE
$pf = $env:ProgramW6432
if (-not $pf) { $pf = $env:ProgramFiles }
$apps = Join-Path $pf 'WindowsApps'
$repo = 'HKLM:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages'
$names = @{}
$roots = @{}
foreach ($k in @(Get-ChildItem -Path $repo)) {
  $names[$k.PSChildName] = $true
  if ($k.PSChildName -like 'Microsoft.DesktopAppInstaller_*') {
    $r = (Get-ItemProperty -Path $k.PSPath).PackageRootFolder
    if ($r) { $roots[$k.PSChildName] = [string]$r }
  }
}
foreach ($d in @(Get-ChildItem -Path $apps -Directory)) { $names[$d.Name] = $true }
$cands = @()
foreach ($n in @($names.Keys | Where-Object { $_ -like 'Microsoft.DesktopAppInstaller_*' })) {
  $root = $roots[$n]
  if (-not $root) { $root = Join-Path $apps $n }
  $manifest = $null
  $mp = Join-Path $root 'AppxManifest.xml'
  if (Test-Path -LiteralPath $mp -PathType Leaf) { $manifest = [string](Get-Content -LiteralPath $mp -Raw) }
  $exe = Join-Path $root 'winget.exe'
  $hasExe = [bool](Test-Path -LiteralPath $exe -PathType Leaf)
  $exeVersion = $null
  if ($hasExe) { $exeVersion = [string](Get-Item -LiteralPath $exe).VersionInfo.ProductVersion }
  $cands += [PSCustomObject]@{
    FullName = $n
    Root = $root
    HasExe = $hasExe
    ExeVersion = $exeVersion
    Manifest = $manifest
  }
}
$gp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
$pol = $null
if (Test-Path $gp) {
  $p = Get-ItemProperty -Path $gp
  $list = {
    param($sub)
    $out = @()
    $key = Join-Path $gp $sub
    if (Test-Path $key) {
      $item = Get-Item -Path $key
      foreach ($v in $item.GetValueNames()) { $out += [string]$item.GetValue($v) }
    }
    $out
  }
  $pol = [PSCustomObject]@{
    EnableAppInstaller = $p.EnableAppInstaller
    EnableWindowsPackageManagerCommandLineInterfaces = $p.EnableWindowsPackageManagerCommandLineInterfaces
    EnableDefaultSource = $p.EnableDefaultSource
    EnableMicrosoftStoreSource = $p.EnableMicrosoftStoreSource
    EnableFontSource = $p.EnableFontSource
    EnableAdditionalSources = $p.EnableAdditionalSources
    EnableAllowedSources = $p.EnableAllowedSources
    AdditionalSources = @(& $list 'AdditionalSources')
    AllowedSources = @(& $list 'AllowedSources')
  }
}
$sys = Join-Path $env:windir 'Sysnative'
if (-not (Test-Path -LiteralPath $sys)) { $sys = Join-Path $env:windir 'System32' }
$us = Join-Path $sys 'config\systemprofile\AppData\Local\Microsoft\WinGet\Settings\defaultState\user_sources'
$userSources = $null
if (Test-Path -LiteralPath $us -PathType Leaf) { $userSources = [string](Get-Content -LiteralPath $us -Raw) }
[PSCustomObject]@{
  MachineArch = $arch
  Packages = @($names.Keys)
  Candidates = @($cands)
  Policy = $pol
  UserSources = $userSources
} | ConvertTo-Json -Depth 4 -Compress
`

// WingetCandidate is one Microsoft.DesktopAppInstaller package found on disk
// or in the package repository.
type WingetCandidate struct {
	FullName   string   `json:"FullName"`
	Root       string   `json:"Root"`
	HasExe     bool     `json:"HasExe"`
	ExeVersion PSString `json:"ExeVersion"`
	Manifest   PSString `json:"Manifest"`
}

type wingetCandidateList []WingetCandidate

func (l *wingetCandidateList) UnmarshalJSON(data []byte) error {
	raw, err := psUnwrapList(data)
	if err != nil {
		return err
	}
	if raw == nil {
		*l = nil
		return nil
	}
	var items []WingetCandidate
	if err := json.Unmarshal(raw, &items); err != nil {
		return err
	}
	*l = items
	return nil
}

// WingetPolicy holds the App Installer Group Policy values under
// HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller. A nil toggle is a
// policy that is not configured.
type WingetPolicy struct {
	EnableAppInstaller                               *int64        `json:"EnableAppInstaller"`
	EnableWindowsPackageManagerCommandLineInterfaces *int64        `json:"EnableWindowsPackageManagerCommandLineInterfaces"`
	EnableDefaultSource                              *int64        `json:"EnableDefaultSource"`
	EnableMicrosoftStoreSource                       *int64        `json:"EnableMicrosoftStoreSource"`
	EnableFontSource                                 *int64        `json:"EnableFontSource"`
	EnableAdditionalSources                          *int64        `json:"EnableAdditionalSources"`
	EnableAllowedSources                             *int64        `json:"EnableAllowedSources"`
	AdditionalSources                                PSStringArray `json:"AdditionalSources"`
	AllowedSources                                   PSStringArray `json:"AllowedSources"`
}

// WingetState is the parsed result of PSGetWingetState.
type WingetState struct {
	MachineArch string              `json:"MachineArch"`
	Packages    PSStringArray       `json:"Packages"`
	Candidates  wingetCandidateList `json:"Candidates"`
	Policy      *WingetPolicy       `json:"Policy"`
	UserSources *PSString           `json:"UserSources"`
}

// ParseWingetState decodes the JSON emitted by PSGetWingetState. Empty output
// is an error: the script always prints an object.
func ParseWingetState(r io.Reader) (*WingetState, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("winget state returned no data")
	}
	var state WingetState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// AppxPackageID is a parsed AppX package full name:
// <Name>_<Version>_<Architecture>_<ResourceId>_<PublisherId>.
type AppxPackageID struct {
	Name         string
	Version      string
	Architecture string
	ResourceID   string
	PublisherID  string
}

// ParseAppxFullName splits a package full name into its parts. Package names
// cannot contain underscores, so the split is unambiguous.
func ParseAppxFullName(fullName string) (AppxPackageID, bool) {
	parts := strings.Split(fullName, "_")
	if len(parts) != 5 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return AppxPackageID{}, false
	}
	if _, ok := parseAppxVersion(parts[1]); !ok {
		return AppxPackageID{}, false
	}
	return AppxPackageID{
		Name:         parts[0],
		Version:      parts[1],
		Architecture: strings.ToLower(parts[2]),
		ResourceID:   parts[3],
		PublisherID:  parts[4],
	}, true
}

// parseAppxVersion parses the four-part numeric AppX version.
func parseAppxVersion(v string) ([4]uint64, bool) {
	var out [4]uint64
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// compareAppxVersion compares two AppX versions numerically. Unparsable
// versions sort below every parsable one.
func compareAppxVersion(a, b string) int {
	va, okA := parseAppxVersion(a)
	vb, okB := parseAppxVersion(b)
	switch {
	case !okA && !okB:
		return 0
	case !okA:
		return -1
	case !okB:
		return 1
	}
	for i := range va {
		if va[i] != vb[i] {
			if va[i] < vb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// wingetPackageName is the AppX package that ships winget.exe.
const wingetPackageName = "Microsoft.DesktopAppInstaller"

// microsoftPublisherID is the publisher hash of packages signed by Microsoft
// Corporation, which App Installer is.
const microsoftPublisherID = "8wekyb3d8bbwe"

// runnableArchitectures lists the package architectures a machine can run,
// native first. ARM64 Windows runs x64, x86, and 32-bit ARM code under
// emulation; x64 Windows runs x86 through WOW64. An unknown machine
// architecture accepts every package architecture.
func runnableArchitectures(machineArch string) []string {
	switch strings.ToLower(strings.TrimSpace(machineArch)) {
	case "amd64", "x64", "x86_64", "64-bit":
		return []string{"x64", "x86"}
	case "arm64", "aarch64":
		return []string{"arm64", "x64", "x86", "arm"}
	case "x86", "32-bit":
		return []string{"x86"}
	case "arm":
		return []string{"arm"}
	default:
		return nil
	}
}

// NativeAppxArchitecture maps the machine architecture to the AppX
// architecture name of its native code, or "" when it is not known.
func NativeAppxArchitecture(machineArch string) string {
	if archs := runnableArchitectures(machineArch); len(archs) > 0 {
		return archs[0]
	}
	return ""
}

// SelectWingetCandidate picks the App Installer package winget would run from:
// the highest version that ships winget.exe for an architecture this machine
// can run, preferring the native architecture on a tie. Bundle and resource
// packages (neutral architecture) carry no winget.exe and never qualify.
func SelectWingetCandidate(candidates []WingetCandidate, machineArch string) (*WingetCandidate, AppxPackageID, bool) {
	archs := runnableArchitectures(machineArch)
	rank := func(arch string) int {
		if archs == nil {
			return 0
		}
		for i, a := range archs {
			if a == arch {
				return i
			}
		}
		return -1
	}

	var best *WingetCandidate
	var bestID AppxPackageID
	for i := range candidates {
		c := &candidates[i]
		if !c.HasExe {
			continue
		}
		id, ok := ParseAppxFullName(c.FullName)
		if !ok || id.Name != wingetPackageName || id.PublisherID != microsoftPublisherID {
			continue
		}
		if id.Architecture == "neutral" || rank(id.Architecture) < 0 {
			continue
		}
		if best == nil {
			best, bestID = c, id
			continue
		}
		switch cmp := compareAppxVersion(id.Version, bestID.Version); {
		case cmp > 0, cmp == 0 && rank(id.Architecture) < rank(bestID.Architecture):
			best, bestID = c, id
		}
	}
	return best, bestID, best != nil
}

// AppxDependency is one PackageDependency in an AppX manifest.
type AppxDependency struct {
	Name       string `xml:"Name,attr"`
	MinVersion string `xml:"MinVersion,attr"`
	Publisher  string `xml:"Publisher,attr"`
}

type appxManifest struct {
	Dependencies struct {
		Packages []AppxDependency `xml:"PackageDependency"`
	} `xml:"Dependencies"`
}

// ParseAppxDependencies returns the framework packages an AppX manifest
// declares under Dependencies/PackageDependency.
func ParseAppxDependencies(manifest string) ([]AppxDependency, error) {
	var m appxManifest
	if err := xml.Unmarshal([]byte(manifest), &m); err != nil {
		return nil, err
	}
	return m.Dependencies.Packages, nil
}

// MissingDependencies returns each declared dependency that no known package
// satisfies, as "<Name> >= <MinVersion>". A framework satisfies a dependency
// when its name matches, its version is at least MinVersion, and its
// architecture is the app's own or neutral, because Windows loads frameworks
// into the app's process.
func MissingDependencies(deps []AppxDependency, packages []string, appArch string) []string {
	have := map[string][]AppxPackageID{}
	for _, p := range packages {
		id, ok := ParseAppxFullName(p)
		if !ok {
			continue
		}
		key := strings.ToLower(id.Name)
		have[key] = append(have[key], id)
	}

	missing := []string{}
	for _, d := range deps {
		found := false
		for _, id := range have[strings.ToLower(d.Name)] {
			if id.Architecture != appArch && id.Architecture != "neutral" {
				continue
			}
			if d.MinVersion == "" || compareAppxVersion(id.Version, d.MinVersion) >= 0 {
				found = true
				break
			}
		}
		if !found {
			if d.MinVersion != "" {
				missing = append(missing, d.Name+" >= "+d.MinVersion)
			} else {
				missing = append(missing, d.Name)
			}
		}
	}
	return missing
}

// WingetSource is one package source winget would use.
type WingetSource struct {
	Name     string
	URL      string
	Type     string
	Origin   string
	Explicit bool
}

// Source types and origins as winget names them.
const (
	wingetSourceTypePreIndexed = "Microsoft.PreIndexed.Package"
	wingetSourceTypeRest       = "Microsoft.Rest"

	WingetOriginDefault = "default"
	WingetOriginUser    = "user"
	WingetOriginPolicy  = "policy"
)

// The well-known sources winget defines. The DesktopFrameworks source is
// internal and never shown, so it is left out.
var wingetDefaultSources = []WingetSource{
	{Name: "msstore", URL: "https://storeedgefd.dsx.mp.microsoft.com/v9.0", Type: wingetSourceTypeRest},
	{Name: "winget", URL: "https://cdn.winget.microsoft.com/cache", Type: wingetSourceTypePreIndexed},
	{Name: "winget-font", URL: "https://cdn.winget.microsoft.com/fonts", Type: wingetSourceTypePreIndexed, Explicit: true},
}

// policyToggle is the state of a Group Policy toggle: nil when not
// configured, otherwise whether it is enabled.
func policyToggle(v *int64) *bool {
	if v == nil {
		return nil
	}
	b := *v != 0
	return &b
}

func (p *WingetPolicy) toggle(name string) *bool {
	if p == nil {
		return nil
	}
	switch name {
	case "msstore":
		return policyToggle(p.EnableMicrosoftStoreSource)
	case "winget":
		return policyToggle(p.EnableDefaultSource)
	case "winget-font":
		return policyToggle(p.EnableFontSource)
	case "additional":
		return policyToggle(p.EnableAdditionalSources)
	case "allowed":
		return policyToggle(p.EnableAllowedSources)
	case "appinstaller":
		return policyToggle(p.EnableAppInstaller)
	case "cli":
		return policyToggle(p.EnableWindowsPackageManagerCommandLineInterfaces)
	}
	return nil
}

// Enabled reports whether Group Policy lets winget run from the command
// line. Both EnableAppInstaller and
// EnableWindowsPackageManagerCommandLineInterfaces block it when set to 0.
func (p *WingetPolicy) Enabled() bool {
	for _, name := range []string{"appinstaller", "cli"} {
		if t := p.toggle(name); t != nil && !*t {
			return false
		}
	}
	return true
}

// defaultEnabled reports whether a default source is on: every default is on
// unless its policy is explicitly disabled.
func (p *WingetPolicy) defaultEnabled(name string) bool {
	t := p.toggle(name)
	return t == nil || *t
}

// defaultRequired reports whether policy explicitly enables a default source,
// which also forbids removing or shadowing it.
func (p *WingetPolicy) defaultRequired(name string) bool {
	t := p.toggle(name)
	return t != nil && *t
}

type policySource struct {
	Name     string `json:"Name"`
	Arg      string `json:"Arg"`
	Type     string `json:"Type"`
	Data     string `json:"Data"`
	Explicit bool   `json:"Explicit"`
}

// parsePolicySources decodes the JSON source definitions stored as values of a
// Group Policy list key. Entries missing a required field are dropped, as
// winget drops them.
func parsePolicySources(values []string) []policySource {
	var out []policySource
	for _, v := range values {
		var raw map[string]any
		if err := json.Unmarshal([]byte(v), &raw); err != nil {
			continue
		}
		complete := true
		for _, f := range []string{"Name", "Arg", "Type", "Data", "Identifier"} {
			if _, ok := raw[f].(string); !ok {
				complete = false
			}
		}
		if !complete {
			continue
		}
		var s policySource
		if err := json.Unmarshal([]byte(v), &s); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out
}

type userSource struct {
	Name        string `json:"Name"`
	Type        string `json:"Type"`
	Arg         string `json:"Arg"`
	Data        string `json:"Data"`
	IsTombstone bool   `json:"IsTombstone"`
	IsOverride  bool   `json:"IsOverride"`
	Explicit    bool   `json:"Explicit"`
}

// parseUserSources decodes the user_sources YAML document winget writes: a
// Sources sequence of maps with Name, Type, Arg, Data, and IsTombstone, plus
// optional Identifier, IsOverride, Explicit, TrustLevel, and Priority. Like
// winget, a document that fails to parse contributes no sources.
func parseUserSources(doc string) []userSource {
	var parsed struct {
		Sources []userSource `json:"Sources"`
	}
	if err := yaml.Unmarshal([]byte(doc), &parsed); err != nil {
		return nil
	}
	return parsed.Sources
}

// userSourceAllowed mirrors how Group Policy filters a user-defined source:
// a tombstone cannot remove a default that policy requires, a source pointing
// at a disabled default is dropped, a source cannot shadow the name of a
// required default, and the allowed-sources policy can block user sources
// entirely or restrict them to a list.
func userSourceAllowed(s userSource, p *WingetPolicy) bool {
	if s.IsTombstone {
		return !p.defaultRequired(s.Name)
	}
	for _, d := range wingetDefaultSources {
		if strings.EqualFold(s.Arg, d.URL) && strings.EqualFold(s.Type, d.Type) {
			return p.defaultEnabled(d.Name)
		}
	}
	for _, d := range wingetDefaultSources {
		if s.Name == d.Name && p.defaultRequired(d.Name) {
			return false
		}
	}
	allowed := p.toggle("allowed")
	if allowed != nil && !*allowed {
		return false
	}
	if allowed != nil && *allowed {
		var list []policySource
		if p != nil {
			list = parsePolicySources(p.AllowedSources)
		}
		for _, a := range list {
			if strings.EqualFold(a.Name, s.Name) && strings.EqualFold(a.Type, s.Type) && a.Arg == s.Arg {
				return true
			}
		}
		return false
	}
	return true
}

// ResolveWingetSources computes the sources winget shows for the SYSTEM
// account from Group Policy and the SYSTEM account's user_sources document.
// It follows winget's own precedence: sources added by policy first, then
// user-defined sources, then the defaults, with the first definition of a
// name winning. A user tombstone hides the default of the same name.
func ResolveWingetSources(policy *WingetPolicy, userSourcesDoc *string) []WingetSource {
	type entry struct {
		src       WingetSource
		tombstone bool
	}
	var list []entry
	seen := func(name string) bool {
		for _, e := range list {
			if strings.EqualFold(e.src.Name, name) {
				return true
			}
		}
		return false
	}
	add := func(e entry) {
		if !seen(e.src.Name) {
			list = append(list, e)
		}
	}

	if t := policy.toggle("additional"); t != nil && *t {
		for _, s := range parsePolicySources(policy.AdditionalSources) {
			add(entry{src: WingetSource{Name: s.Name, URL: s.Arg, Type: s.Type, Origin: WingetOriginPolicy, Explicit: s.Explicit}})
		}
	}

	if userSourcesDoc != nil {
		for _, s := range parseUserSources(*userSourcesDoc) {
			if !userSourceAllowed(s, policy) {
				continue
			}
			if s.IsOverride {
				for _, d := range wingetDefaultSources {
					if d.Name == s.Name && policy.defaultEnabled(d.Name) {
						d.Origin = WingetOriginUser
						d.Explicit = s.Explicit
						add(entry{src: d})
					}
				}
				continue
			}
			add(entry{src: WingetSource{Name: s.Name, URL: s.Arg, Type: s.Type, Origin: WingetOriginUser, Explicit: s.Explicit}, tombstone: s.IsTombstone})
		}
	}

	for _, d := range wingetDefaultSources {
		if policy.defaultEnabled(d.Name) {
			d.Origin = WingetOriginDefault
			add(entry{src: d})
		}
	}

	out := []WingetSource{}
	for _, e := range list {
		if !e.tombstone {
			out = append(out, e.src)
		}
	}
	return out
}
