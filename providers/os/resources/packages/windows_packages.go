// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
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
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/detector/windows"
	"go.mondoo.com/mql/v13/providers/os/registry"
	"go.mondoo.com/mql/v13/providers/os/resources/cpe"
	"go.mondoo.com/mql/v13/providers/os/resources/powershell"
	"go.mondoo.com/mql/v13/providers/os/resources/purl"
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

const installedAppsScript = `
Get-ItemProperty (@(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKCU:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
) | Where-Object { Test-Path $_ }) |
Select-Object -Property DisplayName,DisplayVersion,Publisher,EstimatedSize,InstallSource,UninstallString,InstallLocation,InstallDate,PSPath | ConvertTo-Json -Compress
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

func HotFixesToPackages(hotfixes []PowershellWinHotFix) []Package {
	pkgs := make([]Package, len(hotfixes))
	for i := range hotfixes {
		// Defense-in-depth — Get-HotFix's Description is typically a short
		// string like "Update" / "Security Update", but it comes through the
		// same PowerShell→JSON path as the registry packages, so apply the
		// same sanitization so a stray control character can't corrupt the
		// downstream SBOM projection.
		pkgs[i] = Package{
			Name:        sanitizePackageField(hotfixes[i].HotFixId),
			Description: sanitizePackageField(hotfixes[i].Description),
			Format:      "windows/hotfix",
		}
	}
	return pkgs
}

type WinPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (w *WinPkgManager) Name() string {
	return "Windows Package Manager"
}

func (w *WinPkgManager) Format() string {
	return "win"
}

func (w *WinPkgManager) getLocalInstalledApps() ([]Package, error) {
	pkgs := []string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"HKCU\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
	}
	packages := []Package{}
	for _, r := range pkgs {
		arch := archForRegistryPath(r, w.platform.Arch)
		children, err := registry.GetNativeRegistryKeyChildren(r)
		if err != nil {
			continue
		}
		for _, c := range children {
			p, err := getPackageFromRegistryKey(c, w.platform, arch)
			if err != nil {
				return nil, err
			}
			if p == nil {
				continue
			}
			packages = append(packages, *p)
		}
	}

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

	if pkg, err := w.getDotNetFramework4x(); err != nil {
		log.Debug().Err(err).Msg("could not get .NET Framework 4.x runtime")
	} else if pkg != nil {
		packages = append(packages, *pkg)
	}

	if pkg, err := w.getDotNetFramework35(); err != nil {
		log.Debug().Err(err).Msg("could not get .NET Framework 3.5 runtime")
	} else if pkg != nil {
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
			p, err := getPackageFromRegistryKey(c, w.platform, arch)
			if err != nil {
				return nil, err
			}
			if p == nil {
				continue
			}
			packages = append(packages, *p)
		}
	}

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

func getPackageFromRegistryKey(key registry.RegistryKeyChild, platform *inventory.Platform, arch string) (*Package, error) {
	items, err := registry.GetNativeRegistryKeyItems(key.Path + "\\" + key.Name)
	if err != nil {
		log.Debug().Err(err).Str("path", key.Path).Msg("could not read registry key children")
		return nil, err
	}
	return getPackageFromRegistryKeyItems(items, platform, arch), nil
}

func getPackageFromRegistryKeyItems(children []registry.RegistryKeyItem, platform *inventory.Platform, arch string) *Package {
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
		return nil
	}

	// TODO: We need to figure out why we have empty displayNames.
	// this is common in windows but we need to verify it is a windows
	// issue and not an mql issue.
	if displayName == "" {
		log.Debug().Msg("ignored package since display name is missing")
		return nil
	}

	// For shared registry paths (like HKCU) where WOW64 redirection doesn't apply,
	// fall back to checking install paths for "Program Files (x86)".
	if arch == platform.Arch {
		if detected := archFromInstallPath(installLocation, uninstallString); detected != "" {
			arch = detected
		}
	}

	pkg := createPackage(displayName, displayVersion, "windows/app", arch, publisher, installLocation, platform)

	return pkg
}

// archForRegistryPath returns "x86" for Wow6432Node registry paths (32-bit apps on 64-bit Windows),
// or the platform architecture for regular paths.
func archForRegistryPath(path string, platformArch string) string {
	if strings.Contains(path, "Wow6432Node") {
		return "x86"
	}
	return platformArch
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
	pkgs = append(pkgs, appPkgs...)

	appxPackages, err := w.getAppxPackages()
	if err != nil {
		return nil, errors.Wrap(err, "could not read appx package list")
	}
	pkgs = append(pkgs, appxPackages...)

	canRunCmd := w.conn.Capabilities().Has(shared.Capability_RunCommand)
	if !canRunCmd {
		log.Debug().Msg("cannot run command on windows, skipping hotfixes list")
		return pkgs, nil
	}

	// hotfixes
	cmd, err := w.conn.RunCommand(powershell.Wrap(WINDOWS_QUERY_HOTFIXES))
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch hotfixes")
	}
	hotfixes, err := ParseWindowsHotfixes(cmd.Stdout)
	if err != nil {
		return nil, errors.Wrapf(err, "could not parse hotfix results")
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
	return pkgs, nil
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
	}

	var entries []powershellUninstallEntry
	err = json.Unmarshal(data, &entries)
	if err != nil {
		return nil, err
	}

	pkgs := []Package{}
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
		pkgs = append(pkgs, *pkg)
	}

	return pkgs, nil
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
// Residual, ARM64 only: there the bundle entry is registered under
// Wow6432Node and is therefore labelled arch x86 while the MSI entry is ARM64,
// so the two rows stay distinct on arch even once their versions agree. That
// arch labelling is a separate question and is not touched here.
func normalizeDotNetPackedVersion(name, version string) string {
	if version == "" {
		return version
	}
	for _, re := range []*regexp.Regexp{
		dotNetSuffixedRelease,
		aspNetCoreSharedFrameworkRelease,
		windowsDesktopRuntimeRelease,
	} {
		if m := re.FindStringSubmatch(name); m != nil {
			return m[1]
		}
	}
	return version
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
	}
	pkg := &Package{
		Name:    name,
		Version: version,
		Format:  format,
		Arch:    arch,
		Vendor:  publisher,
		PUrl: purl.NewPackageURL(
			platform, purlType, name, version,
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
