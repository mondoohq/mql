// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"path"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// Formats of the Windows package backends.
const (
	WindowsAppPkgFormat    = "windows/app"
	WindowsAppxPkgFormat   = "windows/appx"
	WindowsHotfixPkgFormat = "windows/hotfix"
)

// dotNetFrameworkName is the package the backend synthesizes for the .NET
// Framework 4.x runtime from its setup registry key. The 4.x runtime is a
// Windows component: it ships in every supported release and is serviced by
// Windows Update.
const dotNetFrameworkName = "Microsoft .NET Framework"

// AppX signature kinds (Windows.ApplicationModel.PackageSignatureKind).
const (
	appxSignatureNone       = 0
	appxSignatureDeveloper  = 1
	appxSignatureEnterprise = 2
	appxSignatureStore      = 3
	appxSignatureSystem     = 4
)

// appxInfo is what Get-AppxPackage reports about an AppX package beyond its
// identity.
type appxInfo struct {
	// family is the package family name, "<Name>_<PublisherId>", e.g.
	// "Microsoft.WindowsCalculator_8wekyb3d8bbwe".
	family string
	// signatureKind is one of the appxSignature constants, -1 when unknown.
	signatureKind int
	framework     bool
}

// appxSignatureKind decodes SignatureKind as Windows PowerShell writes it (the
// enum's number) or as PowerShell 7 can (its name). -1 when it is neither.
func appxSignatureKind(raw json.RawMessage) int {
	var n int
	if json.Unmarshal(raw, &n) == nil && n >= 0 && n <= appxSignatureSystem {
		return n
	}
	var name string
	if json.Unmarshal(raw, &name) == nil {
		switch strings.ToLower(name) {
		case "none":
			return appxSignatureNone
		case "developer":
			return appxSignatureDeveloper
		case "enterprise":
			return appxSignatureEnterprise
		case "store":
			return appxSignatureStore
		case "system":
			return appxSignatureSystem
		}
	}
	return -1
}

// windowsSourceQuery reads what decides whether software came with Windows, in
// one PowerShell call:
//
//   - provisioned: the AppX packages provisioned in the Windows image for every
//     new user, by the name of their registry key ("<Name>_<Version>_<Arch>_
//     <ResourceId>_<PublisherId>"). Calculator, Photos, Paint, Notepad, the
//     Store, Edge, Teams and Outlook are provisioned; an app a user installs
//     from the Store is not.
//   - edge: the uninstall commands of the Edge Update applications that record
//     Windows as their install source, which Edge and WebView2 do when they
//     came with Windows.
//   - appx: how each AppX package is signed and packaged. The package list's
//     own query does not ask for it, so a plain inventory never pays for it.
const windowsSourceQuery = `$o = @{}
$o.appx = @(Get-AppxPackage -AllUsers | Select Name, Version, PackageFamilyName, SignatureKind, IsFramework)
$o.provisioned = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
$o.edge = @(Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState','HKLM:\SOFTWARE\Microsoft\EdgeUpdate\ClientState' -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-ItemProperty $_.PSPath; if ($p.InstallSource -eq 'windows' -or $p.brand -eq 'INBX') { $p.UninstallString } })
$o | ConvertTo-Json -Compress`

// windowsSourceFacts is windowsSourceQuery's answer.
type windowsSourceFacts struct {
	// appx maps "<Name>/<Version>" of each AppX package to how it is signed
	// and packaged.
	appx map[string]appxInfo
	// provisioned holds package family names.
	provisioned map[string]bool
	// edgeDirs are the application directories of Edge Update applications
	// that came with Windows, lower case.
	edgeDirs []string
}

func (w *WinPkgManager) readWindowsSourceFacts() windowsSourceFacts {
	facts := windowsSourceFacts{provisioned: map[string]bool{}}
	cmd, err := w.conn.RunCommand(powershell.Encode(windowsSourceQuery))
	if err != nil || cmd.ExitStatus != 0 {
		log.Debug().Err(err).Msg("mql[packages]> could not read provisioned AppX packages and Edge install sources")
		return facts
	}
	return parseWindowsSourceFacts([]byte(readCommandOutput(cmd.Stdout)))
}

func parseWindowsSourceFacts(data []byte) windowsSourceFacts {
	facts := windowsSourceFacts{provisioned: map[string]bool{}, appx: map[string]appxInfo{}}
	var raw struct {
		Provisioned json.RawMessage `json:"provisioned"`
		Edge        json.RawMessage `json:"edge"`
		Appx        json.RawMessage `json:"appx"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return facts
	}
	var appx []struct {
		Name          string          `json:"Name"`
		Version       string          `json:"Version"`
		FamilyName    string          `json:"PackageFamilyName"`
		SignatureKind json.RawMessage `json:"SignatureKind"`
		IsFramework   bool            `json:"IsFramework"`
	}
	if len(raw.Appx) > 0 && raw.Appx[0] == '{' {
		raw.Appx = append(append(json.RawMessage{'['}, raw.Appx...), ']')
	}
	if err := json.Unmarshal(raw.Appx, &appx); err == nil {
		for _, a := range appx {
			facts.appx[a.Name+"/"+a.Version] = appxInfo{family: a.FamilyName, signatureKind: appxSignatureKind(a.SignatureKind), framework: a.IsFramework}
		}
	}
	for _, key := range jsonStrings(raw.Provisioned) {
		if family := appxFamilyFromKey(key); family != "" {
			facts.provisioned[strings.ToLower(family)] = true
		}
	}
	for _, uninstall := range jsonStrings(raw.Edge) {
		if dir := edgeApplicationDir(uninstall); dir != "" {
			facts.edgeDirs = append(facts.edgeDirs, dir)
		}
	}
	return facts
}

// jsonStrings reads a JSON string or array of strings: PowerShell writes a
// one-element array as the element itself.
func jsonStrings(raw json.RawMessage) []string {
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	return nil
}

// appxFamilyFromKey turns a provisioned package's key name into its family
// name: the first field, the package name, and the last, the publisher ID.
// AppX names cannot contain "_", so the fields split cleanly.
func appxFamilyFromKey(key string) string {
	fields := strings.Split(key, "_")
	if len(fields) < 3 {
		return ""
	}
	return fields[0] + "_" + fields[len(fields)-1]
}

// edgeApplicationDir returns the application directory of an Edge Update
// uninstall command, ".../Edge/Application/154.0.4258.62/Installer/setup.exe"
// is ".../edge/application", lower case.
func edgeApplicationDir(uninstall string) string {
	p := strings.ToLower(strings.ReplaceAll(strings.Trim(uninstall, `" `), `\`, "/"))
	if !strings.HasSuffix(p, "/installer/setup.exe") {
		return ""
	}
	// drop "/installer/setup.exe", then the version directory
	return path.Dir(path.Dir(path.Dir(p)))
}

// Sources says where each Windows package came from (ADR 049).
func (w *WinPkgManager) Sources(pkgs []Package) ([]Source, error) {
	var facts windowsSourceFacts
	for i := range pkgs {
		// only AppX and Edge decisions need the query; skip it for a
		// package list without either
		if pkgs[i].Format == WindowsAppxPkgFormat || pkgs[i].Format == WindowsAppPkgFormat {
			facts = w.readWindowsSourceFacts()
			break
		}
	}
	out := make([]Source, len(pkgs))
	for i := range pkgs {
		out[i] = windowsPackageSource(pkgs[i], facts)
	}
	return out, nil
}

// windowsPackageSource decides one package's source.
//
// An AppX package came with Windows when it is a system component (signature
// kind System), when the Windows image provisioned it for every user, or when
// Microsoft publishes it as a framework the inbox apps depend on, or under
// "CN=Microsoft Windows". The signature kind alone cannot decide it: the inbox
// apps (Calculator, Photos, Paint, Notepad, the Store) are Store-signed, and
// Edge, Teams and Outlook are Developer-signed, like a sideloaded package.
//
// A program in the Uninstall registry was put there by an installer, so its
// channel is "installer"; an MSI is named by its ProductCode. Windows records
// whether it came with Windows only for Edge and WebView2, through Edge
// Update; for everything else osProvided stays null.
func windowsPackageSource(pkg Package, facts windowsSourceFacts) Source {
	if pkg.source != nil {
		return *pkg.source
	}
	osSource := Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "Windows"}
	switch pkg.Format {
	case WindowsHotfixPkgFormat:
		return DefaultSource(pkg)

	case WindowsAppxPkgFormat:
		a, ok := facts.appx[pkg.Name+"/"+pkg.Version]
		if !ok || a.signatureKind < 0 {
			// found on disk without PowerShell: only the system components'
			// location says anything
			if isWindowsSystemAppLocation(pkg) {
				return osSource
			}
			return unknownSource()
		}
		microsoftWindows := strings.HasPrefix(pkg.Vendor, "CN=Microsoft Windows,")
		microsoft := microsoftWindows || strings.HasPrefix(pkg.Vendor, "CN=Microsoft Corporation,")
		switch {
		case a.signatureKind == appxSignatureSystem,
			facts.provisioned[strings.ToLower(a.family)],
			a.framework && microsoft,
			microsoftWindows:
			return osSource
		case a.signatureKind == appxSignatureStore:
			return Source{OSProvided: osProvided(false), Channel: ChannelAppStore, Name: "microsoft-store"}
		}
		return Source{OSProvided: osProvided(false), Channel: ChannelDirect}

	case WindowsAppPkgFormat:
		// the backend builds this one itself, as publisher "Microsoft"; the
		// Uninstall entries of .NET runtimes say "Microsoft Corporation"
		if pkg.Name == dotNetFrameworkName && pkg.Vendor == "Microsoft" {
			return osSource
		}
		if isInboxEdge(pkg, facts.edgeDirs) {
			return osSource
		}
		return Source{Channel: ChannelInstaller, Name: windowsProductCode(pkg)}
	}
	return unknownSource()
}

// isWindowsSystemAppLocation reports an AppX package installed where only
// Windows installs packages: SystemApps and ImmersiveControlPanel.
func isWindowsSystemAppLocation(pkg Package) bool {
	if len(pkg.Files) == 0 {
		return false
	}
	p := strings.ToLower(strings.ReplaceAll(pkg.Files[0].Path, `\`, "/"))
	return strings.Contains(p, "/windows/systemapps/") || strings.HasSuffix(p, "/windows/immersivecontrolpanel")
}

// isInboxEdge reports an Uninstall entry of Edge, WebView2 or Edge Update that
// came with Windows: its install location is the application directory of an
// Edge Update application recording Windows as its install source. Edge
// Update itself has no install location of its own and is matched by name
// when Edge came with Windows.
func isInboxEdge(pkg Package, edgeDirs []string) bool {
	if len(edgeDirs) == 0 || !strings.HasPrefix(pkg.Vendor, "Microsoft") {
		return false
	}
	if pkg.Name == "Microsoft Edge Update" {
		return true
	}
	if len(pkg.Files) == 0 {
		return false
	}
	loc := strings.TrimSuffix(strings.ToLower(strings.ReplaceAll(pkg.Files[0].Path, `\`, "/")), "/")
	for _, dir := range edgeDirs {
		if loc == dir {
			return true
		}
	}
	return false
}

// windowsProductCode returns the MSI ProductCode of an Uninstall entry,
// "{3B0346D3-...}", or "" for one an MSI did not install. The listing records
// it in the purl's product_code qualifier once it has used the entry's
// identity, so that is read first.
func windowsProductCode(pkg Package) string {
	if parsed, err := packageurl.FromString(pkg.PUrl); err == nil {
		if pc := parsed.Qualifiers.Map()[qualifierProductCode]; pc != "" {
			return "{" + strings.ToUpper(strings.Trim(pc, "{}")) + "}"
		}
	}
	if id := pkg.installIdentity; id != nil && id.windowsInstaller && isProductCode(id.uninstallKey) {
		return strings.ToUpper(id.uninstallKey)
	}
	return ""
}

// isProductCode reports an MSI ProductCode, a GUID in braces:
// {23170F69-40C1-2702-2501-000001000000}.
func isProductCode(key string) bool {
	if len(key) != 38 || key[0] != '{' || key[37] != '}' {
		return false
	}
	for i, c := range key[1:37] {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}
