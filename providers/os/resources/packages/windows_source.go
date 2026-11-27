// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/glebarez/go-sqlite" // registers the "sqlite" database/sql driver
	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
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
	// winget indexes what winget's tracking catalogs say, by lower-cased
	// Uninstall key name. Empty when no catalog was read.
	winget wingetIndex
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
	needQuery, hasApp := false, false
	for i := range pkgs {
		// only AppX and Edge decisions need the query; skip it for a
		// package list without either
		switch pkgs[i].Format {
		case WindowsAppxPkgFormat:
			needQuery = true
		case WindowsAppPkgFormat:
			needQuery, hasApp = true, true
		}
	}
	if needQuery {
		facts = w.readWindowsSourceFacts()
	}
	// winget's catalogs only say anything about Uninstall entries
	if hasApp {
		toFsPath := nativeWindowsPath
		if t := w.conn.Type(); t == shared.Type_FileSystem || t == shared.Type_Device {
			toFsPath = mountedSystemDrivePath
		}
		facts.winget = readWingetCatalogs(w.conn.FileSystem(), toFsPath)
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
// Update; for everything else osProvided stays null. A program winget
// installed is the exception: winget's tracking catalog names it, so its
// channel is "winget" and its name the winget package identifier.
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
		if src, ok := facts.winget.source(pkg); ok {
			return src
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

// winget keeps a tracking catalog of what it installed or took over: one SQLite
// file, installed.db, per source directory and per account that ran winget.
// The packaged winget (App Installer) keeps them in the account's package
// data; the unpackaged one, which SYSTEM uses (Intune, scripts), under
// WinGet\State. A machine-scope install is tracked in the catalog of the
// account that ran winget, not in a machine-wide one, so every account's
// catalogs are read.
//
// The catalog joins to the Uninstall registry through productcodes: the
// Uninstall subkey name of the program, lower-cased ("7-zip", a GUID, an Inno
// Setup AppId with "_is1", the "<id>_<source>_<family>" key of a portable).
const (
	wingetPackagedState   = `AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState`
	wingetUnpackagedState = `AppData\Local\Microsoft\WinGet\State\defaultState`
	wingetCatalogFile     = "installed.db"
	// winget's source directory of the Microsoft Store (lower case); the
	// community repository's is "Microsoft.Winget.Source_8wekyb3d8bbwe", and a
	// custom source has a directory of its own.
	wingetMsStoreDir = "storeedgefd"

	wingetMaxCatalogBytes = 16 << 20
	wingetMaxCatalogs     = 64
)

// wingetSystemProfile is the profile of SYSTEM, which no listing of C:\Users
// shows.
const wingetSystemProfile = `C:\Windows\System32\config\systemprofile`

// wingetEntry is one tracked manifest that names an Uninstall key.
type wingetEntry struct {
	id      string
	version string
	// written is when winget tracked it, unix seconds (manifest_metadata 7).
	written int64
	// sourceDir is the catalog's source directory name, lower case.
	sourceDir string
}

// wingetIndex maps a lower-cased Uninstall key name to the manifests that name it.
type wingetIndex map[string][]wingetEntry

// source decides the package's source from the catalog. Old manifests stay
// after an upgrade, so one key can name several; the one for the installed
// version wins, then the most recently tracked one. A catalog can hold an
// older version than the registry (a later upgrade by another account), and
// that still says who installed the program.
func (idx wingetIndex) source(pkg Package) (Source, bool) {
	if len(idx) == 0 || pkg.installIdentity == nil || pkg.installIdentity.uninstallKey == "" {
		return Source{}, false
	}
	entries := idx[strings.ToLower(pkg.installIdentity.uninstallKey)]
	if len(entries) == 0 {
		return Source{}, false
	}
	best := entries[0]
	for _, e := range entries[1:] {
		eMatch, bestMatch := e.version == pkg.Version, best.version == pkg.Version
		if (eMatch && !bestMatch) || (eMatch == bestMatch && e.written > best.written) {
			best = e
		}
	}
	if best.sourceDir == wingetMsStoreDir {
		return Source{OSProvided: osProvided(false), Channel: ChannelAppStore, Name: "microsoft-store"}, true
	}
	return Source{OSProvided: osProvided(false), Channel: ChannelWinget, Name: best.id}, true
}

// wingetCatalogPaths lists the installed.db files of every account, as
// Windows paths. Nothing here fails: a directory that is not there is skipped.
func wingetCatalogPaths(fs afero.Fs, toFsPath func(string) (string, bool)) []string {
	listDirs := func(dir string) []string {
		fp, ok := toFsPath(dir)
		if !ok {
			return nil
		}
		infos, err := afero.ReadDir(fs, fp)
		if err != nil {
			return nil
		}
		var names []string
		for _, fi := range infos {
			if fi.IsDir() {
				names = append(names, fi.Name())
			}
		}
		return names
	}

	profiles := []string{wingetSystemProfile}
	for _, name := range listDirs(`C:\Users`) {
		profiles = append(profiles, `C:\Users\`+name)
	}
	var paths []string
	for _, profile := range profiles {
		for _, state := range []string{wingetPackagedState, wingetUnpackagedState} {
			base := profile + `\` + state
			for _, sourceDir := range listDirs(base) {
				db := base + `\` + sourceDir + `\` + wingetCatalogFile
				if fp, ok := toFsPath(db); ok {
					if fi, err := fs.Stat(fp); err == nil && !fi.IsDir() {
						paths = append(paths, db)
					}
				}
			}
		}
	}
	sort.Strings(paths)
	if len(paths) > wingetMaxCatalogs {
		paths = paths[:wingetMaxCatalogs]
	}
	return paths
}

// readWingetCatalogs reads every account's winget catalogs into one index. A
// catalog that cannot be read is skipped.
func readWingetCatalogs(fs afero.Fs, toFsPath func(string) (string, bool)) wingetIndex {
	idx := wingetIndex{}
	for _, p := range wingetCatalogPaths(fs, toFsPath) {
		fp, _ := toFsPath(p)
		dir := p[:strings.LastIndex(p, `\`)]
		sourceDir := strings.ToLower(dir[strings.LastIndex(dir, `\`)+1:])
		rows, err := readWingetCatalog(fs, fp, sourceDir)
		if err != nil {
			log.Debug().Err(err).Str("path", p).Msg("mql[packages]> could not read winget catalog")
			continue
		}
		for _, r := range rows {
			idx[r.key] = append(idx[r.key], r.wingetEntry)
		}
	}
	return idx
}

// wingetRow is a product code with the manifest that holds it.
type wingetRow struct {
	key string
	wingetEntry
}

// copyWingetFile copies one catalog file to a local file, refusing a file over
// the size bound.
func copyWingetFile(fs afero.Fs, src, dst string) error {
	fi, err := fs.Stat(src)
	if err != nil {
		return err
	}
	if fi.Size() > wingetMaxCatalogBytes {
		return fmt.Errorf("%s is larger than %d bytes", src, wingetMaxCatalogBytes)
	}
	in, err := fs.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(in, wingetMaxCatalogBytes+1)); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// readWingetCatalog copies one installed.db to a local temp file (SQLite needs
// a local path) and reads its product codes.
func readWingetCatalog(fs afero.Fs, fsPath, sourceDir string) ([]wingetRow, error) {
	tmpDir, err := os.MkdirTemp("", "mondoo-winget")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	local := filepath.Join(tmpDir, wingetCatalogFile)
	if err := copyWingetFile(fs, fsPath, local); err != nil {
		return nil, err
	}
	dsn := "file:" + local + "?mode=ro&immutable=1"
	// a catalog winget has open holds recent writes in its write-ahead log,
	// which an immutable open ignores
	if _, err := fs.Stat(fsPath + "-wal"); err == nil {
		if err := copyWingetFile(fs, fsPath+"-wal", local+"-wal"); err == nil {
			dsn = "file:" + local + "?mode=rw"
		}
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT pc.productcode, i.id, v.version, CAST(COALESCE(mm.value, 0) AS INTEGER)
FROM productcodes_map pm
JOIN productcodes pc ON pc.rowid = pm.productcode
JOIN manifest m ON m.rowid = pm.manifest
JOIN ids i ON i.rowid = m.id
JOIN versions v ON v.rowid = m.version
LEFT JOIN manifest_metadata mm ON mm.manifest = m.rowid AND mm.metadata = 7`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []wingetRow
	for rows.Next() {
		var r wingetRow
		if err := rows.Scan(&r.key, &r.id, &r.version, &r.written); err != nil {
			return nil, err
		}
		r.key = strings.ToLower(r.key)
		r.sourceDir = sourceDir
		out = append(out, r)
	}
	return out, rows.Err()
}
