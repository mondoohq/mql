// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"encoding/json"
	"io"
	"maps"
	"regexp"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// A Windows application's DisplayName is a label for people: installers put
// versions, editions, architectures and locales into it, and rename it between
// releases. The Add/Remove Programs entry also carries identifiers that installers
// keep stable on purpose, and those are what this file puts on the package url,
// next to the name, as qualifiers:
//
//	product_code  MSI ProductCode: the Uninstall key of an entry with
//	              WindowsInstaller=1. Identifies one release (usually per version,
//	              language and architecture), so it pins exactly what is installed.
//	upgrade_code  MSI UpgradeCode, or a WiX Burn bundle's BundleUpgradeCode.
//	              Stays the same across every release of a product line; it is
//	              the identifier Windows Installer itself uses to find the
//	              product a newer release replaces.
//	app_id        Every other installer: the Uninstall key name the installer
//	              chose (Inno Setup's AppId with its "_is1" suffix removed, the
//	              key NSIS, install4j or a custom installer writes). Stable for
//	              most installers, but nothing enforces it.
//
// GUIDs are written without braces and in upper case, so the same product
// always yields the same qualifier string regardless of how a tool spelled it.
// The name stays the package name: qualifiers add identity, they do not
// replace the DisplayName consumers already match on.
const (
	qualifierProductCode = "product_code"
	qualifierUpgradeCode = "upgrade_code"
	qualifierAppID       = "app_id"
)

// The installer qualifier says which installer technology wrote the entry, so
// a consumer knows how the install can be updated or removed. It is a closed
// set, decided by the same rules that pick the identity qualifiers above:
//
//	msi           WindowsInstaller=1 on a GUID Uninstall key. Present exactly
//	              when product_code is.
//	burn          A WiX Burn bundle (BundleUpgradeCode). Present exactly when
//	              the bundle's upgrade_code is used.
//	inno          Inno Setup: the Uninstall key is the AppId plus "_is1".
//	installshield An InstallShield (InstallScript) setup: the UninstallString
//	              runs the setup.exe InstallShield caches under
//	              "InstallShield Installation Information".
//	unknown       The entry was examined and none of the above matched, for
//	              example a vendor's own setup.exe or a Squirrel Update.exe.
//
// NSIS is not detected: NSIS writes no fixed key name or value, and the
// "uninstall.exe" its examples use is also used by other installers. Those
// entries report unknown. A package without the qualifier was read by a path
// that cannot see the Uninstall entry's values. Store apps (pkg:appx) never get
// it, their package type already says how they were installed.
const (
	qualifierInstaller = "installer"

	installerMsi           = "msi"
	installerBurn          = "burn"
	installerInno          = "inno"
	installerInstallShield = "installshield"
	installerUnknown       = "unknown"
)

// innoSetupKeySuffix is what Inno Setup appends to the AppId to name the
// Uninstall key.
const innoSetupKeySuffix = "_is1"

// installShieldCacheDir is the directory an InstallShield (InstallScript)
// setup copies itself into to serve as the uninstaller; the UninstallString
// of such an entry runs setup.exe from there.
const installShieldCacheDir = `\installshield installation information\`

// msiUpgradeCodesKey maps every installed MSI product to its UpgradeCode. Each
// subkey is a packed UpgradeCode; its value names are the packed ProductCodes
// of the installed products that share it.
const (
	msiUpgradeCodesKey     = `HKLM\SOFTWARE\Classes\Installer\UpgradeCodes`
	msiUpgradeCodesHiveKey = `Classes\Installer\UpgradeCodes`
)

// installIdentity is what an Uninstall entry says about itself beyond its
// name. Unexported on Package: it only feeds the purl qualifiers.
type installIdentity struct {
	// uninstallKey is the Uninstall subkey's own name.
	uninstallKey string
	// windowsInstaller is the entry's WindowsInstaller=1 flag.
	windowsInstaller bool
	// bundleUpgradeCode is a WiX Burn bundle's BundleUpgradeCode value.
	bundleUpgradeCode string
	// innoSetup records that uninstallKey ended in "_is1", the Inno Setup
	// naming, before the suffix is stripped to form app_id.
	innoSetup bool
	// installShield records that the UninstallString runs InstallShield's
	// cached setup.exe. The command line itself is not kept.
	installShield bool
}

// newInstallIdentity builds the identity of one Uninstall entry from its key
// name and the values the identity rules read.
func newInstallIdentity(keyName string, windowsInstaller bool, bundleUpgradeCode, uninstallString string) *installIdentity {
	return &installIdentity{
		uninstallKey:      keyName,
		windowsInstaller:  windowsInstaller,
		bundleUpgradeCode: bundleUpgradeCode,
		innoSetup:         strings.HasSuffix(keyName, innoSetupKeySuffix),
		installShield:     isInstallShieldUninstall(uninstallString),
	}
}

// isInstallShieldUninstall reports whether an UninstallString runs the setup
// InstallShield cached under "InstallShield Installation Information", e.g.
//
//	"C:\Program Files (x86)\InstallShield Installation Information\{GUID}\setup.exe" -runfromtemp -l0x0409 -removeonly
func isInstallShieldUninstall(uninstallString string) bool {
	return strings.Contains(strings.ToLower(uninstallString), installShieldCacheDir)
}

var guidPattern = regexp.MustCompile(`^\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?$`)

// normalizeGUID returns g as an upper-case GUID without braces, or "" when g is
// not a GUID.
func normalizeGUID(g string) string {
	m := guidPattern.FindStringSubmatch(strings.TrimSpace(g))
	if m == nil {
		return ""
	}
	return strings.ToUpper(m[1])
}

// installIdentityFromItems reads the identity values out of one Uninstall
// subkey's values.
func installIdentityFromItems(keyName string, items []registry.RegistryKeyItem) *installIdentity {
	var windowsInstaller bool
	var bundleUpgradeCode, uninstallString string
	for _, i := range items {
		switch i.Key {
		case "WindowsInstaller":
			windowsInstaller = i.Value.Number == 1
		case "BundleUpgradeCode":
			// REG_MULTI_SZ in WiX 3/4, occasionally REG_SZ.
			if len(i.Value.MultiString) > 0 {
				bundleUpgradeCode = i.Value.MultiString[0]
			} else {
				bundleUpgradeCode = i.Value.String
			}
		case "UninstallString":
			uninstallString = i.Value.String
		}
	}
	return newInstallIdentity(keyName, windowsInstaller, bundleUpgradeCode, uninstallString)
}

// qualifiers returns the identity qualifiers for one entry. upgradeCodes maps a
// normalized ProductCode to its normalized UpgradeCode (msiUpgradeCodesKey).
func (id *installIdentity) qualifiers(upgradeCodes map[string]string) map[string]string {
	if id == nil {
		return nil
	}
	q := map[string]string{}
	if bundle := normalizeGUID(id.bundleUpgradeCode); bundle != "" {
		// A Burn bundle's key is the bundle's per-release provider id; the
		// upgrade code is the stable part, and the bundle has no ProductCode.
		q[qualifierUpgradeCode] = bundle
		q[qualifierInstaller] = installerBurn
		return q
	}
	if id.windowsInstaller {
		if pc := normalizeGUID(id.uninstallKey); pc != "" {
			q[qualifierProductCode] = pc
			if uc := upgradeCodes[pc]; uc != "" {
				q[qualifierUpgradeCode] = uc
			}
			q[qualifierInstaller] = installerMsi
			return q
		}
	}
	switch {
	case id.innoSetup:
		q[qualifierInstaller] = installerInno
	case id.installShield:
		q[qualifierInstaller] = installerInstallShield
	default:
		q[qualifierInstaller] = installerUnknown
	}
	appID := id.uninstallKey
	if id.innoSetup {
		appID = strings.TrimSuffix(appID, innoSetupKeySuffix)
	}
	if g := normalizeGUID(appID); g != "" {
		appID = g
	}
	if appID = strings.TrimSpace(appID); appID != "" {
		q[qualifierAppID] = appID
	}
	return q
}

// unpackMsiGUID turns the packed form Windows Installer uses for registry key
// and value names back into a GUID: each of the first three groups is reversed,
// and each byte of the last two groups has its two hex digits swapped.
//
//	packed 6AE7F01DF7A1F504E9C4E6F8A2D1F35B -> D10F7EA6-1A7F-405F-9E4C-6E8F2A1D3FB5
func unpackMsiGUID(packed string) string {
	if len(packed) != 32 {
		return ""
	}
	for _, r := range packed {
		if !isHexDigit(r) {
			return ""
		}
	}
	rev := func(s string) string {
		b := []byte(s)
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return string(b)
	}
	swapPairs := func(s string) string {
		b := []byte(s)
		for i := 0; i+1 < len(b); i += 2 {
			b[i], b[i+1] = b[i+1], b[i]
		}
		return string(b)
	}
	g := rev(packed[0:8]) + "-" + rev(packed[8:12]) + "-" + rev(packed[12:16]) + "-" +
		swapPairs(packed[16:20]) + "-" + swapPairs(packed[20:32])
	return strings.ToUpper(g)
}

func isHexDigit(r rune) bool {
	return ('0' <= r && r <= '9') || ('a' <= r && r <= 'f') || ('A' <= r && r <= 'F')
}

// msiUpgradeCodesFromKeys builds the ProductCode -> UpgradeCode map from the
// UpgradeCodes key: children lists its subkeys, items reads one subkey's values.
func msiUpgradeCodesFromKeys(children func() ([]registry.RegistryKeyChild, error), items func(child string) ([]registry.RegistryKeyItem, error)) map[string]string {
	out := map[string]string{}
	kids, err := children()
	if err != nil {
		log.Debug().Err(err).Msg("could not read the Windows Installer UpgradeCodes key")
		return out
	}
	for _, k := range kids {
		uc := unpackMsiGUID(k.Name)
		if uc == "" {
			continue
		}
		vals, err := items(k.Name)
		if err != nil {
			continue
		}
		for _, v := range vals {
			if pc := unpackMsiGUID(v.Key); pc != "" {
				out[pc] = uc
			}
		}
	}
	return out
}

// msiUpgradeCodesFromPowershellOutput parses msiUpgradeCodesScript's output.
func msiUpgradeCodesFromPowershellOutput(rows []msiUpgradeCodeRow) map[string]string {
	out := map[string]string{}
	for _, r := range rows {
		uc := unpackMsiGUID(r.U)
		if uc == "" {
			continue
		}
		for _, p := range r.P {
			if pc := unpackMsiGUID(p); pc != "" {
				out[pc] = uc
			}
		}
	}
	return out
}

// msiUpgradeCodeRow is one UpgradeCodes subkey: U is the packed UpgradeCode, P
// the packed ProductCodes listed under it.
type msiUpgradeCodeRow struct {
	U string   `json:"U"`
	P []string `json:"P"`
}

// msiUpgradeCodesScript dumps the UpgradeCodes key for remote connections.
// -InputObject, not a pipe: piping unrolls the array, and Windows PowerShell
// 5.1 then serializes a host with exactly ONE UpgradeCodes subkey as a bare
// object instead of a one-element array. @() on P keeps a subkey with a single
// product a JSON array. An absent key prints nothing.
const msiUpgradeCodesScript = `
$k = 'HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes'
if (Test-Path $k) {
  $rows = @(Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{ U = $_.PSChildName; P = @($_.GetValueNames() | Where-Object { $_ }) }
  })
  ConvertTo-Json -InputObject $rows -Compress -Depth 3
}
`

// applyInstallIdentityQualifiers adds the identity and installer qualifiers to
// every Windows application package that carries an installIdentity, and
// install-scope=user to every one read from a user's registry hive (HKCU or
// HKEY_USERS\<sid>), keeping the qualifiers its purl already has (arch,
// channel, ...). A machine-wide install carries no install-scope, the same as
// on macOS.
//
// It must run AFTER collapsePackages: that collapse keys on the purl, and the
// two Add/Remove Programs entries of one .NET install have different
// ProductCodes, so stamping them first would stop them from collapsing. The
// collapse merges the dropped twin's identity into the survivor
// (absorbPackageAttribution), so nothing is lost by stamping late.
func applyInstallIdentityQualifiers(pkgs []Package, upgradeCodes map[string]string) {
	for i := range pkgs {
		p := &pkgs[i]
		if p.Format != "windows/app" {
			continue
		}
		add := p.installIdentity.qualifiers(upgradeCodes)
		if p.InstallScope == installScopeUser {
			if add == nil {
				add = map[string]string{}
			}
			add[PurlQualifierInstallScope] = InstallScopeUser
		}
		if len(add) == 0 {
			continue
		}
		parsed, err := packageurl.FromString(p.PUrl)
		if err != nil {
			log.Debug().Err(err).Str("purl", p.PUrl).Msg("could not parse package url to add install identity")
			continue
		}
		q := parsed.Qualifiers.Map()
		maps.Copy(q, add)
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		list := make(packageurl.Qualifiers, 0, len(keys))
		for _, k := range keys {
			list = append(list, packageurl.Qualifier{Key: k, Value: q[k]})
		}
		parsed.Qualifiers = list
		p.PUrl = parsed.ToString()
	}
	// Spent: the identity now lives in the purl.
	for i := range pkgs {
		pkgs[i].installIdentity = nil
	}
}

// mergeInstallIdentity decides the identity of a row collapsePackages keeps
// when it folds a duplicate into it. The two rows of one .NET install are an
// MSI entry and a Burn bundle entry; the MSI entry's identity (ProductCode plus
// the product line's UpgradeCode) is the more precise one, so it wins whichever
// row arrived first. Otherwise the survivor keeps its own.
func mergeInstallIdentity(keep *Package, dup Package) {
	if dup.installIdentity == nil {
		return
	}
	isMsi := func(id *installIdentity) bool {
		return id != nil && id.windowsInstaller && normalizeGUID(id.uninstallKey) != ""
	}
	if keep.installIdentity == nil || (!isMsi(keep.installIdentity) && isMsi(dup.installIdentity)) {
		c := *dup.installIdentity
		keep.installIdentity = &c
	}
}

// withInstallIdentity stamps the identity qualifiers on the final, collapsed
// package list. See applyInstallIdentityQualifiers for why it runs last.
func (w *WinPkgManager) withInstallIdentity(pkgs []Package) []Package {
	applyInstallIdentityQualifiers(pkgs, w.msiUpgradeCodes)
	return pkgs
}

// msiUpgradeCodesRemote reads the UpgradeCodes key over the connection, only
// when pkgs holds an MSI entry: hosts without one never pay for the extra
// PowerShell run. A failure is logged and leaves packages with their
// product_code alone, the same best-effort policy as the Omaha probe.
func (w *WinPkgManager) msiUpgradeCodesRemote(pkgs []Package) map[string]string {
	hasMsi := false
	for i := range pkgs {
		if id := pkgs[i].installIdentity; id != nil && id.windowsInstaller {
			hasMsi = true
			break
		}
	}
	if !hasMsi {
		return nil
	}
	cmd, err := w.conn.RunCommand(powershell.Encode(msiUpgradeCodesScript))
	if err != nil {
		log.Debug().Err(err).Msg("could not read the Windows Installer UpgradeCodes key")
		return nil
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	rows, err := parseMsiUpgradeCodeRows(data)
	if err != nil {
		log.Debug().Err(err).Msg("could not parse the Windows Installer UpgradeCodes key")
		return nil
	}
	return msiUpgradeCodesFromPowershellOutput(rows)
}

// parseMsiUpgradeCodeRows accepts msiUpgradeCodesScript's array, and also a
// single bare object: that is what ConvertTo-Json emits for one element when
// the array reaches it through a pipe, which the script avoids but an older
// copy of it, or another PowerShell, may not.
func parseMsiUpgradeCodeRows(data []byte) ([]msiUpgradeCodeRow, error) {
	var rows []msiUpgradeCodeRow
	if err := json.Unmarshal(data, &rows); err == nil {
		return rows, nil
	}
	var one msiUpgradeCodeRow
	if err := json.Unmarshal(data, &one); err != nil {
		return nil, err
	}
	return []msiUpgradeCodeRow{one}, nil
}

// firstJSONString returns a PowerShell-serialized registry value as one
// string: the first element of an array (REG_MULTI_SZ), a bare string, or ""
// for null and anything else.
func firstJSONString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		if len(list) > 0 {
			return list[0]
		}
		return ""
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one
	}
	return ""
}
