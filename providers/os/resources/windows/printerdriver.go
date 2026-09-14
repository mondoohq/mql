// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/purl"
)

// PrinterDriversScript enumerates the print drivers installed on the machine.
//
// Get-PrinterDriver reports drivers registered with the spooler, which is what
// actually runs them — as opposed to the Add/Remove Programs list, where only
// vendor bundles that shipped an installer appear. A driver delivered as an
// INF/CAB package lands in the driver store and has no uninstall entry at all,
// so enumerating software would miss it entirely.
//
// -ErrorAction SilentlyContinue: the cmdlet is unavailable on Server Core
// installations without the printing feature, and a machine with no drivers is
// a normal state rather than a failure.
//
// ConvertTo-Json is forced to a list with @(): PowerShell serializes a single
// object as an object rather than a one-element array, which would otherwise
// need two parse paths.
const PrinterDriversScript = `
@(Get-PrinterDriver -ErrorAction SilentlyContinue | Select-Object -Property Name,PrinterEnvironment,Manufacturer,DriverVersion,MajorVersion,HardwareID,InfPath,ConfigFile,DataFile,DriverPath,PrintProcessor) | ConvertTo-Json -Compress
`

// PrinterDriver is one driver as the spooler reports it.
type PrinterDriver struct {
	Name string `json:"Name"`
	// PrinterEnvironment is the architecture the driver is registered under,
	// e.g. "Windows x64".
	PrinterEnvironment string `json:"PrinterEnvironment"`
	Manufacturer       string `json:"Manufacturer"`
	// DriverVersion is Windows' packed 64-bit version. See DottedVersion.
	DriverVersion uint64 `json:"DriverVersion"`
	// MajorVersion is the driver MODEL version (2, 3, 4) — the spooler
	// interface generation, not the vendor's release number.
	MajorVersion int64 `json:"MajorVersion"`
	// HardwareID is the identifier the vendor declares in the driver's INF.
	// Unlike Name it does not change between releases — Windows uses it to rank
	// and upgrade drivers, so a vendor that changed it would break updates for
	// every existing installation. See Purl.
	HardwareID     string `json:"HardwareID"`
	InfPath        string `json:"InfPath"`
	ConfigFile     string `json:"ConfigFile"`
	DataFile       string `json:"DataFile"`
	DriverPath     string `json:"DriverPath"`
	PrintProcessor string `json:"PrintProcessor"`
}

// DottedVersion renders DriverVersion the way a vendor writes it.
//
// Windows packs a driver version into one 64-bit integer as four 16-bit fields,
// most significant first, so the raw value is unreadable on its own:
//
//	1688862492857958400  ->  6.0.24328.0
//
// Vendors publish and advise on the dotted form ("Ver.3.0.0.0"), so a caller
// comparing against vendor documentation needs this rather than the packed
// integer. Both are exposed, because the packed value is what the spooler
// actually stores and is the one to use when comparing two drivers exactly.
func (d PrinterDriver) DottedVersion() string {
	if d.DriverVersion == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		(d.DriverVersion>>48)&0xFFFF,
		(d.DriverVersion>>32)&0xFFFF,
		(d.DriverVersion>>16)&0xFFFF,
		d.DriverVersion&0xFFFF,
	)
}

// ParsePrinterDrivers reads the script's output.
//
// An empty document is not an error: a machine with the spooler stopped, or
// with no drivers installed, legitimately reports nothing.
func ParsePrinterDrivers(r io.Reader) ([]PrinterDriver, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return []PrinterDriver{}, nil
	}

	// DriverVersion arrives as a JSON number large enough to lose precision in
	// a float, and PowerShell occasionally emits it as a string. Decode into
	// json.Number and convert explicitly rather than letting either happen
	// silently.
	var raw []struct {
		PrinterDriver
		DriverVersion json.Number `json:"DriverVersion"`
		MajorVersion  json.Number `json:"MajorVersion"`
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, errors.New("failed to parse printer drivers: " + err.Error())
	}

	out := make([]PrinterDriver, 0, len(raw))
	for _, r := range raw {
		d := r.PrinterDriver
		if v, err := strconv.ParseUint(r.DriverVersion.String(), 10, 64); err == nil {
			d.DriverVersion = v
		}
		if v, err := strconv.ParseInt(r.MajorVersion.String(), 10, 64); err == nil {
			d.MajorVersion = v
		}
		out = append(out, d)
	}
	return out, nil
}

// purlToken reduces a driver or vendor string to a PURL token: lowercase, with
// anything outside [a-z0-9.+] folded to a single "-".
//
// The same normalisation both sides of a match must agree on, so it is written
// once here rather than at each call site.
func purlToken(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '+':
			b.WriteRune(r)
			dash = false
		default:
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	// Trailing punctuation is never part of a name. A "." survives the loop
	// because it is a legal token character mid-string ("Ver.3.0"), but
	// "Ricoh Company, Ltd." would otherwise end "-ltd." and miss the suffix
	// list below.
	return strings.Trim(b.String(), "-.")
}

// vendorSuffixes are the corporate suffixes a driver's Manufacturer carries
// that its advisories do not: "Ricoh Company, Ltd." and "RICOH" have to reach
// the same token.
var vendorSuffixes = []string{
	"-company-ltd", "-company-limited", "-co-ltd", "-corporation", "-corp",
	"-industries-ltd", "-industries", "-inc", "-ltd", "-gmbh", "-kk",
}

// VendorToken reduces a driver's Manufacturer to the vendor namespace.
func VendorToken(manufacturer string) string {
	token := purlToken(manufacturer)
	for _, suffix := range vendorSuffixes {
		if strings.HasSuffix(token, suffix) {
			token = strings.TrimSuffix(token, suffix)
			break
		}
	}
	return strings.Trim(token, "-")
}

// releaseSuffixPattern matches a release number a vendor appends to a driver
// name: the "V4.34" in "RICOH PCL6 UniversalDriver V4.34".
//
// Anchored to the END of the string, which is the whole point. Real driver
// names carry "V4" in two different roles:
//
//	RICOH PCL6 UniversalDriver V4.34    V4.34 is the release      -> strip
//	RICOH PCL6 V4 UniversalDriver V2.0  V4 is the driver MODEL    -> keep
//
// Anchoring separates them without knowing anything about either.
var releaseSuffixPattern = regexp.MustCompile(`(?i)\s+v?\d+(?:\.\d+)+\s*$`)

// driverNameToken reduces a driver Name to a token that survives an update.
//
// Strips a leading vendor word and a trailing release, because a name carrying
// its own release number changes with every driver update and so cannot be an
// identity. Used only when HardwareID is unavailable — see Purl.
func driverNameToken(name, manufacturer string) string {
	name = releaseSuffixPattern.ReplaceAllString(strings.TrimSpace(name), "")

	// Drop a leading vendor word ("RICOH PCL6 …" -> "PCL6 …") so the token does
	// not repeat the namespace it already sits in.
	if vendor := VendorToken(manufacturer); vendor != "" {
		if fields := strings.Fields(name); len(fields) > 1 && purlToken(fields[0]) == vendor {
			name = strings.Join(fields[1:], " ")
		}
	}
	return purlToken(name)
}

// Purl is the package URL identifying this driver, empty when it cannot be
// identified.
//
// # The identity is HardwareID, not Name
//
// The name the spooler reports carries the driver's own release number, so it
// changes with every update. The hardware ID does not. Two published Ricoh
// universal-print-driver packages, 2.3 years and nine minor versions apart,
// declare the same one:
//
//	4.12.0.0 (2016)  "RICOH PCL6 UniversalDriver V4.12"  RICOHPCL6DriveforUP
//	4.21.0.0 (2019)  "RICOH PCL6 UniversalDriver V4.21"  RICOHPCL6DriveforUP
//
// So a PURL keyed on the name identifies a release, while one keyed on the
// hardware ID identifies the product — which is what anything tracking a
// driver across upgrades needs.
//
// Name is left exactly as the spooler reported it; only the identity is
// canonicalised.
//
// # Fallback
//
// A driver with no hardware ID falls back to the name with its vendor prefix
// and trailing release removed. That is a degraded identity: it is stable
// across releases but not across a vendor rewording its product.
//
// # Why an empty result rather than a partial one
//
// Returns nothing when the manufacturer or the token is missing. A vendor-less
// driver PURL would match whatever advisory happened to carry the same driver
// name, and driver names are emphatically not unique across vendors — every
// printer vendor ships something called "PCL 6 Driver" — so guessing here
// attaches one vendor's vulnerability to another vendor's driver.
func (d PrinterDriver) Purl() string {
	vendor := VendorToken(d.Manufacturer)
	if vendor == "" {
		return ""
	}

	name := purlToken(d.HardwareID)
	if name == "" {
		name = driverNameToken(d.Name, d.Manufacturer)
	}
	if name == "" {
		return ""
	}

	// Rendered through the purl encoder rather than concatenated. purlToken
	// already leaves nothing that needs escaping, but that is a property of the
	// tokeniser rather than something this function enforces, and this is the
	// only producer of pkg:windows-driver -- so the encoding stays in one place
	// with every other purl mql emits.
	return purl.NewPackageURL(nil, purl.TypeWindowsDriver, name, d.DottedVersion(),
		purl.WithNamespace(vendor),
	).String()
}
