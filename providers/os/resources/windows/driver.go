// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// DriversScript enumerates the kernel and file system drivers registered with
// the service control manager, and reports the Authenticode verdict on each
// driver image.
//
// Win32_SystemDriver is the spine rather than the driver store, because it
// lists what the SCM will actually load. A driver present in the store but not
// registered cannot run, and a registered driver whose image was deleted still
// holds a service entry worth reporting.
//
// PathName arrives in NT form and has to be resolved before the image can be
// read: "\??\C:\Windows\system32\drivers\foo.sys", "\SystemRoot\System32\..."
// and a bare "system32\..." are all in normal use. Drivers registered with no
// path at all fall back to the conventional drivers\<name>.sys location, which
// is where the SCM itself looks.
//
// Resolution happens here rather than in Go because the signature and version
// lookups below need the resolved path anyway; returning it keeps one
// implementation instead of two that can disagree.
//
// ConvertTo-Json is forced to a list with @(): PowerShell serializes a single
// object as an object rather than a one-element array, which would otherwise
// need two parse paths.
const DriversScript = `
$ErrorActionPreference = 'SilentlyContinue'
@(Get-CimInstance -ClassName Win32_SystemDriver | ForEach-Object {
  $p = $_.PathName
  if ($p) {
    $p = $p -replace '^\\\?\?\\', ''
    $p = $p -replace '^\\SystemRoot\\', ($env:SystemRoot + '\')
    if ($p -match '^[Ss]ystem32\\') { $p = Join-Path $env:SystemRoot $p }
  } elseif ($_.Name) {
    $p = Join-Path $env:SystemRoot ('System32\drivers\' + $_.Name + '.sys')
  }
  $ver = $null; $mfr = $null; $signed = $null; $signer = $null
  if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) {
    $vi = (Get-Item -LiteralPath $p).VersionInfo
    if ($vi) { $ver = $vi.FileVersion; $mfr = $vi.CompanyName }
    $sig = Get-AuthenticodeSignature -LiteralPath $p
    if ($sig -and $sig.Status -ne 'UnknownError') {
      $signed = ($sig.Status -eq 'Valid')
      if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
    }
  }
  [PSCustomObject]@{
    Name = $_.Name; DisplayName = $_.DisplayName; Description = $_.Description
    Path = $p; ServiceType = $_.ServiceType; StartMode = $_.StartMode
    Started = $_.Started; Version = $ver; Manufacturer = $mfr
    Signed = $signed; Signer = $signer
  }
}) | ConvertTo-Json -Compress -Depth 3
`

// Driver is one kernel or file system driver as the SCM reports it.
type Driver struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	Description string `json:"Description"`
	// Path is the resolved absolute path of the driver image. Empty only when
	// the driver is registered under no name and no path.
	Path string `json:"Path"`
	// ServiceType is "Kernel Driver" or "File System Driver".
	ServiceType string `json:"ServiceType"`
	// StartMode is one of Boot, System, Auto, Manual, Disabled.
	StartMode string `json:"StartMode"`
	Started   bool   `json:"Started"`
	// Version is the file version recorded in the image, e.g. "10.0.26100.1150".
	Version string `json:"Version"`
	// Manufacturer is the CompanyName recorded in the image. It is the vendor
	// namespace Purl is keyed on.
	Manufacturer string `json:"Manufacturer"`
	// Signed is nil when no Authenticode verdict could be reached, which is not
	// the same as false. A deleted image or an unreadable certificate store
	// leaves the question unanswered, and reporting that as "unsigned" would
	// invent a finding.
	Signed *bool `json:"Signed"`
	// Signer is the full subject DN of the signing certificate. See SignerCommonName.
	Signer string `json:"Signer"`
}

// ParseDrivers reads the script's output.
//
// An empty document is not an error: a target where the CIM query returned
// nothing legitimately reports no drivers.
func ParseDrivers(r io.Reader) ([]Driver, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return []Driver{}, nil
	}

	var drivers []Driver
	if err := json.Unmarshal([]byte(trimmed), &drivers); err != nil {
		return nil, errors.New("failed to parse drivers: " + err.Error())
	}
	return drivers, nil
}

// SignerCommonName extracts the CN from a certificate subject DN.
//
// Get-AuthenticodeSignature reports the full subject, which is unreadable in a
// report and useless for grouping:
//
//	CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
//
// Only the CN identifies the signer. Splitting on "," does not work, because a
// CN legitimately contains one and the DN then quotes it:
//
//	CN="Ricoh Company, Ltd.", O=...
//
// so a naive split reports "Ricoh Company" and silently drops the rest. Both
// forms are handled here.
//
// Returns an empty string when the subject carries no CN, rather than falling
// back to the whole DN, so a caller can tell "no signer" from "some signer".
func SignerCommonName(subject string) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return ""
	}

	// Find CN= at the start of a DN component, not inside a value.
	idx := -1
	for i := 0; i+3 <= len(subject); i++ {
		if !strings.EqualFold(subject[i:i+3], "cn=") {
			continue
		}
		if i == 0 || subject[i-1] == ',' || subject[i-1] == ' ' {
			idx = i + 3
			break
		}
	}
	if idx < 0 {
		return ""
	}

	rest := subject[idx:]
	if strings.HasPrefix(rest, `"`) {
		// Quoted: the value runs to the closing quote, commas included.
		if end := strings.Index(rest[1:], `"`); end >= 0 {
			return strings.TrimSpace(rest[1 : 1+end])
		}
		return strings.TrimSpace(strings.Trim(rest, `"`))
	}
	if end := strings.Index(rest, ","); end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimSpace(rest)
}

// Purl is the package URL identifying this driver, empty when it cannot be
// identified.
//
// Uses the same pkg:windows-driver namespace as PrinterDriver.Purl, so a
// vulnerability feed matches both kinds of driver the same way, and the vendor
// token goes through the same VendorToken normalisation, so "Microsoft
// Corporation" on a system driver and "Microsoft" on a print driver reach the
// same namespace.
//
// A system driver has no hardware ID to key on, so the service name is the
// identity. Unlike a print driver name it does not carry a release number: the
// SCM keys the service by it, so a vendor changing it between releases would
// orphan the existing registration.
//
// Returns nothing when the image records no company name. A vendor-less driver
// PURL would match whatever advisory happened to carry the same driver name,
// and driver names are not unique across vendors.
func (d Driver) Purl() string {
	vendor := VendorToken(d.Manufacturer)
	if vendor == "" {
		return ""
	}
	name := purlToken(d.Name)
	if name == "" {
		return ""
	}

	p := "pkg:windows-driver/" + vendor + "/" + name
	if v := versionToken(d.Version); v != "" {
		p += "@" + v
	}
	return p
}

// versionToken reduces a FileVersion to the dotted release it identifies.
//
// Windows FileVersion routinely carries a build tag after the version proper:
//
//	10.0.26100.1150 (WinBuild.160101.0800)
//
// Only the dotted part names the release, and the tag is identical across
// every Microsoft driver on the machine, so leaving it in produces a PURL that
// no advisory matches. Version is still reported raw on the resource; only the
// identity is canonicalised.
func versionToken(version string) string {
	v := strings.TrimSpace(version)
	if i := strings.IndexAny(v, " \t"); i >= 0 {
		v = v[:i]
	}
	return purlToken(v)
}
