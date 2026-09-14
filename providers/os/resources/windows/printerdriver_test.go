// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

// The fixture mirrors what Get-PrinterDriver | ConvertTo-Json emits: a packed
// 64-bit DriverVersion, the driver MODEL version in MajorVersion, and the INF
// the package was installed from.
const printerDriverJSON = `[
{"Name":"Microsoft Print To PDF","PrinterEnvironment":"Windows x64","Manufacturer":"Microsoft","DriverVersion":1688862492857958400,"MajorVersion":4,"InfPath":"C:\\Windows\\System32\\DriverStore\\FileRepository\\prnms009.inf_amd64_9d4f8b8bd0e4e0d5\\prnms009.inf","ConfigFile":"","DataFile":"C:\\Windows\\system32\\spool\\drivers\\x64\\3\\PrintToPDF.dll","DriverPath":"C:\\Windows\\system32\\spool\\drivers\\x64\\3\\mxdwdrv.dll","PrintProcessor":"winprint"},
{"Name":"Brother HL-L2375DW series","PrinterEnvironment":"Windows x64","Manufacturer":"Brother","DriverVersion":844433520133734400,"MajorVersion":3,"InfPath":"C:\\Windows\\System32\\DriverStore\\FileRepository\\brpom19a.inf_amd64_1a2b3c\\brpom19a.inf","ConfigFile":"BRPOM19A.DLL","DataFile":"BROM19A.DAT","DriverPath":"BRPRM19A.DLL","PrintProcessor":"winprint"}
]`

func TestParsePrinterDrivers(t *testing.T) {
	drivers, err := ParsePrinterDrivers(strings.NewReader(printerDriverJSON))
	require.NoError(t, err)
	require.Len(t, drivers, 2)

	assert.Equal(t, "Microsoft Print To PDF", drivers[0].Name)
	assert.Equal(t, "Windows x64", drivers[0].PrinterEnvironment)
	assert.Equal(t, int64(4), drivers[0].MajorVersion, "the driver MODEL version, not the vendor's release")
	assert.Contains(t, drivers[0].InfPath, "DriverStore")

	assert.Equal(t, "Brother", drivers[1].Manufacturer)
	assert.Equal(t, uint64(844433520133734400), drivers[1].DriverVersion,
		"the packed version must survive as an integer, not lose precision through a float")
}

// TestDottedVersionUnpacksTheWindowsEncoding: Windows packs a driver version
// into one 64-bit integer as four 16-bit fields, most significant first, so the
// raw value is meaningless on its own. Vendors publish the dotted form.
// packed builds Windows' packed 64-bit driver version from its four fields.
//
// Written as a helper rather than inline: an inline "a<<48 | 0<<32 | c<<16 | 0"
// reads as documenting all four positions but the zero terms are no-ops, which
// staticcheck rightly flags as a mistake waiting to happen.
func packed(a, b, c, d uint64) uint64 {
	return a<<48 | b<<32 | c<<16 | d
}

func TestDottedVersionUnpacksTheWindowsEncoding(t *testing.T) {
	for _, tc := range []struct {
		packed uint64
		want   string
	}{
		{packed(6, 0, 24328, 0), "6.0.24328.0"},
		// The shape a printer vendor advises on ("Ver.3.0.0.0").
		{packed(3, 0, 0, 0), "3.0.0.0"},
		// Every field distinct, so a transposed shift is caught.
		{packed(1, 2, 3, 4), "1.2.3.4"},
		// The widest each field goes.
		{packed(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF), "65535.65535.65535.65535"},
		// The high bit set: the value exceeds what a signed 64-bit integer can
		// hold, which is why this is exposed as a dotted string rather than as
		// a packed number.
		{packed(0x8000, 0, 0, 1), "32768.0.0.1"},
	} {
		assert.Equal(t, tc.want, PrinterDriver{DriverVersion: tc.packed}.DottedVersion())
	}

	// Absent rather than "0.0.0.0": a driver with no version reported must not
	// look like a real version zero.
	assert.Empty(t, PrinterDriver{}.DottedVersion())
}

// TestParsePrinterDriversHandlesAnEmptyMachine: the spooler stopped, or no
// drivers installed, is a normal state and not a failure.
func TestParsePrinterDriversHandlesAnEmptyMachine(t *testing.T) {
	for _, in := range []string{"", "   ", "null"} {
		drivers, err := ParsePrinterDrivers(strings.NewReader(in))
		require.NoError(t, err, "input %q", in)
		assert.Empty(t, drivers)
	}
}

// TestParsePrinterDriversAcceptsAStringVersion: PowerShell sometimes serializes
// a large integer as a string. Both must decode to the same value.
func TestParsePrinterDriversAcceptsAStringVersion(t *testing.T) {
	drivers, err := ParsePrinterDrivers(strings.NewReader(
		`[{"Name":"x","DriverVersion":"844433520133734400","MajorVersion":"3"}]`))
	require.NoError(t, err)
	require.Len(t, drivers, 1)
	assert.Equal(t, uint64(844433520133734400), drivers[0].DriverVersion)
	assert.Equal(t, int64(3), drivers[0].MajorVersion)
}

// TestPurlKeepsVendorsApart is the reason the vendor is the namespace.
//
// Driver names are NOT unique across vendors: "PCL 6 Driver" and
// "PostScript3 Driver" name page description languages that every printer
// vendor ships a driver for. Keying on the name alone would match one vendor's
// advisory against another vendor's driver.
func TestPurlKeepsVendorsApart(t *testing.T) {
	ricoh := PrinterDriver{Name: "PCL 6 Driver", Manufacturer: "RICOH", DriverVersion: 3 << 48}
	brother := PrinterDriver{Name: "PCL 6 Driver", Manufacturer: "Brother", DriverVersion: 3 << 48}

	assert.Equal(t, "pkg:windows-driver/ricoh/pcl-6-driver@3.0.0.0", ricoh.Purl())
	assert.Equal(t, "pkg:windows-driver/brother/pcl-6-driver@3.0.0.0", brother.Purl())
	assert.NotEqual(t, ricoh.Purl(), brother.Purl(), "same driver name, different vendors")
}

// TestVendorTokenNormalisesCorporateSuffixes: the spooler reports the
// manufacturer as the INF spells it, which carries corporate suffixes the
// vendor's advisories do not.
func TestVendorTokenNormalisesCorporateSuffixes(t *testing.T) {
	for _, in := range []string{"RICOH", "Ricoh", "Ricoh Company, Ltd.", "RICOH COMPANY, LTD."} {
		assert.Equal(t, "ricoh", VendorToken(in), "input %q", in)
	}
	for _, in := range []string{"Brother", "Brother Industries, Ltd", "brother industries"} {
		assert.Equal(t, "brother", VendorToken(in), "input %q", in)
	}
	assert.Equal(t, "konica-minolta", VendorToken("Konica Minolta, Inc."))
}

// TestPurlRefusesAPartialIdentity: a vendor-less driver PURL would match
// whatever advisory carried the same driver name, so an unidentifiable driver
// yields nothing at all.
func TestPurlRefusesAPartialIdentity(t *testing.T) {
	assert.Empty(t, PrinterDriver{Name: "PCL 6 Driver"}.Purl(), "no manufacturer")
	assert.Empty(t, PrinterDriver{Manufacturer: "RICOH"}.Purl(), "no name")
	assert.Empty(t, PrinterDriver{Name: "  ", Manufacturer: "  "}.Purl())

	// A driver with no version is still identifiable; the PURL simply carries
	// no version, and an unversioned package cannot match a bounded advisory.
	assert.Equal(t, "pkg:windows-driver/ricoh/lan-fax-driver",
		PrinterDriver{Name: "LAN Fax Driver", Manufacturer: "RICOH"}.Purl())
}

// TestPurlOnRealVendorDriverNames uses the names Ricoh publishes in its own
// advisories, which are what the catalog rows have to line up with.
func TestPurlOnRealVendorDriverNames(t *testing.T) {
	for name, want := range map[string]string{
		"PostScript3 Driver":                 "pkg:windows-driver/ricoh/postscript3-driver",
		"PCL 6 Driver":                       "pkg:windows-driver/ricoh/pcl-6-driver",
		"PS Driver for Universal Print":      "pkg:windows-driver/ricoh/ps-driver-for-universal-print",
		"PCL6 Driver for Universal Print":    "pkg:windows-driver/ricoh/pcl6-driver-for-universal-print",
		"PCL6 V4 Driver for Universal Print": "pkg:windows-driver/ricoh/pcl6-v4-driver-for-universal-print",
		"LAN Fax Driver":                     "pkg:windows-driver/ricoh/lan-fax-driver",
		"Generic PCL5 Driver":                "pkg:windows-driver/ricoh/generic-pcl5-driver",
	} {
		got := PrinterDriver{Name: name, Manufacturer: "RICOH"}.Purl()
		assert.Equal(t, want, got, "name %q", name)
	}
}

// TestPurlIsKeyedOnTheHardwareID is the property the whole identity rests on:
// a driver keeps the same PURL across an update.
//
// Both rows are real. Two published Ricoh universal-print-driver packages, 2.3
// years and nine minor versions apart, register a NAME carrying their own
// release while declaring the SAME hardware ID in their INF:
//
//	oemsetup.inf DriverVer 11/07/2016,4.12.0.0 -> "RICOH PCL6 UniversalDriver V4.12"
//	oemsetup.inf DriverVer 01/28/2019,4.21.0.0 -> "RICOH PCL6 UniversalDriver V4.21"
//	both: USBPRINT\RICOHPCL6DriveforUP, LPTENUM\RICOHPCL6DriveforUP, RICOHPCL6DriveforUP
//
// Keyed on the name these are two different packages; keyed on the hardware ID
// they are one product at two versions, which is what an upgrade actually is.
func TestPurlIsKeyedOnTheHardwareID(t *testing.T) {
	v412 := PrinterDriver{
		Name:          "RICOH PCL6 UniversalDriver V4.12",
		Manufacturer:  "RICOH",
		HardwareID:    "RICOHPCL6DriveforUP",
		DriverVersion: packed(4, 12, 0, 0),
	}
	v421 := PrinterDriver{
		Name:          "RICOH PCL6 UniversalDriver V4.21",
		Manufacturer:  "RICOH",
		HardwareID:    "RICOHPCL6DriveforUP",
		DriverVersion: packed(4, 21, 0, 0),
	}

	assert.Equal(t, "pkg:windows-driver/ricoh/ricohpcl6driveforup@4.12.0.0", v412.Purl())
	assert.Equal(t, "pkg:windows-driver/ricoh/ricohpcl6driveforup@4.21.0.0", v421.Purl())

	// The identity is the same across the upgrade; only the version moves.
	assert.Equal(t, purlWithoutVersion(v412.Purl()), purlWithoutVersion(v421.Purl()),
		"an update must not change the driver's identity")
}

// TestPurlFallsBackToTheNameWithoutAHardwareID. Some drivers report none, and a
// degraded identity beats no finding — but it must at least survive an update,
// so the release is stripped from the name.
func TestPurlFallsBackToTheNameWithoutAHardwareID(t *testing.T) {
	v412 := PrinterDriver{Name: "RICOH PCL6 UniversalDriver V4.12", Manufacturer: "RICOH", DriverVersion: packed(4, 12, 0, 0)}
	v421 := PrinterDriver{Name: "RICOH PCL6 UniversalDriver V4.21", Manufacturer: "RICOH", DriverVersion: packed(4, 21, 0, 0)}

	assert.Equal(t, "pkg:windows-driver/ricoh/pcl6-universaldriver@4.12.0.0", v412.Purl())
	assert.Equal(t, "pkg:windows-driver/ricoh/pcl6-universaldriver@4.21.0.0", v421.Purl())
	assert.Equal(t, purlWithoutVersion(v412.Purl()), purlWithoutVersion(v421.Purl()))
}

// TestDriverNameTokenKeepsTheModelVersion is the trap the trailing anchor
// exists for. Both names contain "V4", in different roles:
//
//	RICOH PCL6 UniversalDriver V4.34    V4.34 is the release   -> stripped
//	RICOH PCL6 V4 UniversalDriver V2.0  V4 is the driver MODEL -> kept
//
// Stripping "V4" from the second would merge two different products, which
// have different advisories and different bounds.
func TestDriverNameTokenKeepsTheModelVersion(t *testing.T) {
	assert.Equal(t, "pcl6-universaldriver",
		driverNameToken("RICOH PCL6 UniversalDriver V4.34", "RICOH"))
	assert.Equal(t, "pcl6-v4-universaldriver",
		driverNameToken("RICOH PCL6 V4 UniversalDriver V2.0", "RICOH"))
	assert.NotEqual(t,
		driverNameToken("RICOH PCL6 UniversalDriver V4.34", "RICOH"),
		driverNameToken("RICOH PCL6 V4 UniversalDriver V2.0", "RICOH"))

	// A name with no release suffix is unchanged apart from the vendor prefix.
	assert.Equal(t, "ps-universaldriver", driverNameToken("RICOH PS UniversalDriver", "RICOH"))

	// The leading word is dropped only when it IS the manufacturer, since the
	// vendor already forms the PURL namespace and repeating it says nothing.
	assert.Equal(t, "print-to-pdf", driverNameToken("Microsoft Print To PDF", "Microsoft Corp"))
	// A different vendor's name in the string is part of the product, not a
	// prefix: dropping it would merge unrelated drivers under one identity.
	assert.Equal(t, "hp-laserjet-driver", driverNameToken("HP LaserJet Driver", "RICOH"))
}

// TestPurlOnCapturedWindowsDrivers uses the four drivers a real Windows 11 host
// reported, verbatim, including the GUID hardware IDs Microsoft's class drivers
// declare. A GUID is as stable an identity as a vendor string.
func TestPurlOnCapturedWindowsDrivers(t *testing.T) {
	for _, tc := range []struct{ name, hwid, want string }{
		{"Universal Print Class Driver", "{6d170653-5280-44c2-ba44-2c04bc9d46da}", "pkg:windows-driver/microsoft/6d170653-5280-44c2-ba44-2c04bc9d46da"},
		{"Microsoft Print To PDF", "{084f01fa-e634-4d77-83ee-074817c03581}", "pkg:windows-driver/microsoft/084f01fa-e634-4d77-83ee-074817c03581"},
	} {
		d := PrinterDriver{Name: tc.name, Manufacturer: "Microsoft", HardwareID: tc.hwid}
		assert.Equal(t, tc.want, d.Purl(), "driver %q", tc.name)
	}
}

// TestPurlIsAParseablePurl pins the invariant that lets this PURL be rendered
// at all: purlToken leaves nothing that needs percent-encoding, so no vendor
// or driver string can break out of its own component.
//
// Related to https://github.com/mondoohq/mql/issues/10636 (4). This is the only
// producer of pkg:windows-driver, and it used to assemble the string by
// concatenation, so nothing checked what a token could smuggle in. A hardware
// ID is the realistic carrier: PnP IDs are full of "&" and backslashes, and an
// unescaped "&" is exactly what splits one qualifier into two.
func TestPurlIsAParseablePurl(t *testing.T) {
	for _, d := range []PrinterDriver{
		{Name: "PCL 6 Driver", Manufacturer: "RICOH", HardwareID: `PCI\VEN_8086&DEV_1234&SUBSYS_0001`, DriverVersion: 3 << 48},
		{Name: "Drucker & Fax Treiber", Manufacturer: "Brother Industries, Ltd", DriverVersion: 3 << 48},
		{Name: "PCL 6 Driver", Manufacturer: "Kyocera Document Solutions, Inc. (日本)", DriverVersion: 3 << 48},
		{Name: "Universal Print Class Driver", Manufacturer: "Microsoft", HardwareID: "{6d170653-5280-44c2-ba44-2c04bc9d46da}"},
	} {
		rendered := d.Purl()
		require.NotEmpty(t, rendered, "driver %q", d.Name)

		assert.NotContains(t, rendered, "%",
			"a driver PURL must never need percent-encoding: %q", rendered)

		parsed, err := packageurl.FromString(rendered)
		require.NoError(t, err, "PURL %q must parse", rendered)
		assert.Equal(t, string(purl.TypeWindowsDriver), parsed.Type)
		assert.NotEmpty(t, parsed.Namespace, "the vendor namespace must survive: %q", rendered)
		assert.NotEmpty(t, parsed.Name)
		assert.Empty(t, parsed.Qualifiers,
			"a driver PURL carries no qualifiers, so nothing may have leaked into one: %q", rendered)
		assert.Equal(t, rendered, parsed.ToString(),
			"the rendered PURL must already be in canonical form")
	}
}

// purlWithoutVersion drops the @version so two releases can be compared on
// identity alone.
func purlWithoutVersion(p string) string {
	if i := strings.LastIndex(p, "@"); i > 0 {
		return p[:i]
	}
	return p
}
