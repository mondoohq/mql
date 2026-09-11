// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// driversJSON is the shape ConvertTo-Json produces for DriversScript. Written
// by hand from the Win32_SystemDriver field set rather than captured from a
// run, so that it cannot agree with the decoder by construction.
//
// The three records cover the states that decode differently: a signed inbox
// driver, a third-party driver measured as unsigned, and a registered driver
// whose image is gone so no verdict was reached.
const driversJSON = `[
 {"Name":"storahci","DisplayName":"Microsoft Standard SATA AHCI Driver","Description":"Microsoft Standard SATA AHCI Driver",
  "Path":"C:\\Windows\\System32\\drivers\\storahci.sys","ServiceType":"Kernel Driver","StartMode":"Boot","Started":true,
  "Version":"10.0.26100.1150 (WinBuild.160101.0800)","Manufacturer":"Microsoft Corporation",
  "Signed":true,"Signer":"CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"},
 {"Name":"vulndrv","DisplayName":"Vuln Kernel Helper","Description":"",
  "Path":"C:\\Windows\\System32\\drivers\\vulndrv.sys","ServiceType":"Kernel Driver","StartMode":"Manual","Started":false,
  "Version":"1.0.0.4","Manufacturer":"Ricoh Company, Ltd.","Signed":false,"Signer":null},
 {"Name":"ghostdrv","DisplayName":"Ghost Filter","Description":"",
  "Path":"C:\\Windows\\System32\\drivers\\ghostdrv.sys","ServiceType":"File System Driver","StartMode":"Disabled","Started":false,
  "Version":null,"Manufacturer":null,"Signed":null,"Signer":null}
]`

func TestParseDrivers(t *testing.T) {
	drivers, err := ParseDrivers(strings.NewReader(driversJSON))
	require.NoError(t, err)
	require.Len(t, drivers, 3)

	// Every field read by value: a mistyped struct tag yields the zero value
	// rather than an error, so only comparing the value catches it.
	d := drivers[0]
	assert.Equal(t, "storahci", d.Name)
	assert.Equal(t, "Microsoft Standard SATA AHCI Driver", d.DisplayName)
	assert.Equal(t, `C:\Windows\System32\drivers\storahci.sys`, d.Path)
	assert.Equal(t, "Kernel Driver", d.ServiceType)
	assert.Equal(t, "Boot", d.StartMode)
	assert.True(t, d.Started)
	assert.Equal(t, "10.0.26100.1150 (WinBuild.160101.0800)", d.Version)
	assert.Equal(t, "Microsoft Corporation", d.Manufacturer)

	// The three-state signature. An absent verdict must stay nil: reporting it
	// as false would invent an unsigned-driver finding on every driver whose
	// image could not be read.
	require.NotNil(t, drivers[0].Signed)
	assert.True(t, *drivers[0].Signed)

	require.NotNil(t, drivers[1].Signed)
	assert.False(t, *drivers[1].Signed, "a driver measured as unsigned must read false, not null")

	assert.Nil(t, drivers[2].Signed, "an unreachable image must leave signed null, not false")

	// A null string field decodes to empty rather than failing the whole document.
	assert.Empty(t, drivers[2].Version)
	assert.Empty(t, drivers[2].Manufacturer)
}

func TestParseDriversEmpty(t *testing.T) {
	// A target that reported nothing is a normal state, not an error.
	for _, in := range []string{"", "   ", "null", "[]"} {
		drivers, err := ParseDrivers(strings.NewReader(in))
		require.NoError(t, err, "input %q", in)
		assert.Empty(t, drivers, "input %q", in)
	}
}

func TestParseDriversMalformed(t *testing.T) {
	_, err := ParseDrivers(strings.NewReader(`{"Name":`))
	assert.Error(t, err)
}

func TestSignerCommonName(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		expected string
	}{
		{
			name:     "plain CN",
			subject:  "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
			expected: "Microsoft Windows",
		},
		{
			// The case a naive strings.Split(subject, ",") gets wrong: it
			// reports "Ricoh Company" and silently drops ", Ltd.".
			name:     "quoted CN containing a comma",
			subject:  `CN="Ricoh Company, Ltd.", O=Ricoh, C=JP`,
			expected: "Ricoh Company, Ltd.",
		},
		{
			name:     "CN is the only component",
			subject:  "CN=Contoso Driver Publisher",
			expected: "Contoso Driver Publisher",
		},
		{
			// A CN that is not the first component still has to be found.
			name:     "CN after another component",
			subject:  "O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher, C=US",
			expected: "Microsoft Windows Hardware Compatibility Publisher",
		},
		{
			name:     "no CN present",
			subject:  "O=Microsoft Corporation, C=US",
			expected: "",
		},
		{
			name:     "empty subject",
			subject:  "",
			expected: "",
		},
		{
			// "CN=" appearing inside a value must not be mistaken for the
			// start of a component.
			name:     "CN inside another value",
			subject:  "O=Falcon=Holdings, C=AU",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, SignerCommonName(tc.subject))
		})
	}
}

func TestDriverPurl(t *testing.T) {
	tests := []struct {
		name     string
		driver   Driver
		expected string
	}{
		{
			// The build tag must not reach the PURL: it is identical across
			// every Microsoft driver, so an advisory keyed on the release
			// would never match.
			name:     "build tag stripped from version",
			driver:   Driver{Name: "storahci", Manufacturer: "Microsoft Corporation", Version: "10.0.26100.1150 (WinBuild.160101.0800)"},
			expected: "pkg:windows-driver/microsoft/storahci@10.0.26100.1150",
		},
		{
			// Corporate suffix folded, so this reaches the same namespace as a
			// print driver from the same vendor.
			name:     "vendor suffix normalised",
			driver:   Driver{Name: "vulndrv", Manufacturer: "Ricoh Company, Ltd.", Version: "1.0.0.4"},
			expected: "pkg:windows-driver/ricoh/vulndrv@1.0.0.4",
		},
		{
			name:     "no version still identifies the product",
			driver:   Driver{Name: "ghostdrv", Manufacturer: "Contoso Inc"},
			expected: "pkg:windows-driver/contoso/ghostdrv",
		},
		{
			// Guessing here would attach one vendor's advisory to another
			// vendor's driver, since driver names are not unique across vendors.
			name:     "no manufacturer yields no purl",
			driver:   Driver{Name: "storahci", Version: "10.0.26100.1150"},
			expected: "",
		},
		{
			name:     "no name yields no purl",
			driver:   Driver{Manufacturer: "Microsoft Corporation", Version: "1.0"},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.driver.Purl())
		})
	}
}

// TestDriverPurlNamespaceMatchesPrinterDriver pins the property that makes the
// shared namespace worth having: the same vendor reaches the same token from a
// system driver and a print driver, even though the two APIs spell the company
// differently.
func TestDriverPurlNamespaceMatchesPrinterDriver(t *testing.T) {
	sys := Driver{Name: "rzpnk", Manufacturer: "Ricoh Company, Ltd."}
	printer := PrinterDriver{Name: "RICOH PCL6 UniversalDriver V4.34", Manufacturer: "RICOH", HardwareID: "RICOHPCL6DriveforUP"}

	assert.True(t, strings.HasPrefix(sys.Purl(), "pkg:windows-driver/ricoh/"))
	assert.True(t, strings.HasPrefix(printer.Purl(), "pkg:windows-driver/ricoh/"))
}
