// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseMacOSReceiptBundles(t *testing.T) {
	out, err := parseMacOSReceiptBundles(strings.NewReader(
		"#/var/db/receipts/a.bom\n" +
			"./Applications/A.app\n" +
			"\n" +
			"#/var/db/receipts/empty.bom\n" +
			"#/var/db/receipts/b.bom\n" +
			"./B.app\n" +
			"./B.app/Contents/Helpers/B Helper.app\n"))
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{
		"/var/db/receipts/a.bom": {"./Applications/A.app"},
		"/var/db/receipts/b.bom": {"./B.app", "./B.app/Contents/Helpers/B Helper.app"},
	}, out)

	// Bundle lines before any receipt header belong to nothing.
	out, err = parseMacOSReceiptBundles(strings.NewReader("./Stray.app\n"))
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestReceiptMatchesVersion(t *testing.T) {
	cases := []struct {
		app, receipt string
		want         bool
	}{
		{"4.52.162", "4.52.162", true},
		// Package versions append a build number the short version omits.
		{"15.3.1", "15.3.1.1.1785016684", true},
		{"8.10", "8.10.21306.0", true},
		{"7.2.2 (88465)", "7.2.2.88465", true},
		{"1.02", "1.2", true},
		// The app updated itself after the package was installed.
		{"2.5", "2.4.0", false},
		{"9.5.4", "9.2.4", false},
		// Component-wise, not string prefix.
		{"1.2", "1.20", false},
		// A more specific app version than the receipt's is not the same one.
		{"15.3.1", "15.3", false},
		// A placeholder package version dates nothing.
		{"5.1.102", "0", false},
		{"", "1.0", false},
		{"1.0", "", false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, receiptMatchesVersion(c.app, c.receipt), "app %q receipt %q", c.app, c.receipt)
	}
}

func TestMacOSReceiptInstallDates(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_macos_receipts.toml"))
	require.NoError(t, err)

	receipts := readMacOSReceipts(conn)

	// Keynote 14 and 15 both claim Keynote.app; the later install is on disk.
	require.Contains(t, receipts, "/Applications/Keynote.app")
	assert.Equal(t, "com.apple.pkg.Keynote15", receipts["/Applications/Keynote.app"].PackageIdentifier)
	// App Store receipts are relative to "Applications", without a leading slash.
	assert.Contains(t, receipts, "/Applications/Bitwarden.app")
	// A receipt whose plist is missing claims nothing.
	assert.NotContains(t, receipts, "/Applications/Orphan.app")

	app := func(name, path, version string) Package {
		return Package{Name: name, Version: version, Format: MacosPkgFormat, Files: []FileRecord{{Path: path}}}
	}
	pkgs := []Package{
		app("Keynote", "/Applications/Keynote.app", "15.3.1"),
		app("Bitwarden", "/Applications/Bitwarden.app", "2026.9.0"),
		app("Slack", "/Applications/Slack.app", "4.52.162"),
		app("Owly", "/Applications/Owly.app", "2.5"),
		app("Iru Self Service", "/Applications/Iru Self Service.app", "5.1.102"),
		app("Calculator", "/System/Applications/Calculator.app", "12.0"),
		app("XProtect", "/Library/Apple/System/Library/CoreServices/XProtect.app", "163"),
		{Name: "no files", Version: "1.0", Format: MacosPkgFormat},
	}
	applyMacOSReceiptInstallDates(pkgs, receipts)

	date := func(s string) time.Time {
		d, err := time.Parse(time.RFC3339, s)
		require.NoError(t, err)
		return d
	}
	assert.Equal(t, date("2026-08-17T15:59:39Z"), pkgs[0].InstallDate)
	assert.Equal(t, date("2026-09-19T04:30:45Z"), pkgs[1].InstallDate)
	assert.Equal(t, date("2026-09-23T13:52:17Z"), pkgs[2].InstallDate)
	// Receipt names 2.4.0, the app is at 2.5: it updated since.
	assert.True(t, pkgs[3].InstallDate.IsZero())
	// Receipt version "0".
	assert.True(t, pkgs[4].InstallDate.IsZero())
	// Ships with the OS, no receipt.
	assert.True(t, pkgs[5].InstallDate.IsZero())
	// Software Update's receipts for Apple packages live in their own directory.
	assert.Equal(t, date("2026-09-22T13:54:53Z"), pkgs[6].InstallDate)
	assert.True(t, pkgs[7].InstallDate.IsZero())
}

func TestMacOSReceiptInstallDatesWithoutReceipts(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_macos.toml"))
	require.NoError(t, err)
	assert.Empty(t, readMacOSReceipts(conn))
}
