// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/mock"
	"go.mondoo.com/mql/v13/providers/os/resources/windows"
)

func TestParseAuditpol(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/auditpol.toml"))
	require.NoError(t, err)

	f, err := mock.RunCommand("auditpol /get /category:* /r")
	require.NoError(t, err)

	auditpol, err := windows.ParseAuditpol(f.Stdout)
	require.NoError(t, err)

	// 60 policy rows; the CSV header row is not an entry
	assert.Equal(t, 60, len(auditpol))

	expected := &windows.AuditpolEntry{
		MachineName:      "Test",
		PolicyTarget:     "System",
		Subcategory:      "Kernel Object",
		SubcategoryGUID:  "0CCE921F-69AE-11D9-BED3-505054503030",
		InclusionSetting: "No Auditing",
		ExclusionSetting: "",
	}
	found := findPol(auditpol, "Kernel Object")
	assert.Equal(t, expected, found)
}

// When auditpol fails (e.g. non-admin shell) it prints a human-readable error
// instead of CSV. Previously the parser panicked with "index out of range [3]
// with length 1" on such output.
func TestParseAuditpol_NonCSVOutput(t *testing.T) {
	cases := map[string]string{
		"non-admin":         "The command must be run with administrator privileges\n",
		"error code":        "ERROR 0x00000057 occurred: The parameter is incorrect.\n",
		"empty":             "",
		"malformed midline": "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\nunexpected diagnostic line\nTest,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := windows.ParseAuditpol(strings.NewReader(in))
			require.NoError(t, err)
		})
	}
}

// The header row is six comma-separated column titles and previously parsed
// as a policy entry with subcategory "Subcategory".
func TestParseAuditpol_SkipsHeaderRow(t *testing.T) {
	in := "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\n" +
		"Test,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,\n"
	auditpol, err := windows.ParseAuditpol(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, auditpol, 1)
	assert.Equal(t, "Logon", auditpol[0].Subcategory)
}

func TestLookupAuditpolSubcategory(t *testing.T) {
	cases := []struct {
		guid     string
		name     string
		category string
	}{
		{"0CCE9215-69AE-11D9-BED3-505054503030", "Logon", "Logon/Logoff"},
		{"{0CCE922B-69AE-11D9-BED3-505054503030}", "Process Creation", "Detailed Tracking"},
		{"0cce923f-69ae-11d9-bed3-505054503030", "Credential Validation", "Account Logon"},
		{"0CCE9245-69AE-11D9-BED3-505054503030", "Removable Storage", "Object Access"},
		// reported by auditpol on Windows Server 2016, 2019, and 2022 but absent
		// from MS-GPAC; without it the category read back as an empty string
		{"0CCE924B-69AE-11D9-BED3-505054503030", "Access Rights", "Logon/Logoff"},
	}
	for _, tc := range cases {
		t.Run(tc.guid, func(t *testing.T) {
			sub, ok := windows.LookupAuditpolSubcategory(tc.guid)
			require.True(t, ok)
			assert.Equal(t, tc.name, sub.Name)
			assert.Equal(t, tc.category, sub.Category)
		})
	}

	_, ok := windows.LookupAuditpolSubcategory("00000000-0000-0000-0000-000000000000")
	assert.False(t, ok)
}

// Every subcategory the auditpol recording reports must resolve through the
// well-known table, and vice versa — the table and a real system agree on
// all 60 subcategories and their English names.
func TestAuditpolSubcategoryTableMatchesSystem(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/auditpol.toml"))
	require.NoError(t, err)
	f, err := mock.RunCommand("auditpol /get /category:* /r")
	require.NoError(t, err)
	auditpol, err := windows.ParseAuditpol(f.Stdout)
	require.NoError(t, err)
	require.Len(t, auditpol, 60)

	for _, entry := range auditpol {
		sub, ok := windows.LookupAuditpolSubcategory(entry.SubcategoryGUID)
		require.True(t, ok, "GUID %s missing from table", entry.SubcategoryGUID)
		assert.Equal(t, entry.Subcategory, sub.Name, "name mismatch for %s", entry.SubcategoryGUID)
		assert.NotEmpty(t, sub.Category)
	}
}

func findPol(auditpol []windows.AuditpolEntry, subcategory string) *windows.AuditpolEntry {
	for i := range auditpol {
		if auditpol[i].Subcategory == subcategory {
			return &auditpol[i]
		}
	}
	return nil
}

// The well-known table must carry every subcategory a real system reports.
// A GUID it misses degrades the subcategory to its localized name with no
// category at all, so a category filter such as
// `windows.auditPolicy.where(category == "Logon/Logoff")` silently skips it and
// an assertion over that category passes without ever having seen it.
//
// The GUIDs below are the full set `auditpol /list /subcategory:* /v` reports on
// Windows Server 2016 (10.0.14393), 2019 (10.0.17763), 2022 (10.0.20348), and
// 2025 (10.0.26100); all four agree, and all four include Access Rights, which
// MS-GPAC does not document.
func TestAuditpolTableCoversLiveSubcategories(t *testing.T) {
	liveSubcategories := map[string]struct{ name, category string }{
		"0CCE9210-69AE-11D9-BED3-505054503030": {"Security State Change", "System"},
		"0CCE9211-69AE-11D9-BED3-505054503030": {"Security System Extension", "System"},
		"0CCE9212-69AE-11D9-BED3-505054503030": {"System Integrity", "System"},
		"0CCE9213-69AE-11D9-BED3-505054503030": {"IPsec Driver", "System"},
		"0CCE9214-69AE-11D9-BED3-505054503030": {"Other System Events", "System"},
		"0CCE9215-69AE-11D9-BED3-505054503030": {"Logon", "Logon/Logoff"},
		"0CCE9216-69AE-11D9-BED3-505054503030": {"Logoff", "Logon/Logoff"},
		"0CCE9217-69AE-11D9-BED3-505054503030": {"Account Lockout", "Logon/Logoff"},
		"0CCE9218-69AE-11D9-BED3-505054503030": {"IPsec Main Mode", "Logon/Logoff"},
		"0CCE9219-69AE-11D9-BED3-505054503030": {"IPsec Quick Mode", "Logon/Logoff"},
		"0CCE921A-69AE-11D9-BED3-505054503030": {"IPsec Extended Mode", "Logon/Logoff"},
		"0CCE921B-69AE-11D9-BED3-505054503030": {"Special Logon", "Logon/Logoff"},
		"0CCE921C-69AE-11D9-BED3-505054503030": {"Other Logon/Logoff Events", "Logon/Logoff"},
		"0CCE9243-69AE-11D9-BED3-505054503030": {"Network Policy Server", "Logon/Logoff"},
		"0CCE9247-69AE-11D9-BED3-505054503030": {"User / Device Claims", "Logon/Logoff"},
		"0CCE9249-69AE-11D9-BED3-505054503030": {"Group Membership", "Logon/Logoff"},
		"0CCE924B-69AE-11D9-BED3-505054503030": {"Access Rights", "Logon/Logoff"},
		"0CCE921D-69AE-11D9-BED3-505054503030": {"File System", "Object Access"},
		"0CCE921E-69AE-11D9-BED3-505054503030": {"Registry", "Object Access"},
		"0CCE921F-69AE-11D9-BED3-505054503030": {"Kernel Object", "Object Access"},
		"0CCE9220-69AE-11D9-BED3-505054503030": {"SAM", "Object Access"},
		"0CCE9221-69AE-11D9-BED3-505054503030": {"Certification Services", "Object Access"},
		"0CCE9222-69AE-11D9-BED3-505054503030": {"Application Generated", "Object Access"},
		"0CCE9223-69AE-11D9-BED3-505054503030": {"Handle Manipulation", "Object Access"},
		"0CCE9224-69AE-11D9-BED3-505054503030": {"File Share", "Object Access"},
		"0CCE9225-69AE-11D9-BED3-505054503030": {"Filtering Platform Packet Drop", "Object Access"},
		"0CCE9226-69AE-11D9-BED3-505054503030": {"Filtering Platform Connection", "Object Access"},
		"0CCE9227-69AE-11D9-BED3-505054503030": {"Other Object Access Events", "Object Access"},
		"0CCE9244-69AE-11D9-BED3-505054503030": {"Detailed File Share", "Object Access"},
		"0CCE9245-69AE-11D9-BED3-505054503030": {"Removable Storage", "Object Access"},
		"0CCE9246-69AE-11D9-BED3-505054503030": {"Central Policy Staging", "Object Access"},
		"0CCE9228-69AE-11D9-BED3-505054503030": {"Sensitive Privilege Use", "Privilege Use"},
		"0CCE9229-69AE-11D9-BED3-505054503030": {"Non Sensitive Privilege Use", "Privilege Use"},
		"0CCE922A-69AE-11D9-BED3-505054503030": {"Other Privilege Use Events", "Privilege Use"},
		"0CCE922B-69AE-11D9-BED3-505054503030": {"Process Creation", "Detailed Tracking"},
		"0CCE922C-69AE-11D9-BED3-505054503030": {"Process Termination", "Detailed Tracking"},
		"0CCE922D-69AE-11D9-BED3-505054503030": {"DPAPI Activity", "Detailed Tracking"},
		"0CCE922E-69AE-11D9-BED3-505054503030": {"RPC Events", "Detailed Tracking"},
		"0CCE9248-69AE-11D9-BED3-505054503030": {"Plug and Play Events", "Detailed Tracking"},
		"0CCE924A-69AE-11D9-BED3-505054503030": {"Token Right Adjusted Events", "Detailed Tracking"},
		"0CCE922F-69AE-11D9-BED3-505054503030": {"Audit Policy Change", "Policy Change"},
		"0CCE9230-69AE-11D9-BED3-505054503030": {"Authentication Policy Change", "Policy Change"},
		"0CCE9231-69AE-11D9-BED3-505054503030": {"Authorization Policy Change", "Policy Change"},
		"0CCE9232-69AE-11D9-BED3-505054503030": {"MPSSVC Rule-Level Policy Change", "Policy Change"},
		"0CCE9233-69AE-11D9-BED3-505054503030": {"Filtering Platform Policy Change", "Policy Change"},
		"0CCE9234-69AE-11D9-BED3-505054503030": {"Other Policy Change Events", "Policy Change"},
		"0CCE9235-69AE-11D9-BED3-505054503030": {"User Account Management", "Account Management"},
		"0CCE9236-69AE-11D9-BED3-505054503030": {"Computer Account Management", "Account Management"},
		"0CCE9237-69AE-11D9-BED3-505054503030": {"Security Group Management", "Account Management"},
		"0CCE9238-69AE-11D9-BED3-505054503030": {"Distribution Group Management", "Account Management"},
		"0CCE9239-69AE-11D9-BED3-505054503030": {"Application Group Management", "Account Management"},
		"0CCE923A-69AE-11D9-BED3-505054503030": {"Other Account Management Events", "Account Management"},
		"0CCE923B-69AE-11D9-BED3-505054503030": {"Directory Service Access", "DS Access"},
		"0CCE923C-69AE-11D9-BED3-505054503030": {"Directory Service Changes", "DS Access"},
		"0CCE923D-69AE-11D9-BED3-505054503030": {"Directory Service Replication", "DS Access"},
		"0CCE923E-69AE-11D9-BED3-505054503030": {"Detailed Directory Service Replication", "DS Access"},
		"0CCE923F-69AE-11D9-BED3-505054503030": {"Credential Validation", "Account Logon"},
		"0CCE9240-69AE-11D9-BED3-505054503030": {"Kerberos Service Ticket Operations", "Account Logon"},
		"0CCE9241-69AE-11D9-BED3-505054503030": {"Other Account Logon Events", "Account Logon"},
		"0CCE9242-69AE-11D9-BED3-505054503030": {"Kerberos Authentication Service", "Account Logon"},
	}

	require.Len(t, liveSubcategories, 60)
	for guid, want := range liveSubcategories {
		sub, ok := windows.LookupAuditpolSubcategory(guid)
		require.True(t, ok, "GUID %s (%s) missing from the well-known table", guid, want.name)
		assert.Equal(t, want.name, sub.Name, "name mismatch for %s", guid)
		assert.Equal(t, want.category, sub.Category, "category mismatch for %s", guid)
	}
}
