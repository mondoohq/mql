// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// liveWindowsVersions are the Windows Server releases the testdata fixtures in
// this file were captured from. Each name is both the fixture suffix and the
// machine name the recording carries, since the real host names were replaced
// during capture.
var liveWindowsVersions = []struct {
	name  string
	build string
}{
	{"ws2016", "10.0.14393"},
	{"ws2019", "10.0.17763"},
	{"ws2022", "10.0.20348"},
	{"ws2025", "10.0.26100"},
}

// TestParseAuditpolLiveCaptures runs the parser over the verbatim
// `auditpol /get /category:* /r` output of four Windows Server releases. Only
// the machine name was replaced; every subcategory name, GUID, and audit
// setting is what the host reported.
func TestParseAuditpolLiveCaptures(t *testing.T) {
	for _, v := range liveWindowsVersions {
		t.Run(v.name, func(t *testing.T) {
			f, err := os.Open("./testdata/auditpol-" + v.name + ".csv")
			require.NoError(t, err)
			defer f.Close()

			entries, err := windows.ParseAuditpol(f)
			require.NoError(t, err)

			// every release in scope reports the same 60 subcategories: the 59
			// of MS-GPAC plus Access Rights
			require.Len(t, entries, 60)

			guids := map[string]struct{}{}
			for _, e := range entries {
				assert.Equal(t, strings.ToUpper(v.name), e.MachineName)
				assert.Equal(t, "System", e.PolicyTarget)
				assert.NotEmpty(t, e.Subcategory)
				assert.NotEmpty(t, e.SubcategoryGUID)
				// the header row must never parse as an entry
				assert.NotEqual(t, "Subcategory", e.Subcategory)
				// auditpol reports one of four settings; anything else means
				// a column shifted
				assert.Contains(t,
					[]string{"Success", "Failure", "Success and Failure", "No Auditing"},
					e.InclusionSetting)
				_, dup := guids[e.SubcategoryGUID]
				assert.False(t, dup, "duplicate GUID %s", e.SubcategoryGUID)
				guids[e.SubcategoryGUID] = struct{}{}
			}
			assert.Len(t, guids, 60)

			// spot-check three settings that differ from one another on a
			// stock host, so a decode that collapsed them would show up
			assert.Equal(t, "Success and Failure", findSetting(t, entries, "Logon"))
			assert.Equal(t, "Success", findSetting(t, entries, "Credential Validation"))
			assert.Equal(t, "No Auditing", findSetting(t, entries, "Registry"))
		})
	}
}

// TestAuditpolLiveCapturesAgreeAcrossVersions pins that the subcategory set is
// identical on all four releases. A release that added or dropped one would
// break here rather than silently changing what a category filter matches.
func TestAuditpolLiveCapturesAgreeAcrossVersions(t *testing.T) {
	var reference map[string]string
	for _, v := range liveWindowsVersions {
		f, err := os.Open("./testdata/auditpol-" + v.name + ".csv")
		require.NoError(t, err)
		entries, err := windows.ParseAuditpol(f)
		f.Close()
		require.NoError(t, err)

		got := map[string]string{}
		for _, e := range entries {
			got[e.SubcategoryGUID] = e.Subcategory
		}
		if reference == nil {
			reference = got
			continue
		}
		assert.Equal(t, reference, got, "%s reports a different subcategory set", v.name)
	}
	require.NotNil(t, reference)
	assert.Contains(t, reference, "0CCE924B-69AE-11D9-BED3-505054503030")
	assert.Equal(t, "Access Rights", reference["0CCE924B-69AE-11D9-BED3-505054503030"])
}

func findSetting(t *testing.T, entries []windows.AuditpolEntry, subcategory string) string {
	t.Helper()
	for i := range entries {
		if entries[i].Subcategory == subcategory {
			return entries[i].InclusionSetting
		}
	}
	t.Fatalf("subcategory %q not found", subcategory)
	return ""
}

// TestParseSecpolLiveCaptures runs the parser over the verbatim
// `secedit /export /cfg` output of four Windows Server releases. The exports
// carry no host name and no machine-unique SID; the two derived service SIDs
// they do carry were replaced with synthetic tails of the same shape.
func TestParseSecpolLiveCaptures(t *testing.T) {
	for _, v := range liveWindowsVersions {
		t.Run(v.name, func(t *testing.T) {
			f, err := os.Open("./testdata/secpol-" + v.name + ".inf")
			require.NoError(t, err)
			defer f.Close()

			secpol, err := windows.ParseSecpol(f)
			require.NoError(t, err)

			// a real export names every principal as a SID, so no resolver is
			// needed and nothing may be dropped for want of one
			rights, err := secpol.PrivilegeRightSids(nil)
			require.NoError(t, err)
			assert.Empty(t, secpol.AccountNames())

			// each of the four maps must come back populated: an empty one
			// makes every assertion written over it pass vacuously
			assert.NotEmpty(t, secpol.SystemAccess)
			assert.NotEmpty(t, secpol.EventAudit)
			assert.NotEmpty(t, secpol.RegistryValues)
			assert.NotEmpty(t, rights)

			// stock defaults, identical on all four releases
			assert.Equal(t, "42", secpol.SystemAccess["MaximumPasswordAge"])
			assert.Equal(t, "0", secpol.SystemAccess["MinimumPasswordLength"])
			assert.Equal(t, "1", secpol.SystemAccess["PasswordComplexity"])
			assert.Equal(t, "1", secpol.SystemAccess["EnableAdminAccount"])
			assert.Equal(t, "0", secpol.SystemAccess["EnableGuestAccount"])
			// the ini reader unquotes, so the value is the bare account name
			assert.Equal(t, "Administrator", secpol.SystemAccess["NewAdministratorName"])
			assert.Equal(t, "Guest", secpol.SystemAccess["NewGuestName"])

			// the legacy audit categories are all off on a stock host
			assert.Equal(t, "0", secpol.EventAudit["AuditLogonEvents"])
			assert.Equal(t, "0", secpol.EventAudit["AuditAccountLogon"])

			// registry values keep their type-prefixed raw form
			assert.Equal(t, "4,1",
				secpol.RegistryValues[`MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse`])
			assert.Equal(t, "3,0",
				secpol.RegistryValues[`MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing`])
			assert.Equal(t, "4,0",
				secpol.RegistryValues[`MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled`])

			// user rights: the leading "*" is stripped, the list is split on
			// commas, and every entry survives as a SID
			assert.Equal(t,
				[]any{"S-1-1-0", "S-1-5-32-544", "S-1-5-32-545", "S-1-5-32-551"},
				rights["SeNetworkLogonRight"])
			assert.Equal(t,
				[]any{"S-1-5-32-544"},
				rights["SeDebugPrivilege"])
			assert.Equal(t,
				[]any{"S-1-5-32-544", "S-1-5-32-555"},
				rights["SeRemoteInteractiveLogonRight"])

			// a stock host grants none of the deny rights, and the parser must
			// report that as an absent key rather than as an empty list that
			// would read as "explicitly nobody"
			_, ok := rights["SeDenyNetworkLogonRight"]
			assert.False(t, ok)

			for right, principals := range rights {
				sids, ok := principals.([]any)
				require.True(t, ok, "%s is not a list", right)
				assert.NotEmpty(t, sids, "%s came back empty", right)
				for _, s := range sids {
					assert.Regexp(t, `^S(-\d+)+$`, s, "%s holds a non-SID principal", right)
				}
			}
		})
	}
}

// TestSecpolLiveCapturesVersionDrift records the two differences between the
// four stock exports. They are small, and pinning them keeps a fixture refresh
// from quietly swapping one release's capture for another's.
func TestSecpolLiveCapturesVersionDrift(t *testing.T) {
	load := func(name string) (*windows.Secpol, map[string]any) {
		f, err := os.Open("./testdata/secpol-" + name + ".inf")
		require.NoError(t, err)
		defer f.Close()
		s, err := windows.ParseSecpol(f)
		require.NoError(t, err)
		rights, err := s.PrivilegeRightSids(nil)
		require.NoError(t, err)
		return s, rights
	}

	ws2016, ws2016Rights := load("ws2016")
	ws2019, _ := load("ws2019")
	ws2022, ws2022Rights := load("ws2022")
	ws2025, ws2025Rights := load("ws2025")

	// Windows Server 2025 is the first of the four to ship account lockout on
	// by default, and it is the only one that exports the three lockout keys
	// that go with it. A benchmark reading LockoutBadCount gets 0 (lockout
	// disabled) on 2016, 2019, and 2022, and 10 on 2025.
	for _, s := range []*windows.Secpol{ws2016, ws2019, ws2022} {
		assert.Equal(t, "0", s.SystemAccess["LockoutBadCount"])
		assert.NotContains(t, s.SystemAccess, "LockoutDuration")
		assert.NotContains(t, s.SystemAccess, "ResetLockoutCount")
		assert.NotContains(t, s.SystemAccess, "AllowAdministratorLockout")
	}
	assert.Equal(t, "10", ws2025.SystemAccess["LockoutBadCount"])
	assert.Equal(t, "10", ws2025.SystemAccess["LockoutDuration"])
	assert.Equal(t, "10", ws2025.SystemAccess["ResetLockoutCount"])
	assert.Equal(t, "1", ws2025.SystemAccess["AllowAdministratorLockout"])

	// FilterAdministratorToken is exported on 2016 and gone from 2019 on
	const filterAdminToken = `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`
	assert.Contains(t, ws2016.RegistryValues, filterAdminToken)
	assert.NotContains(t, ws2022.RegistryValues, filterAdminToken)

	// the Window Manager group holds SeIncreaseBasePriorityPrivilege from 2019
	// on, so the same right has a different principal list per release
	assert.Equal(t, []any{"S-1-5-32-544"},
		ws2016Rights["SeIncreaseBasePriorityPrivilege"])
	assert.Equal(t, []any{"S-1-5-32-544", "S-1-5-90-0"},
		ws2022Rights["SeIncreaseBasePriorityPrivilege"])

	// 2025 grants SeServiceLogonRight to the virtual-account authority as well
	assert.Equal(t, []any{"S-1-5-80-0"}, ws2016Rights["SeServiceLogonRight"])
	assert.Len(t, ws2025Rights["SeServiceLogonRight"], 2)
}
