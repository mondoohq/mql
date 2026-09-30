// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// infSection returns a section of a secedit export in testdata, in file order.
func infSection(t *testing.T, file, name string) []string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + file)
	require.NoError(t, err)
	var lines []string
	in := false
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(l, "[") {
			in = l == "["+name+"]"
			continue
		}
		if in && l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func TestRenderSystemAccessMatchesSecedit(t *testing.T) {
	// Windows Server 2022 defaults: no lockout, password expiry 42 days.
	ws2022 := SecpolSystemAccess{
		MaxPasswordAge:     42 * 86400,
		ForceLogoff:        timeqForever,
		PasswordProperties: domainPasswordComplex,
		Accounts: SecpolAccounts{
			AdministratorName: "Administrator", AdminEnabled: true,
			GuestName: "Guest",
		},
	}
	assert.Equal(t, infSection(t, "secpol-ws2022.inf", "System Access"), RenderSystemAccess(ws2022))

	// Windows Server 2025 with account lockout: the window, the duration and
	// administrator lockout appear.
	ws2025 := ws2022
	ws2025.LockoutThreshold = 10
	ws2025.LockoutObservationWindow = 10 * 60
	ws2025.LockoutDuration = 10 * 60
	ws2025.PasswordProperties |= domainLockoutAdmins
	assert.Equal(t, infSection(t, "secpol-ws2025.inf", "System Access"), RenderSystemAccess(ws2025))
}

func TestRenderSystemAccessNever(t *testing.T) {
	lines := RenderSystemAccess(SecpolSystemAccess{
		MaxPasswordAge: timeqForever, LockoutThreshold: 3, LockoutDuration: timeqForever,
		ForceLogoff: 0, PasswordProperties: domainPasswordStoreClear | domainPasswordNoAnonChange,
		AnonymousNameLookup: true,
	})
	assert.Contains(t, lines, "MaximumPasswordAge = -1")
	assert.Contains(t, lines, "LockoutDuration = -1")
	assert.Contains(t, lines, "ForceLogoffWhenHourExpire = 1")
	assert.Contains(t, lines, "ClearTextPassword = 1")
	assert.Contains(t, lines, "RequireLogonToChangePassword = 1")
	assert.Contains(t, lines, "LSAAnonymousNameLookup = 1")
	assert.Contains(t, lines, "AllowAdministratorLockout = 0")
}

func TestRenderEventAudit(t *testing.T) {
	assert.Equal(t, infSection(t, "secpol-ws2022.inf", "Event Audit"), RenderEventAudit(false, []uint32{3, 3, 3, 3, 3, 3, 3, 3, 3}))

	// POLICY_AUDIT_EVENT_TYPE order differs from secedit's: DetailedTracking
	// (4) is AuditProcessTracking, printed after AuditAccountManage.
	lines := RenderEventAudit(true, []uint32{1, 3, 0, 0, 2, 1, 3, 0, 4 | 1})
	assert.Equal(t, []string{
		"AuditSystemEvents = 1",
		"AuditLogonEvents = 3",
		"AuditObjectAccess = 0",
		"AuditPrivilegeUse = 0",
		"AuditPolicyChange = 1",
		"AuditAccountManage = 3",
		"AuditProcessTracking = 2",
		"AuditDSAccess = 0",
		"AuditAccountLogon = 1",
	}, lines)
}

func TestRenderRegistryValue(t *testing.T) {
	for _, tc := range []struct {
		v    SecpolRegistryValue
		want string
	}{
		{SecpolRegistryValue{Path: `MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount`, Type: regSZ, String: "10"},
			`MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"10"`},
		{SecpolRegistryValue{Path: `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption`, Type: regSZ},
			`MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,""`},
		{SecpolRegistryValue{Path: `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText`, Type: regMultiSZ},
			`MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,`},
		{SecpolRegistryValue{Path: `MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine`, Type: regMultiSZ,
			Strings: []string{`System\CurrentControlSet\Control\ProductOptions`, `System\CurrentControlSet\Control\Server Applications`, `Software\Microsoft\Windows NT\CurrentVersion`}},
			`MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion`},
		{SecpolRegistryValue{Path: `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`, Type: regDWORD, Number: 5},
			`MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,5`},
		{SecpolRegistryValue{Path: `MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing`, Type: regBinary, Binary: []byte{0}},
			`MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing=3,0`},
	} {
		got, ok := RenderRegistryValue(tc.v)
		require.True(t, ok)
		assert.Equal(t, tc.want, got)
		assert.Contains(t, append(infSection(t, "secpol-ws2022.inf", "Registry Values"), infSection(t, "secpol-ws2025.inf", "Registry Values")...), tc.want)
	}
}

func TestRenderPrivilegeRightsParsesLikeSecedit(t *testing.T) {
	inf := RenderSecpol(nil, nil, nil, RenderPrivilegeRights(map[string][]string{
		"SeBackupPrivilege": {"S-1-5-32-551", "S-1-5-32-544"},
		"SeTcbPrivilege":    {},
		"SeDebugPrivilege":  {"S-1-5-32-544"},
	}))
	p, err := ParseSecpol(strings.NewReader(inf))
	require.NoError(t, err)
	rights, err := p.PrivilegeRightSids(nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"SeBackupPrivilege": []any{"S-1-5-32-544", "S-1-5-32-551"},
		"SeDebugPrivilege":  []any{"S-1-5-32-544"},
	}, rights, "a right without holders is absent, as secedit leaves it out")
}
