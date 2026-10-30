// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// The Win32 structs are declared by hand; pin their layout to the headers.
func TestSecpolNativeStructLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("layout pinned for 64-bit")
	}
	assert.Equal(t, uintptr(24), unsafe.Sizeof(policyAuditEventsInfo{}))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(policyAuditEventsInfo{}.EventAuditingOptions))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(policyAuditEventsInfo{}.MaximumAuditEventCount))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(policyAccountDomainInfo{}))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(policyAccountDomainInfo{}.DomainSid))
	assert.Equal(t, uintptr(20), unsafe.Sizeof(userModalsInfo0{}))
	assert.Equal(t, uintptr(12), unsafe.Sizeof(userModalsInfo3{}))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(domainPasswordInfo{}))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(domainPasswordInfo{}.MaxPasswordAge))
	assert.Equal(t, uintptr(56), unsafe.Sizeof(userInfo1{}))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(userInfo1{}.Flags))
}

func TestGrantsAnonymousLookupNames(t *testing.T) {
	for _, tc := range []struct {
		sddl string
		want bool
	}{
		// Windows Server 2022, enabled and disabled through the security policy
		{"D:(A;;0x800;;;AN)(A;;0xf1fff;;;BA)(A;;0x20801;;;WD)(A;;0x801;;;AN)(A;;0x1000;;;LS)(A;;0x1000;;;NS)(A;;0x1000;;;S-1-5-17)(A;;0x801;;;AC)(A;;0x801;;;S-1-15-2-2)", true},
		{"D:(D;;0x800;;;AN)(A;;0xf1fff;;;BA)(A;;0x20801;;;WD)(A;;0x801;;;AN)(A;;0x1000;;;LS)(A;;0x1000;;;NS)(A;;0x1000;;;S-1-5-17)(A;;0x801;;;AC)(A;;0x801;;;S-1-15-2-2)", false},
		// the first ANONYMOUS LOGON ACE for POLICY_LOOKUP_NAMES (0x800) alone
		// decides; the ACE that always allows 0x801 does not
		{"D:(A;;0x801;;;AN)(D;;0x800;;;AN)", false},
		{"D:(D;;0x800;;;AN)(A;;0x800;;;AN)", false},
		{"D:(A;;0x800;;;AN)(D;;0x800;;;AN)", true},
		{"D:(A;;0x801;;;AN)", false},
		// only Everyone may: an anonymous caller is not in Everyone unless
		// EveryoneIncludesAnonymous is set, which is a separate policy
		{"D:(A;;0x1;;;AN)(A;;0x801;;;WD)", false},
		{"D:", false},
		{"O:BA", false},
	} {
		sd, err := windows.SecurityDescriptorFromString(tc.sddl)
		require.NoError(t, err)
		got, err := grantsAnonymousLookupNames(sd)
		require.NoError(t, err, tc.sddl)
		assert.Equal(t, tc.want, got, tc.sddl)
	}
}

// TestNativeSecpolMatchesSecedit reads the policy both ways on this machine:
// the native export must be the secedit export, line for line per section,
// and parse to the same values. It needs an elevated shell, as secedit does.
//
// Settings that are off on most machines would go untested, so it then turns
// "Network access: Allow anonymous SID/Name translation" to the other state
// with secedit, compares again, and restores it.
func TestNativeSecpolMatchesSecedit(t *testing.T) {
	if os.Getenv("MONDOO_SECPOL_EQUIVALENCE") == "" {
		t.Skip("set MONDOO_SECPOL_EQUIVALENCE=1 to compare with secedit (needs an elevated shell; toggles and restores LSAAnonymousNameLookup)")
	}
	want := seceditExport(t)
	assertNativeMatchesSecedit(t, want)

	before := systemAccessValue(t, want, "LSAAnonymousNameLookup")
	toggled := "1"
	if before == "1" {
		toggled = "0"
	}
	t.Cleanup(func() { seceditConfigureSystemAccess(t, "LSAAnonymousNameLookup", before) })
	seceditConfigureSystemAccess(t, "LSAAnonymousNameLookup", toggled)

	want = seceditExport(t)
	require.Equal(t, toggled, systemAccessValue(t, want, "LSAAnonymousNameLookup"), "secedit did not apply LSAAnonymousNameLookup")
	t.Run("LSAAnonymousNameLookup="+toggled, func(t *testing.T) {
		assertNativeMatchesSecedit(t, want)
	})
}

// seceditExport returns `secedit /export` of this machine's policy.
func seceditExport(t *testing.T) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "secpol.inf")
	out, err := exec.Command("secedit", "/export", "/cfg", cfg).CombinedOutput()
	require.NoError(t, err, string(out))
	raw, err := os.ReadFile(cfg)
	require.NoError(t, err)
	return decodeUTF16(raw)
}

// seceditConfigureSystemAccess sets one [System Access] value with secedit,
// through a scratch database.
func seceditConfigureSystemAccess(t *testing.T, key, value string) {
	t.Helper()
	// not t.TempDir: this also runs as a cleanup
	dir, err := os.MkdirTemp("", "secpol")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	cfg := filepath.Join(dir, "set.inf")
	inf := "[Unicode]\r\nUnicode=yes\r\n[System Access]\r\n" + key + " = " + value + "\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n"
	require.NoError(t, os.WriteFile(cfg, []byte(inf), 0o600))
	out, err := exec.Command("secedit", "/configure", "/db", filepath.Join(dir, "set.sdb"), "/cfg", cfg, "/areas", "SECURITYPOLICY", "/quiet").CombinedOutput()
	require.NoError(t, err, string(out))
}

func systemAccessValue(t *testing.T, inf, key string) string {
	t.Helper()
	for _, line := range sections(inf)["System Access"] {
		if k, v, ok := strings.Cut(line, " = "); ok && k == key {
			return v
		}
	}
	require.Failf(t, "no value in [System Access]", "%s", key)
	return ""
}

func assertNativeMatchesSecedit(t *testing.T, want string) {
	t.Helper()
	got, err := NativeSecpolExport()
	require.NoError(t, err)

	// [Privilege Rights] is compared below, after resolving account names
	wantSections, gotSections := sections(want), sections(got)
	for _, name := range []string{"System Access", "Event Audit", "Registry Values"} {
		assert.Equal(t, wantSections[name], gotSections[name], "[%s]", name)
	}

	wantPolicy, err := ParseSecpol(strings.NewReader(want))
	require.NoError(t, err)
	gotPolicy, err := ParseSecpol(strings.NewReader(got))
	require.NoError(t, err)
	assert.Equal(t, wantPolicy.SystemAccess, gotPolicy.SystemAccess)
	assert.Equal(t, wantPolicy.EventAudit, gotPolicy.EventAudit)
	assert.Equal(t, wantPolicy.RegistryValues, gotPolicy.RegistryValues)
	// secedit may name local accounts instead of giving their SID; the
	// resource resolves those names, so compare after resolving through the
	// same lookup the local scan uses.
	wantRights, err := wantPolicy.PrivilegeRightSids(lookupSidsForTest)
	require.NoError(t, err)
	gotRights, err := gotPolicy.PrivilegeRightSids(lookupSidsForTest)
	require.NoError(t, err)
	assert.Equal(t, wantRights, gotRights)
}

// sections returns the lines of each INF section, sorted, with privilege
// rights' principals sorted and secedit's account names left as they are.
func sections(inf string) map[string][]string {
	res := map[string][]string{}
	current := ""
	for _, line := range strings.Split(strings.ReplaceAll(inf, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.Trim(line, "[]")
			continue
		}
		if current == "Privilege Rights" {
			if k, v, ok := strings.Cut(line, " = "); ok {
				vals := strings.Split(v, ",")
				sort.Strings(vals)
				line = k + " = " + strings.Join(vals, ",")
			}
		}
		res[current] = append(res[current], line)
	}
	for k := range res {
		sort.Strings(res[k])
	}
	return res
}

func decodeUTF16(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		b = b[2:]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

func lookupSidsForTest(names []string) (map[string]string, error) {
	res := map[string]string{}
	for _, n := range names {
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			"([System.Security.Principal.NTAccount]'"+strings.ReplaceAll(n, "'", "''")+"').Translate([System.Security.Principal.SecurityIdentifier]).Value").Output()
		if err == nil {
			res[n] = strings.TrimSpace(string(out))
		}
	}
	return res, nil
}
