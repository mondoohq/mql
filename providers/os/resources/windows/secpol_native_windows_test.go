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

// TestNativeSecpolMatchesSecedit reads the policy both ways on this machine:
// the native export must be the secedit export, line for line per section,
// and parse to the same values. It needs an elevated shell, as secedit does.
func TestNativeSecpolMatchesSecedit(t *testing.T) {
	if os.Getenv("MONDOO_SECPOL_EQUIVALENCE") == "" {
		t.Skip("set MONDOO_SECPOL_EQUIVALENCE=1 to compare with secedit (needs an elevated shell)")
	}
	cfg := filepath.Join(t.TempDir(), "secpol.inf")
	out, err := exec.Command("secedit", "/export", "/cfg", cfg).CombinedOutput()
	require.NoError(t, err, string(out))
	raw, err := os.ReadFile(cfg)
	require.NoError(t, err)
	want := decodeUTF16(raw)

	got, err := NativeSecpolExport()
	require.NoError(t, err)

	wantSections, gotSections := sections(want), sections(got)
	for _, name := range []string{"System Access", "Event Audit", "Registry Values", "Privilege Rights"} {
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
