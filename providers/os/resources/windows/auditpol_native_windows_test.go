// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"bytes"
	"os"
	"os/exec"
	"sort"
	"testing"
	"unicode/utf8"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/charmap"
)

// AUDIT_POLICY_INFORMATION is declared by hand; pin its layout to ntsecapi.h
// (a GUID, a ULONG and a GUID, 4-byte aligned on every architecture).
func TestAuditPolicyInformationLayout(t *testing.T) {
	assert.Equal(t, uintptr(16), unsafe.Sizeof(windows.GUID{}))
	assert.Equal(t, uintptr(36), unsafe.Sizeof(auditPolicyInformation{}))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(auditPolicyInformation{}.AuditSubCategoryGuid))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(auditPolicyInformation{}.AuditingInformation))
	assert.Equal(t, uintptr(20), unsafe.Offsetof(auditPolicyInformation{}.AuditCategoryGuid))
}

func TestAuditFlagsFromInformation(t *testing.T) {
	for v, want := range map[uint32]AuditFlags{0: 0, 1: AuditSuccess, 2: AuditFailure, 3: AuditSuccess | AuditFailure, 4: 0} {
		got, ok := auditFlagsFromInformation(v)
		assert.True(t, ok, "%d", v)
		assert.Equal(t, want, got, "%d", v)
	}
	_, ok := auditFlagsFromInformation(0x10)
	assert.False(t, ok)
}

// TestNativeAuditPolicyMatchesAuditpol reads the audit policy both ways on this
// machine: natively, and with AuditpolScript through PowerShell. Every
// subcategory must be reported the same, field for field. It needs an elevated
// shell, as auditpol does.
func TestNativeAuditPolicyMatchesAuditpol(t *testing.T) {
	if os.Getenv("MONDOO_AUDITPOL_EQUIVALENCE") == "" {
		t.Skip("set MONDOO_AUDITPOL_EQUIVALENCE=1 to compare with auditpol (needs an elevated shell)")
	}
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", AuditpolScript).Output()
	require.NoError(t, err)
	want, err := ParseAuditpol(bytes.NewReader(out))
	require.NoError(t, err)
	require.NotEmpty(t, want, "auditpol reported no subcategories")

	// The backup's columns are those `auditpol /get /r` prints, which the
	// resources reported before. auditpol prints them in a code page that
	// depends on the console (1252 or 850 on a German host), so they are
	// compared in whichever of these decodes them.
	getOut, err := exec.Command("auditpol", "/get", "/category:*", "/r").Output()
	require.NoError(t, err)
	assert.True(t, sameAsGet(t, getOut, want), "auditpol /get and the backup differ")

	got, err := NativeAuditPolicy()
	require.NoError(t, err)

	byGUID := func(entries []AuditpolEntry) map[string]AuditpolEntry {
		m := map[string]AuditpolEntry{}
		for _, e := range entries {
			m[e.SubcategoryGUID] = e
		}
		return m
	}
	w, g := byGUID(want), byGUID(got)
	require.Len(t, g, len(got), "native subcategory GUIDs are unique")
	assert.Equal(t, keys(w), keys(g), "the same subcategories")
	assert.Equal(t, guids(want), guids(got), "in the same order")

	settings := map[string]int{}
	for guid, we := range w {
		ge, ok := g[guid]
		if !ok {
			continue
		}
		require.NotNil(t, we.Flags, "%s (%s): no numeric setting from auditpol /backup", guid, we.Subcategory)
		require.NotNil(t, ge.Flags, "%s (%s): no native setting", guid, we.Subcategory)
		assert.Equal(t, we, ge, "%s (%s)", guid, we.Subcategory)
		// the numeric setting and the display text must agree
		assert.Equal(t, we.InclusionSetting, texts(t).setting(*we.Flags), "%s: display text vs numeric setting", guid)
		settings[we.Flags.Setting()]++
	}
	t.Logf("language %s, %d subcategories, settings %v", preferredUILanguage(), len(w), settings)
}

func texts(t *testing.T) auditpolTexts {
	tx, lang, ok := auditpolTextsForLanguage(preferredUILanguage())
	require.True(t, ok, "auditpol texts for %q", lang)
	return tx
}

func keys(m map[string]AuditpolEntry) []string {
	res := make([]string, 0, len(m))
	for k := range m {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}

func guids(entries []AuditpolEntry) []string {
	res := make([]string, len(entries))
	for i := range entries {
		res[i] = entries[i].SubcategoryGUID
	}
	return res
}

func sameAsGet(t *testing.T, raw []byte, want []AuditpolEntry) bool {
	candidates := [][]byte{}
	if utf8.Valid(raw) {
		candidates = append(candidates, raw)
	}
	for _, cm := range []*charmap.Charmap{charmap.Windows1252, charmap.CodePage850} {
		if b, err := cm.NewDecoder().Bytes(raw); err == nil {
			candidates = append(candidates, b)
		}
	}
	for _, c := range candidates {
		get, err := ParseAuditpol(bytes.NewReader(c))
		require.NoError(t, err)
		if len(get) != len(want) {
			continue
		}
		same := true
		for i := range get {
			g, w := get[i], want[i]
			g.Flags, w.Flags = nil, nil
			if g != w {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}
