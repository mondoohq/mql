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

// Captures of AuditpolScript (the auditpol /backup file, printed by PowerShell)
// and of `auditpol /get /category:* /r` on the same host, back to back. Only
// the machine names were replaced. The /get capture of the German host was
// printed in code page 850 and is stored as UTF-8.
var auditpolCaptures = []struct {
	host string
	lang string
}{
	// CIS hardened Windows Server 2022 image, English: all four settings
	{"ws2022-cis", "en-US"},
	// Windows Server 2022, German, with a few settings changed so that all
	// four occur
	{"ws2022-de", "de-DE"},
	// Windows Server 2025, English
	{"ws2025", "en-US"},
}

func parseCapture(t *testing.T, name string) []AuditpolEntry {
	t.Helper()
	f, err := os.Open("./testdata/" + name)
	require.NoError(t, err)
	defer f.Close()
	entries, err := ParseAuditpol(f)
	require.NoError(t, err)
	return entries
}

func TestParseAuditpolBackupCaptures(t *testing.T) {
	for _, c := range auditpolCaptures {
		t.Run(c.host, func(t *testing.T) {
			backup := parseCapture(t, "auditpol-backup-"+c.host+".csv")
			get := parseCapture(t, "auditpol-get-"+c.host+".csv")
			texts, _, ok := auditpolTextsForLanguage(c.lang)
			require.True(t, ok)

			// the 60 subcategories, not the audit options and global SACLs the
			// backup adds, in the order auditpol /get lists them
			require.Len(t, backup, 60)
			require.Len(t, get, 60)
			for i := range backup {
				b, g := backup[i], get[i]
				require.NotNil(t, b.Flags, "%s: numeric setting", b.SubcategoryGUID)
				// the backup's text columns are those of auditpol /get
				assert.Equal(t, strings.ToUpper(c.host), b.MachineName)
				assert.Equal(t, g.MachineName, b.MachineName)
				assert.Equal(t, g.PolicyTarget, b.PolicyTarget)
				assert.Equal(t, g.Subcategory, b.Subcategory)
				assert.Equal(t, g.SubcategoryGUID, b.SubcategoryGUID)
				assert.Equal(t, g.InclusionSetting, b.InclusionSetting)
				assert.Equal(t, g.ExclusionSetting, b.ExclusionSetting)
				// and the numeric setting agrees with the display text
				assert.Equal(t, texts.setting(*b.Flags), b.InclusionSetting, b.SubcategoryGUID)
				assert.Equal(t, texts.PolicyTarget, b.PolicyTarget)
				// the fallback, flags from the display text of /get, agrees too
				require.NotNil(t, g.Flags, "%s: flags from %q", g.SubcategoryGUID, g.InclusionSetting)
				assert.Equal(t, *b.Flags, *g.Flags, b.SubcategoryGUID)
			}
		})
	}
}

func TestParseAuditpolBackupSettings(t *testing.T) {
	entries := parseCapture(t, "auditpol-backup-ws2022-de.csv")
	byGUID := map[string]AuditpolEntry{}
	for _, e := range entries {
		byGUID[e.SubcategoryGUID] = e
	}
	cases := []struct {
		guid, inclusion, setting string
		success, failure         bool
	}{
		{"0CCE9217-69AE-11D9-BED3-505054503030", "Erfolg und Fehler", "Success and Failure", true, true},
		{"0CCE922F-69AE-11D9-BED3-505054503030", "Erfolg", "Success", true, false},
		{"0CCE9234-69AE-11D9-BED3-505054503030", "Fehler", "Failure", false, true},
		{"0CCE9211-69AE-11D9-BED3-505054503030", "Keine Überwachung", "No Auditing", false, false},
	}
	for _, c := range cases {
		e, ok := byGUID[c.guid]
		require.True(t, ok, c.guid)
		require.NotNil(t, e.Flags)
		assert.Equal(t, c.inclusion, e.InclusionSetting)
		assert.Equal(t, c.setting, e.Flags.Setting())
		assert.Equal(t, c.success, e.Flags.Success())
		assert.Equal(t, c.failure, e.Flags.Failure())
	}
}

// A setting value this parser doesn't know leaves the setting unknown; it is
// not read as no auditing. Neither is a /get row with an unknown text.
func TestParseAuditpolUnknownSetting(t *testing.T) {
	in := "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n" +
		"HOST,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,7\r\n" +
		"HOST,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,,\r\n" +
		"HOST,,Option:CrashOnAuditFail,,Disabled,,0\r\n" +
		"HOST,,FileGlobalSacl,,,,\r\n"
	entries, err := ParseAuditpol(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Nil(t, entries[0].Flags)
	assert.Nil(t, entries[1].Flags)

	in = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n" +
		"HOST,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Réussite,\r\n"
	entries, err = ParseAuditpol(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Nil(t, entries[0].Flags)
}

func TestAuditFlagsSetting(t *testing.T) {
	assert.Equal(t, "No Auditing", AuditFlags(0).Setting())
	assert.Equal(t, "Success", AuditSuccess.Setting())
	assert.Equal(t, "Failure", AuditFailure.Setting())
	assert.Equal(t, "Success and Failure", (AuditSuccess | AuditFailure).Setting())
}

func TestAuditpolTextsForLanguage(t *testing.T) {
	for _, lang := range []string{"en-US", "en-GB", "EN", "de-DE", "de-AT", "de"} {
		_, _, ok := auditpolTextsForLanguage(lang)
		assert.True(t, ok, lang)
	}
	for _, lang := range []string{"fr-FR", "nl-NL", ""} {
		_, _, ok := auditpolTextsForLanguage(lang)
		assert.False(t, ok, lang)
	}
}

func TestAuditFlagsFromInclusionSetting(t *testing.T) {
	cases := []struct {
		setting string
		flags   AuditFlags
		ok      bool
	}{
		{"Success", AuditSuccess, true},
		{"Failure", AuditFailure, true},
		{"Success and Failure", AuditSuccess | AuditFailure, true},
		{"No Auditing", 0, true},
		{"Erfolg", AuditSuccess, true},
		{"Fehler", AuditFailure, true},
		{"Erfolg und Fehler", AuditSuccess | AuditFailure, true},
		{"Keine Überwachung", 0, true},
		{"  success and failure  ", AuditSuccess | AuditFailure, true},
		// the Dutch, Italian and French texts the provider always accepted
		{"Geslaagd en mislukt", AuditSuccess | AuditFailure, true},
		{"Esito positivo e negativo", AuditSuccess | AuditFailure, true},
		{"Échec", AuditFailure, true},
		{"Echec", AuditFailure, true},
		// unknown texts, including "no auditing" in a language not verified,
		// are not read as no auditing
		{"unbekannt", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		f, ok := AuditFlagsFromInclusionSetting(c.setting)
		assert.Equal(t, c.ok, ok, c.setting)
		assert.Equal(t, c.flags, f, c.setting)
	}
}
