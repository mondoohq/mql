// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/csv"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
// Test,System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},No Auditing,
type AuditpolEntry struct {
	MachineName      string
	PolicyTarget     string
	Subcategory      string
	SubcategoryGUID  string
	InclusionSetting string
	ExclusionSetting string
	// Flags is the audit setting, independent of the display language; nil
	// when it could not be read.
	Flags *AuditFlags
}

// AuditFlags is a subcategory's audit setting as the POLICY_AUDIT_EVENT_SUCCESS
// and POLICY_AUDIT_EVENT_FAILURE bits. The values are also the numeric
// "Setting Value" of `auditpol /backup`: 0 no auditing, 1 success, 2 failure,
// 3 success and failure.
type AuditFlags uint32

const (
	AuditSuccess AuditFlags = 0x1
	AuditFailure AuditFlags = 0x2
)

// The canonical English audit settings, whatever the display language.
const (
	AuditSettingNoAuditing        = "No Auditing"
	AuditSettingSuccess           = "Success"
	AuditSettingFailure           = "Failure"
	AuditSettingSuccessAndFailure = "Success and Failure"
)

func (f AuditFlags) Success() bool { return f&AuditSuccess != 0 }
func (f AuditFlags) Failure() bool { return f&AuditFailure != 0 }

// Setting is the canonical English setting: "Success and Failure", "Success",
// "Failure" or "No Auditing".
func (f AuditFlags) Setting() string {
	switch {
	case f.Success() && f.Failure():
		return AuditSettingSuccessAndFailure
	case f.Success():
		return AuditSettingSuccess
	case f.Failure():
		return AuditSettingFailure
	default:
		return AuditSettingNoAuditing
	}
}

// auditpolTexts are the texts auditpol prints in one display language.
type auditpolTexts struct {
	PolicyTarget      string
	NoAuditing        string
	Success           string
	Failure           string
	SuccessAndFailure string
}

func (t auditpolTexts) setting(f AuditFlags) string {
	switch {
	case f.Success() && f.Failure():
		return t.SuccessAndFailure
	case f.Success():
		return t.Success
	case f.Failure():
		return t.Failure
	default:
		return t.NoAuditing
	}
}

// auditpolLanguageTexts are auditpol's texts per display language (the primary
// language subtag), as `auditpol /get /category:* /r` prints them on Windows
// Server 2022 and 2025. Only languages verified on a real host are listed:
// the native path runs for these and uses the PowerShell path for any other.
var auditpolLanguageTexts = map[string]auditpolTexts{
	"en": {
		PolicyTarget:      "System",
		NoAuditing:        "No Auditing",
		Success:           "Success",
		Failure:           "Failure",
		SuccessAndFailure: "Success and Failure",
	},
	"de": {
		PolicyTarget:      "System",
		NoAuditing:        "Keine Überwachung",
		Success:           "Erfolg",
		Failure:           "Fehler",
		SuccessAndFailure: "Erfolg und Fehler",
	},
}

// auditpolTextsForLanguage returns auditpol's texts for a display language
// such as "de-DE", and the primary subtag it looked up.
func auditpolTextsForLanguage(lang string) (auditpolTexts, string, bool) {
	primary := strings.ToLower(strings.TrimSpace(lang))
	if i := strings.IndexAny(primary, "-_"); i >= 0 {
		primary = primary[:i]
	}
	t, ok := auditpolLanguageTexts[primary]
	return t, primary, ok
}

// auditpolLocalizedSettings maps inclusion settings as auditpol prints them
// (lowercased) to their flags. It's only a fallback for when the numeric
// setting couldn't be read. The Dutch, Italian and French entries are the
// ones the provider has always accepted; their "No Auditing" texts aren't
// known, so those stay unknown (null) rather than read as no auditing.
var auditpolLocalizedSettings = func() map[string]AuditFlags {
	m := map[string]AuditFlags{
		// Dutch
		"geslaagd":            AuditSuccess,
		"mislukt":             AuditFailure,
		"geslaagd en mislukt": AuditSuccess | AuditFailure,
		// Italian
		"operazione riuscita":       AuditSuccess,
		"errore":                    AuditFailure,
		"esito positivo e negativo": AuditSuccess | AuditFailure,
		// French. auditpol may render the capital "É" with or without its
		// accent, so accept both spellings of the failure forms.
		"succès":          AuditSuccess,
		"échec":           AuditFailure,
		"echec":           AuditFailure,
		"succès et échec": AuditSuccess | AuditFailure,
		"succès et echec": AuditSuccess | AuditFailure,
	}
	for _, t := range auditpolLanguageTexts {
		for _, f := range []AuditFlags{0, AuditSuccess, AuditFailure, AuditSuccess | AuditFailure} {
			m[strings.ToLower(t.setting(f))] = f
		}
	}
	return m
}()

// AuditFlagsFromInclusionSetting maps an inclusion setting as auditpol prints
// it, in any language the provider knows, to its flags.
func AuditFlagsFromInclusionSetting(setting string) (AuditFlags, bool) {
	f, ok := auditpolLocalizedSettings[strings.ToLower(strings.TrimSpace(setting))]
	return f, ok
}

// AuditpolSubcategory carries the canonical English name of a well-known
// audit subcategory and the audit category it belongs to. auditpol localizes
// subcategory names to the OS display language, while the GUIDs stay stable
// across Windows versions and languages.
type AuditpolSubcategory struct {
	Name     string
	Category string
}

// auditpolSubcategories are the subcategory GUIDs (uppercase, no braces) with
// their canonical English name and audit category, in the order
// `auditpol /get /category:* /r` lists them. It covers the 60 subcategories
// `auditpol /list /subcategory:* /v` reports on Windows Server 2016, 2019,
// 2022, and 2025: the 59 of MS-GPAC plus Access Rights, which the
// specification does not list but every one of those releases does.
var auditpolSubcategories = []struct {
	GUID     string
	Name     string
	Category string
}{
	// System
	{"0CCE9211-69AE-11D9-BED3-505054503030", "Security System Extension", "System"},
	{"0CCE9212-69AE-11D9-BED3-505054503030", "System Integrity", "System"},
	{"0CCE9213-69AE-11D9-BED3-505054503030", "IPsec Driver", "System"},
	{"0CCE9214-69AE-11D9-BED3-505054503030", "Other System Events", "System"},
	{"0CCE9210-69AE-11D9-BED3-505054503030", "Security State Change", "System"},
	// Logon/Logoff
	{"0CCE9215-69AE-11D9-BED3-505054503030", "Logon", "Logon/Logoff"},
	{"0CCE9216-69AE-11D9-BED3-505054503030", "Logoff", "Logon/Logoff"},
	{"0CCE9217-69AE-11D9-BED3-505054503030", "Account Lockout", "Logon/Logoff"},
	{"0CCE9218-69AE-11D9-BED3-505054503030", "IPsec Main Mode", "Logon/Logoff"},
	{"0CCE9219-69AE-11D9-BED3-505054503030", "IPsec Quick Mode", "Logon/Logoff"},
	{"0CCE921A-69AE-11D9-BED3-505054503030", "IPsec Extended Mode", "Logon/Logoff"},
	{"0CCE921B-69AE-11D9-BED3-505054503030", "Special Logon", "Logon/Logoff"},
	{"0CCE921C-69AE-11D9-BED3-505054503030", "Other Logon/Logoff Events", "Logon/Logoff"},
	{"0CCE9243-69AE-11D9-BED3-505054503030", "Network Policy Server", "Logon/Logoff"},
	{"0CCE9247-69AE-11D9-BED3-505054503030", "User / Device Claims", "Logon/Logoff"},
	{"0CCE9249-69AE-11D9-BED3-505054503030", "Group Membership", "Logon/Logoff"},
	{"0CCE924B-69AE-11D9-BED3-505054503030", "Access Rights", "Logon/Logoff"},
	// Object Access
	{"0CCE921D-69AE-11D9-BED3-505054503030", "File System", "Object Access"},
	{"0CCE921E-69AE-11D9-BED3-505054503030", "Registry", "Object Access"},
	{"0CCE921F-69AE-11D9-BED3-505054503030", "Kernel Object", "Object Access"},
	{"0CCE9220-69AE-11D9-BED3-505054503030", "SAM", "Object Access"},
	{"0CCE9221-69AE-11D9-BED3-505054503030", "Certification Services", "Object Access"},
	{"0CCE9222-69AE-11D9-BED3-505054503030", "Application Generated", "Object Access"},
	{"0CCE9223-69AE-11D9-BED3-505054503030", "Handle Manipulation", "Object Access"},
	{"0CCE9224-69AE-11D9-BED3-505054503030", "File Share", "Object Access"},
	{"0CCE9225-69AE-11D9-BED3-505054503030", "Filtering Platform Packet Drop", "Object Access"},
	{"0CCE9226-69AE-11D9-BED3-505054503030", "Filtering Platform Connection", "Object Access"},
	{"0CCE9227-69AE-11D9-BED3-505054503030", "Other Object Access Events", "Object Access"},
	{"0CCE9244-69AE-11D9-BED3-505054503030", "Detailed File Share", "Object Access"},
	{"0CCE9245-69AE-11D9-BED3-505054503030", "Removable Storage", "Object Access"},
	{"0CCE9246-69AE-11D9-BED3-505054503030", "Central Policy Staging", "Object Access"},
	// Privilege Use
	{"0CCE9229-69AE-11D9-BED3-505054503030", "Non Sensitive Privilege Use", "Privilege Use"},
	{"0CCE922A-69AE-11D9-BED3-505054503030", "Other Privilege Use Events", "Privilege Use"},
	{"0CCE9228-69AE-11D9-BED3-505054503030", "Sensitive Privilege Use", "Privilege Use"},
	// Detailed Tracking
	{"0CCE922B-69AE-11D9-BED3-505054503030", "Process Creation", "Detailed Tracking"},
	{"0CCE922C-69AE-11D9-BED3-505054503030", "Process Termination", "Detailed Tracking"},
	{"0CCE922D-69AE-11D9-BED3-505054503030", "DPAPI Activity", "Detailed Tracking"},
	{"0CCE922E-69AE-11D9-BED3-505054503030", "RPC Events", "Detailed Tracking"},
	{"0CCE9248-69AE-11D9-BED3-505054503030", "Plug and Play Events", "Detailed Tracking"},
	{"0CCE924A-69AE-11D9-BED3-505054503030", "Token Right Adjusted Events", "Detailed Tracking"},
	// Policy Change
	{"0CCE922F-69AE-11D9-BED3-505054503030", "Audit Policy Change", "Policy Change"},
	{"0CCE9230-69AE-11D9-BED3-505054503030", "Authentication Policy Change", "Policy Change"},
	{"0CCE9231-69AE-11D9-BED3-505054503030", "Authorization Policy Change", "Policy Change"},
	{"0CCE9232-69AE-11D9-BED3-505054503030", "MPSSVC Rule-Level Policy Change", "Policy Change"},
	{"0CCE9233-69AE-11D9-BED3-505054503030", "Filtering Platform Policy Change", "Policy Change"},
	{"0CCE9234-69AE-11D9-BED3-505054503030", "Other Policy Change Events", "Policy Change"},
	// Account Management
	{"0CCE9236-69AE-11D9-BED3-505054503030", "Computer Account Management", "Account Management"},
	{"0CCE9237-69AE-11D9-BED3-505054503030", "Security Group Management", "Account Management"},
	{"0CCE9238-69AE-11D9-BED3-505054503030", "Distribution Group Management", "Account Management"},
	{"0CCE9239-69AE-11D9-BED3-505054503030", "Application Group Management", "Account Management"},
	{"0CCE923A-69AE-11D9-BED3-505054503030", "Other Account Management Events", "Account Management"},
	{"0CCE9235-69AE-11D9-BED3-505054503030", "User Account Management", "Account Management"},
	// DS Access
	{"0CCE923B-69AE-11D9-BED3-505054503030", "Directory Service Access", "DS Access"},
	{"0CCE923C-69AE-11D9-BED3-505054503030", "Directory Service Changes", "DS Access"},
	{"0CCE923D-69AE-11D9-BED3-505054503030", "Directory Service Replication", "DS Access"},
	{"0CCE923E-69AE-11D9-BED3-505054503030", "Detailed Directory Service Replication", "DS Access"},
	// Account Logon
	{"0CCE9240-69AE-11D9-BED3-505054503030", "Kerberos Service Ticket Operations", "Account Logon"},
	{"0CCE9241-69AE-11D9-BED3-505054503030", "Other Account Logon Events", "Account Logon"},
	{"0CCE9242-69AE-11D9-BED3-505054503030", "Kerberos Authentication Service", "Account Logon"},
	{"0CCE923F-69AE-11D9-BED3-505054503030", "Credential Validation", "Account Logon"},
}

// auditpolKnownSubcategories maps the GUIDs of auditpolSubcategories to their
// name and category, and auditpolSubcategoryOrder to their position.
var auditpolKnownSubcategories, auditpolSubcategoryOrder = func() (map[string]AuditpolSubcategory, map[string]int) {
	known := make(map[string]AuditpolSubcategory, len(auditpolSubcategories))
	order := make(map[string]int, len(auditpolSubcategories))
	for i, s := range auditpolSubcategories {
		known[s.GUID] = AuditpolSubcategory{Name: s.Name, Category: s.Category}
		order[s.GUID] = i
	}
	return known, order
}()

// SortAuditpolEntries puts entries in the order `auditpol /get /category:* /r`
// lists them, whichever way they were read; subcategories this provider
// doesn't know keep their order after the known ones.
func SortAuditpolEntries(entries []AuditpolEntry) {
	pos := func(e AuditpolEntry) int {
		if i, ok := auditpolSubcategoryOrder[strings.ToUpper(e.SubcategoryGUID)]; ok {
			return i
		}
		return len(auditpolSubcategories)
	}
	sort.SliceStable(entries, func(i, j int) bool { return pos(entries[i]) < pos(entries[j]) })
}

// LookupAuditpolSubcategory resolves a subcategory GUID (braces optional,
// case-insensitive) to its canonical English name and audit category.
func LookupAuditpolSubcategory(guid string) (AuditpolSubcategory, bool) {
	guid = strings.ToUpper(strings.TrimSpace(guid))
	guid = strings.TrimPrefix(guid, "{")
	guid = strings.TrimSuffix(guid, "}")
	sub, ok := auditpolKnownSubcategories[guid]
	return sub, ok
}

var auditpolGuidRe = regexp.MustCompile(`^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$`)

// AuditpolScript writes the audit policy with `auditpol /backup` to a
// temporary file, prints it and removes the file. The backup's rows are those
// of `auditpol /get /category:* /r` (in another order) plus a last "Setting
// Value" column with the setting as a number, which is what the flags are read
// from. Reading the file with Get-Content has PowerShell decode it (auditpol
// writes it in the ANSI code page) and print it in UTF-8, so the localized
// columns don't depend on the code page auditpol would print in. If the backup
// fails, it prints `auditpol /get /category:* /r` as before, and exits with its
// exit code.
const AuditpolScript = `[Console]::OutputEncoding = [Text.Encoding]::UTF8
$f = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
auditpol /backup /file:$f | Out-Null
if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $f)) {
  Get-Content -LiteralPath $f
  Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
  exit 0
}
Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
auditpol /get /category:* /r
exit $LASTEXITCODE`

// ParseAuditpol parses the CSV of `auditpol /backup` or of
// `auditpol /get /category:* /r`, in the order `auditpol /get` lists the
// subcategories. A backup row's numeric setting ("Setting Value", 0 no
// auditing, 1 success, 2 failure, 3 success and failure) sets the flags.
// Without one (the output of `auditpol /get`), the flags come from the
// inclusion setting if it is a text the provider knows, and stay nil
// otherwise. Rows without a subcategory GUID, the header and a backup's audit
// options and global SACLs, are skipped.
//
// See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
func ParseAuditpol(r io.Reader) ([]AuditpolEntry, error) {
	res := []AuditpolEntry{}

	csvReader := csv.NewReader(r)
	// auditpol prints a plain-text error instead of CSV when it fails (e.g.
	// non-admin shell). Tolerate variable-width rows so such output produces an
	// empty result rather than poisoning FieldsPerRecord from the first record.
	csvReader.FieldsPerRecord = -1
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if len(record) < 6 {
			continue
		}

		guid := strings.TrimSpace(record[3])
		guid = strings.TrimPrefix(guid, "{")
		guid = strings.TrimSuffix(guid, "}")

		// every policy row carries a subcategory GUID; this skips the CSV
		// header row regardless of the OS display language
		if !auditpolGuidRe.MatchString(guid) {
			continue
		}

		entry := AuditpolEntry{
			MachineName:      strings.TrimSpace(record[0]),
			PolicyTarget:     strings.TrimSpace(record[1]),
			Subcategory:      strings.TrimSpace(record[2]),
			SubcategoryGUID:  strings.ToUpper(guid),
			InclusionSetting: strings.TrimSpace(record[4]),
			ExclusionSetting: strings.TrimSpace(record[5]),
		}
		if len(record) >= 7 {
			// The backup format's Setting Value column is authoritative: a
			// blank or unknown value leaves the setting unknown rather than
			// guessed, and the localized text is deliberately not tried as
			// a fallback for these rows.
			if v, err := strconv.ParseUint(strings.TrimSpace(record[6]), 10, 32); err == nil && AuditFlags(v)&^(AuditSuccess|AuditFailure) == 0 {
				f := AuditFlags(v)
				entry.Flags = &f
			}
		} else if f, ok := AuditFlagsFromInclusionSetting(entry.InclusionSetting); ok {
			entry.Flags = &f
		}
		res = append(res, entry)
	}

	SortAuditpolEntries(res)
	return res, nil
}
