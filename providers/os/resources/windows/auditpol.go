// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/csv"
	"io"
	"regexp"
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
}

// AuditpolSubcategory carries the canonical English name of a well-known
// audit subcategory and the audit category it belongs to. auditpol localizes
// subcategory names to the OS display language, while the GUIDs stay stable
// across Windows versions and languages.
type AuditpolSubcategory struct {
	Name     string
	Category string
}

// auditpolKnownSubcategories maps subcategory GUIDs (uppercase, no braces) to
// their canonical English name and audit category. It covers the 60
// subcategories `auditpol /list /subcategory:* /v` reports on Windows Server
// 2016, 2019, 2022, and 2025: the 59 of MS-GPAC plus Access Rights, which the
// specification does not list but every one of those releases does.
var auditpolKnownSubcategories = map[string]AuditpolSubcategory{
	// System
	"0CCE9210-69AE-11D9-BED3-505054503030": {"Security State Change", "System"},
	"0CCE9211-69AE-11D9-BED3-505054503030": {"Security System Extension", "System"},
	"0CCE9212-69AE-11D9-BED3-505054503030": {"System Integrity", "System"},
	"0CCE9213-69AE-11D9-BED3-505054503030": {"IPsec Driver", "System"},
	"0CCE9214-69AE-11D9-BED3-505054503030": {"Other System Events", "System"},
	// Logon/Logoff
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
	// Object Access
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
	// Privilege Use
	"0CCE9228-69AE-11D9-BED3-505054503030": {"Sensitive Privilege Use", "Privilege Use"},
	"0CCE9229-69AE-11D9-BED3-505054503030": {"Non Sensitive Privilege Use", "Privilege Use"},
	"0CCE922A-69AE-11D9-BED3-505054503030": {"Other Privilege Use Events", "Privilege Use"},
	// Detailed Tracking
	"0CCE922B-69AE-11D9-BED3-505054503030": {"Process Creation", "Detailed Tracking"},
	"0CCE922C-69AE-11D9-BED3-505054503030": {"Process Termination", "Detailed Tracking"},
	"0CCE922D-69AE-11D9-BED3-505054503030": {"DPAPI Activity", "Detailed Tracking"},
	"0CCE922E-69AE-11D9-BED3-505054503030": {"RPC Events", "Detailed Tracking"},
	"0CCE9248-69AE-11D9-BED3-505054503030": {"Plug and Play Events", "Detailed Tracking"},
	"0CCE924A-69AE-11D9-BED3-505054503030": {"Token Right Adjusted Events", "Detailed Tracking"},
	// Policy Change
	"0CCE922F-69AE-11D9-BED3-505054503030": {"Audit Policy Change", "Policy Change"},
	"0CCE9230-69AE-11D9-BED3-505054503030": {"Authentication Policy Change", "Policy Change"},
	"0CCE9231-69AE-11D9-BED3-505054503030": {"Authorization Policy Change", "Policy Change"},
	"0CCE9232-69AE-11D9-BED3-505054503030": {"MPSSVC Rule-Level Policy Change", "Policy Change"},
	"0CCE9233-69AE-11D9-BED3-505054503030": {"Filtering Platform Policy Change", "Policy Change"},
	"0CCE9234-69AE-11D9-BED3-505054503030": {"Other Policy Change Events", "Policy Change"},
	// Account Management
	"0CCE9235-69AE-11D9-BED3-505054503030": {"User Account Management", "Account Management"},
	"0CCE9236-69AE-11D9-BED3-505054503030": {"Computer Account Management", "Account Management"},
	"0CCE9237-69AE-11D9-BED3-505054503030": {"Security Group Management", "Account Management"},
	"0CCE9238-69AE-11D9-BED3-505054503030": {"Distribution Group Management", "Account Management"},
	"0CCE9239-69AE-11D9-BED3-505054503030": {"Application Group Management", "Account Management"},
	"0CCE923A-69AE-11D9-BED3-505054503030": {"Other Account Management Events", "Account Management"},
	// DS Access
	"0CCE923B-69AE-11D9-BED3-505054503030": {"Directory Service Access", "DS Access"},
	"0CCE923C-69AE-11D9-BED3-505054503030": {"Directory Service Changes", "DS Access"},
	"0CCE923D-69AE-11D9-BED3-505054503030": {"Directory Service Replication", "DS Access"},
	"0CCE923E-69AE-11D9-BED3-505054503030": {"Detailed Directory Service Replication", "DS Access"},
	// Account Logon
	"0CCE923F-69AE-11D9-BED3-505054503030": {"Credential Validation", "Account Logon"},
	"0CCE9240-69AE-11D9-BED3-505054503030": {"Kerberos Service Ticket Operations", "Account Logon"},
	"0CCE9241-69AE-11D9-BED3-505054503030": {"Other Account Logon Events", "Account Logon"},
	"0CCE9242-69AE-11D9-BED3-505054503030": {"Kerberos Authentication Service", "Account Logon"},
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

// see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
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

		res = append(res, AuditpolEntry{
			MachineName:      strings.TrimSpace(record[0]),
			PolicyTarget:     strings.TrimSpace(record[1]),
			Subcategory:      strings.TrimSpace(record[2]),
			SubcategoryGUID:  guid,
			InclusionSetting: strings.TrimSpace(record[4]),
			ExclusionSetting: strings.TrimSpace(record[5]),
		})
	}

	return res, nil
}
