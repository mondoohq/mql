// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestSidString(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, ""},
		// short principal SIDs must not panic (regression) and fall back to hex
		{"one byte", []byte{0x00}, "0x00"},
		{"seven bytes", []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, "0x01010000000000"},
		// BUILTIN\Administrators: S-1-5-32-544
		{"builtin admins",
			[]byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00},
			"S-1-5-32-544"},
		// Everyone: S-1-1-0
		{"everyone",
			[]byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
			"S-1-1-0"},
		// A domain account: S-1-5-21-1-2-3-1108
		{"domain user",
			[]byte{0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x54, 0x04, 0x00, 0x00},
			"S-1-5-21-1-2-3-1108"},
		// Not a valid NT SID (length mismatch) -> hex fallback, uppercase.
		{"hex fallback", []byte{0x00, 0xab, 0xcd}, "0x00ABCD"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sidString(tc.in); got != tc.want {
				t.Errorf("sidString(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsActiveDirectoryType(t *testing.T) {
	ad := []string{"WINDOWS_LOGIN", "WINDOWS_GROUP", "WINDOWS_USER", "EXTERNAL_USER", "EXTERNAL_GROUP"}
	for _, x := range ad {
		if !isActiveDirectoryType(x) {
			t.Errorf("isActiveDirectoryType(%q) = false, want true", x)
		}
	}
	notAD := []string{"SQL_LOGIN", "SQL_USER", "CERTIFICATE_MAPPED_LOGIN", "ASYMMETRIC_KEY_MAPPED_USER", ""}
	for _, x := range notAD {
		if isActiveDirectoryType(x) {
			t.Errorf("isActiveDirectoryType(%q) = true, want false", x)
		}
	}
}

func TestQuoteName(t *testing.T) {
	cases := map[string]string{
		"master":     "[master]",
		"my db":      "[my db]",
		"weird]name": "[weird]]name]",
		"a]]b":       "[a]]]]b]",
	}
	for in, want := range cases {
		if got := quoteName(in); got != want {
			t.Errorf("quoteName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBackupTypeDesc(t *testing.T) {
	cases := map[string]string{
		"D": "DATABASE",
		"I": "DIFFERENTIAL",
		"L": "LOG",
		"F": "FILE",
		"G": "DIFFERENTIAL_FILE",
		"P": "PARTIAL",
		"Q": "DIFFERENTIAL_PARTIAL",
		"Z": "Z",
	}
	for in, want := range cases {
		if got := backupTypeDesc(in); got != want {
			t.Errorf("backupTypeDesc(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIdentifierBuilders(t *testing.T) {
	if got := serverPrincipalID("h:1433", "sa"); got != "sa@h:1433" {
		t.Errorf("serverPrincipalID = %q", got)
	}
	dbID := databaseIdentifier("h:1433", "CM_CAS")
	if dbID != "h:1433\\CM_CAS" {
		t.Errorf("databaseIdentifier = %q", dbID)
	}
	if got := databasePrincipalID(dbID, "guest"); got != "guest@h:1433\\CM_CAS" {
		t.Errorf("databasePrincipalID = %q", got)
	}
	// composite permission id must be unique per (class, securable, permission, state, grantee)
	a := permissionResourceID("p", "SERVER", 0, 0, "CONTROL SERVER", "GRANT", "sa")
	b := permissionResourceID("p", "SERVER", 0, 0, "CONTROL SERVER", "DENY", "sa")
	if a == b {
		t.Errorf("permissionResourceID collides across state: %q", a)
	}
}
