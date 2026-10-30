// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/binary"
	"testing"

	"go.mondoo.com/mql/providers/activedirectory/connection"
)

// buildBasicACE constructs a minimal ACCESS_ALLOWED_ACE (type 0) binary blob.
// Layout: [type(1) flags(1) size(2) mask(4) SID(variable)]
func buildBasicACE(mask uint32, sid []byte) []byte {
	aceSize := 4 + 4 + len(sid) // header + mask + SID
	ace := make([]byte, aceSize)
	ace[0] = 0x00 // ACCESS_ALLOWED
	ace[1] = 0x00 // flags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize))
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	copy(ace[8:], sid)
	return ace
}

// buildObjectACE constructs a minimal ACCESS_ALLOWED_OBJECT_ACE (type 5).
// Layout: [type(1) flags(1) size(2) mask(4) objFlags(4) objectGUID?(16) inheritedGUID?(16) SID(variable)]
func buildObjectACE(mask uint32, objFlags uint32, objectGUID []byte, inheritedGUID []byte, sid []byte) []byte {
	size := 4 + 4 + 4 // header + mask + objFlags
	if objFlags&0x01 != 0 {
		size += 16
	}
	if objFlags&0x02 != 0 {
		size += 16
	}
	size += len(sid)

	ace := make([]byte, size)
	ace[0] = 0x05 // ACCESS_ALLOWED_OBJECT
	ace[1] = 0x00
	binary.LittleEndian.PutUint16(ace[2:4], uint16(size))
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	binary.LittleEndian.PutUint32(ace[8:12], objFlags)

	pos := 12
	if objFlags&0x01 != 0 {
		copy(ace[pos:pos+16], objectGUID)
		pos += 16
	}
	if objFlags&0x02 != 0 {
		copy(ace[pos:pos+16], inheritedGUID)
		pos += 16
	}
	copy(ace[pos:], sid)
	return ace
}

// buildDACL constructs a DACL from a list of pre-built ACE blobs.
func buildDACL(aces ...[]byte) []byte {
	totalACELen := 0
	for _, a := range aces {
		totalACELen += len(a)
	}
	// ACL header: revision(1) + sbz1(1) + aclSize(2) + aceCount(2) + sbz2(2) = 8 bytes
	aclSize := 8 + totalACELen
	acl := make([]byte, aclSize)
	acl[0] = 0x02 // ACL revision
	binary.LittleEndian.PutUint16(acl[2:4], uint16(aclSize))
	binary.LittleEndian.PutUint16(acl[4:6], uint16(len(aces)))

	pos := 8
	for _, a := range aces {
		copy(acl[pos:], a)
		pos += len(a)
	}
	return acl
}

// buildSD constructs a self-relative SECURITY_DESCRIPTOR with only a DACL.
func buildSD(dacl []byte) []byte {
	// SD header: 20 bytes
	// revision(1) + sbz1(1) + control(2) + ownerOff(4) + groupOff(4) + saclOff(4) + daclOff(4)
	daclOffset := uint32(20)
	sd := make([]byte, 20+len(dacl))
	sd[0] = 0x01                                         // revision
	binary.LittleEndian.PutUint16(sd[2:4], 0x8004)       // SE_DACL_PRESENT | SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(sd[16:20], daclOffset) // DACL offset
	copy(sd[20:], dacl)
	return sd
}

// everyoneSID is the binary representation of S-1-1-0 (Everyone).
var everyoneSID = []byte{
	0x01,                               // revision
	0x01,                               // sub-authority count
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // authority = 1
	0x00, 0x00, 0x00, 0x00, // sub-authority 1 = 0
}

// adminSID is a synthetic domain admin SID S-1-5-21-100-200-300-512.
var adminSID = []byte{
	0x01,                               // revision
	0x05,                               // sub-authority count
	0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority = 5
	0x15, 0x00, 0x00, 0x00, // 21
	0x64, 0x00, 0x00, 0x00, // 100
	0xC8, 0x00, 0x00, 0x00, // 200
	0x2C, 0x01, 0x00, 0x00, // 300
	0x00, 0x02, 0x00, 0x00, // 512 (Domain Admins)
}

func TestIsLowPrivSID(t *testing.T) {
	tests := []struct {
		name string
		sid  string
		want bool
	}{
		{"Everyone", "S-1-1-0", true},
		{"Anonymous", "S-1-5-7", true},
		{"Authenticated Users", "S-1-5-11", true},
		{"BUILTIN Users", "S-1-5-32-545", true},
		{"Domain Users (RID 513)", "S-1-5-21-100-200-300-513", true},
		{"Domain Computers (RID 515)", "S-1-5-21-100-200-300-515", true},
		{"Domain Admins (RID 512)", "S-1-5-21-100-200-300-512", false},
		{"Random user SID", "S-1-5-21-100-200-300-1234", false},
		{"Empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLowPrivSID(tt.sid); got != tt.want {
				t.Errorf("isLowPrivSID(%q) = %v, want %v", tt.sid, got, tt.want)
			}
		})
	}
}

func TestHasDangerousRights(t *testing.T) {
	tests := []struct {
		name string
		mask uint32
		want bool
	}{
		{"GenericAll", rightGenericAll, true},
		{"WriteDACL", rightWriteDACL, true},
		{"WriteOwner", rightWriteOwner, true},
		{"GenericWrite", rightGenericWrite, true},
		{"GenericAll + other bits", rightGenericAll | 0x0001, true},
		{"WriteProperty only", rightWriteProperty, false},
		{"Read control only", 0x00020000, false},
		{"Zero mask", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasDangerousRights(tt.mask); got != tt.want {
				t.Errorf("hasDangerousRights(0x%08X) = %v, want %v", tt.mask, got, tt.want)
			}
		})
	}
}

func TestDecodeSIDBytes(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		want    string
		wantErr bool
	}{
		{
			name: "Everyone S-1-1-0",
			raw:  everyoneSID,
			want: "S-1-1-0",
		},
		{
			name: "Domain Admin S-1-5-21-100-200-300-512",
			raw:  adminSID,
			want: "S-1-5-21-100-200-300-512",
		},
		{
			name:    "too short",
			raw:     []byte{0x01, 0x01, 0x00},
			wantErr: true,
		},
		{
			name:    "truncated sub-authorities",
			raw:     []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := connection.DecodeSID(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeSID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("DecodeSID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeGUID(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			// Certificate Enrollment GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55
			// Wire format (mixed-endian): first 3 components LE, last 2 BE.
			name: "Certificate Enrollment GUID",
			raw: []byte{
				0x68, 0xc9, 0x10, 0x0e, // Data1 LE: 0x0e10c968
				0xfb, 0x78, // Data2 LE: 0x78fb
				0xd2, 0x11, // Data3 LE: 0x11d2
				0x90, 0xd4, // Data4[0:2] BE
				0x00, 0xc0, 0x4f, 0x79, 0xdc, 0x55, // Data4[2:8] BE
			},
			want: "0e10c968-78fb-11d2-90d4-00c04f79dc55",
		},
		{
			name: "all zeros",
			raw:  make([]byte, 16),
			want: "00000000-0000-0000-0000-000000000000",
		},
		{
			name: "too short returns empty",
			raw:  []byte{0x01, 0x02},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeGUID(tt.raw); got != tt.want {
				t.Errorf("decodeGUID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSecurityDescriptor_Empty(t *testing.T) {
	// Too-short SD returns empty result.
	sd := parseSecurityDescriptor(nil)
	if len(sd.aces) != 0 {
		t.Errorf("nil SD: expected 0 ACEs, got %d", len(sd.aces))
	}

	sd = parseSecurityDescriptor([]byte{0x01})
	if len(sd.aces) != 0 {
		t.Errorf("1-byte SD: expected 0 ACEs, got %d", len(sd.aces))
	}
}

func TestParseSecurityDescriptor_ZeroDACLOffset(t *testing.T) {
	// SD with DACL offset = 0 (no DACL present).
	sd := make([]byte, 20)
	sd[0] = 0x01
	result := parseSecurityDescriptor(sd)
	if len(result.aces) != 0 {
		t.Errorf("zero DACL offset: expected 0 ACEs, got %d", len(result.aces))
	}
}

func TestParseSecurityDescriptor_BasicACE(t *testing.T) {
	// Build an SD with one ACCESS_ALLOWED_ACE granting GenericAll to Everyone.
	ace := buildBasicACE(rightGenericAll, everyoneSID)
	dacl := buildDACL(ace)
	sd := buildSD(dacl)

	result := parseSecurityDescriptor(sd)
	if len(result.aces) != 1 {
		t.Fatalf("expected 1 ACE, got %d", len(result.aces))
	}

	a := result.aces[0]
	if a.aceType != 0x00 {
		t.Errorf("aceType = %d, want 0", a.aceType)
	}
	if a.mask != rightGenericAll {
		t.Errorf("mask = 0x%08X, want 0x%08X", a.mask, rightGenericAll)
	}
	if a.sid != "S-1-1-0" {
		t.Errorf("sid = %q, want S-1-1-0", a.sid)
	}
}

func TestParseSecurityDescriptor_MultipleACEs(t *testing.T) {
	ace1 := buildBasicACE(rightWriteDACL, everyoneSID)
	ace2 := buildBasicACE(rightWriteOwner, adminSID)
	dacl := buildDACL(ace1, ace2)
	sd := buildSD(dacl)

	result := parseSecurityDescriptor(sd)
	if len(result.aces) != 2 {
		t.Fatalf("expected 2 ACEs, got %d", len(result.aces))
	}
	if result.aces[0].mask != rightWriteDACL {
		t.Errorf("ACE[0] mask = 0x%08X, want WriteDACL", result.aces[0].mask)
	}
	if result.aces[1].sid != "S-1-5-21-100-200-300-512" {
		t.Errorf("ACE[1] sid = %q, want admin SID", result.aces[1].sid)
	}
}

func TestParseSecurityDescriptor_ObjectACE(t *testing.T) {
	// Certificate enrollment GUID
	enrollGUID := []byte{
		0x68, 0xc9, 0x10, 0x0e,
		0xfb, 0x78,
		0xd2, 0x11,
		0x90, 0xd4,
		0x00, 0xc0, 0x4f, 0x79, 0xdc, 0x55,
	}

	ace := buildObjectACE(0x00000100, 0x01, enrollGUID, nil, everyoneSID)
	dacl := buildDACL(ace)
	sd := buildSD(dacl)

	result := parseSecurityDescriptor(sd)
	if len(result.aces) != 1 {
		t.Fatalf("expected 1 ACE, got %d", len(result.aces))
	}

	a := result.aces[0]
	if a.aceType != 0x05 {
		t.Errorf("aceType = %d, want 5", a.aceType)
	}
	if a.objectGUID != "0e10c968-78fb-11d2-90d4-00c04f79dc55" {
		t.Errorf("objectGUID = %q, want enrollment GUID", a.objectGUID)
	}
	if a.sid != "S-1-1-0" {
		t.Errorf("sid = %q, want Everyone", a.sid)
	}
}

func TestCheckESC4(t *testing.T) {
	tests := []struct {
		name string
		sd   parsedSD
		want bool
	}{
		{
			name: "low-priv with GenericAll = vulnerable",
			sd: parsedSD{aces: []aceEntry{
				{aceType: 0x00, mask: rightGenericAll, sid: "S-1-1-0"},
			}},
			want: true,
		},
		{
			name: "low-priv with WriteDACL = vulnerable",
			sd: parsedSD{aces: []aceEntry{
				{aceType: 0x00, mask: rightWriteDACL, sid: "S-1-5-11"},
			}},
			want: true,
		},
		{
			name: "admin with GenericAll = not vulnerable",
			sd: parsedSD{aces: []aceEntry{
				{aceType: 0x00, mask: rightGenericAll, sid: "S-1-5-21-100-200-300-512"},
			}},
			want: false,
		},
		{
			name: "low-priv with non-dangerous rights = not vulnerable",
			sd: parsedSD{aces: []aceEntry{
				{aceType: 0x00, mask: 0x00020000, sid: "S-1-1-0"},
			}},
			want: false,
		},
		{
			name: "ACCESS_DENIED type skipped",
			sd: parsedSD{aces: []aceEntry{
				{aceType: 0x01, mask: rightGenericAll, sid: "S-1-1-0"},
			}},
			want: false,
		},
		{
			name: "empty SD",
			sd:   parsedSD{},
			want: false,
		},
		{
			name: "Domain Users RID suffix = vulnerable",
			sd: parsedSD{aces: []aceEntry{
				{aceType: 0x00, mask: rightWriteOwner, sid: "S-1-5-21-999-888-777-513"},
			}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkESC4(tt.sd); got != tt.want {
				t.Errorf("checkESC4() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractEnrollmentPermissions(t *testing.T) {
	tests := []struct {
		name        string
		sd          parsedSD
		wantSIDs    int
		wantLowPriv bool
	}{
		{
			name: "object ACE with enrollment GUID for Everyone",
			sd: parsedSD{aces: []aceEntry{
				{aceType: 0x05, mask: 0x100, sid: "S-1-1-0", objectGUID: guidCertificateEnrollment},
			}},
			wantSIDs:    1,
			wantLowPriv: true,
		},
		{
			name: "object ACE with auto-enroll GUID for Everyone",
			sd: parsedSD{aces: []aceEntry{
				{aceType: 0x05, mask: 0x100, sid: "S-1-1-0", objectGUID: guidAutoEnroll},
			}},
			wantSIDs:    1,
			wantLowPriv: true,
		},
		{
			name: "basic ACE with GenericAll for admin = not low-priv",
			sd: parsedSD{aces: []aceEntry{
				{aceType: 0x00, mask: rightGenericAll, sid: "S-1-5-21-100-200-300-512"},
			}},
			wantSIDs:    1,
			wantLowPriv: false,
		},
		{
			name: "object ACE with wrong GUID = not enrollment",
			sd: parsedSD{aces: []aceEntry{
				{aceType: 0x05, mask: 0x100, sid: "S-1-1-0", objectGUID: "deadbeef-0000-0000-0000-000000000000"},
			}},
			wantSIDs:    0,
			wantLowPriv: false,
		},
		{
			name:        "empty SD",
			sd:          parsedSD{},
			wantSIDs:    0,
			wantLowPriv: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sids, lowPriv := extractEnrollmentPermissions(tt.sd)
			if len(sids) != tt.wantSIDs {
				t.Errorf("enrollment SIDs = %d, want %d", len(sids), tt.wantSIDs)
			}
			if lowPriv != tt.wantLowPriv {
				t.Errorf("lowPriv = %v, want %v", lowPriv, tt.wantLowPriv)
			}
		})
	}
}

func TestParseADDuration(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "wrong length",
			raw:  []byte{0x01, 0x02},
			want: "unknown",
		},
		{
			name: "positive value",
			raw:  mustUint64LE(1),
			want: "unknown",
		},
		{
			// 2 years = 2 * 365 * 24 * 3600 * 10_000_000 = 630720000000000
			// Negative: -630720000000000 as uint64 (two's complement)
			name: "2 years",
			raw:  mustInt64LE(-630720000000000),
			want: "2 years",
		},
		{
			// 6 weeks = 6 * 7 * 24 * 3600 * 10_000_000 = 36288000000000
			name: "6 weeks",
			raw:  mustInt64LE(-36288000000000),
			want: "6 weeks",
		},
		{
			// 30 days = 30 * 24 * 3600 * 10_000_000 = 25920000000000
			name: "30 days",
			raw:  mustInt64LE(-25920000000000),
			want: "30 days",
		},
		{
			// 1 day
			name: "1 day",
			raw:  mustInt64LE(-864000000000),
			want: "1 day",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseADDuration(tt.raw); got != tt.want {
				t.Errorf("parseADDuration() = %q, want %q", got, tt.want)
			}
		})
	}
}

// mustInt64LE encodes an int64 as 8 bytes little-endian.
func mustInt64LE(v int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b
}

// mustUint64LE encodes a uint64 as 8 bytes little-endian.
func mustUint64LE(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func TestParseObjectACE_TruncatedHeader(t *testing.T) {
	// An ACE where offset+4 > len(sd) — must not panic.
	buf := []byte{0x05, 0x00, 0x20} // only 3 bytes, need at least 4 for aceSize
	_, ok := parseObjectACE(buf, 0)
	if ok {
		t.Error("expected parseObjectACE to return false for truncated header")
	}
}

func TestParseObjectACE_CorruptAceSize(t *testing.T) {
	// aceSize claims 255 bytes but buffer is only 20 bytes — must not panic.
	buf := make([]byte, 20)
	buf[0] = 0x05                                            // type
	binary.LittleEndian.PutUint16(buf[2:4], 0x00FF)          // aceSize = 255 (corrupt)
	binary.LittleEndian.PutUint32(buf[4:8], rightGenericAll) // mask
	binary.LittleEndian.PutUint32(buf[8:12], 0)              // flags
	_, ok := parseObjectACE(buf, 0)
	if ok {
		t.Error("expected parseObjectACE to return false for corrupt aceSize")
	}
}

func TestParseBasicACE_CorruptAceSize(t *testing.T) {
	// aceSize claims 200 bytes but buffer is only 12 bytes — must not panic.
	buf := make([]byte, 12)
	buf[0] = 0x00                                            // type
	binary.LittleEndian.PutUint16(buf[2:4], 200)             // aceSize = 200 (corrupt)
	binary.LittleEndian.PutUint32(buf[4:8], rightGenericAll) // mask
	_, ok := parseBasicACE(buf, 0, 0x00)
	if ok {
		t.Error("expected parseBasicACE to return false for corrupt aceSize")
	}
}
