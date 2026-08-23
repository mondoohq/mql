// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/binary"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

// aceEntry represents a parsed ACCESS_ALLOWED_ACE from a Windows
// SECURITY_DESCRIPTOR DACL.
type aceEntry struct {
	// aceType: 0 = ACCESS_ALLOWED, 1 = ACCESS_DENIED, 5 = ACCESS_ALLOWED_OBJECT
	aceType    uint8
	aceFlags   uint8 // ACE header flags (INHERITED_ACE = 0x10, etc.)
	mask       uint32
	sid        string
	objectGUID string // non-empty only for object ACEs (type 5)
}

// parsedSD holds the results of parsing a binary nTSecurityDescriptor.
type parsedSD struct {
	aces []aceEntry
}

// Well-known dangerous right masks.
const (
	rightGenericAll      = 0x10000000
	rightWriteDACL       = 0x00040000
	rightWriteOwner      = 0x00080000
	rightGenericWrite    = 0x40000000
	rightWriteProperty   = 0x00000020
	rightDSControlAccess = 0x00000100
)

// Low-privilege SID prefixes and exact matches used to detect risky ACLs.
var lowPrivSIDs = map[string]bool{
	"S-1-1-0":      true, // Everyone
	"S-1-5-7":      true, // Anonymous
	"S-1-5-11":     true, // Authenticated Users
	"S-1-5-32-545": true, // BUILTIN\Users
}

// lowPrivRIDSuffixes are domain-relative RIDs that indicate low-privilege
// groups (Domain Users = 513, Domain Computers = 515).
var lowPrivRIDSuffixes = []string{"-513", "-515"}

// isLowPrivSID returns true if the SID represents a well-known low-privilege
// principal or a domain users/computers group.
func isLowPrivSID(sid string) bool {
	if lowPrivSIDs[sid] {
		return true
	}
	for _, suffix := range lowPrivRIDSuffixes {
		if len(sid) > len(suffix) && sid[len(sid)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

// hasDangerousRights returns true if the ACE mask includes any right that
// allows modifying the object's security descriptor or full control.
func hasDangerousRights(mask uint32) bool {
	return mask&rightGenericAll != 0 ||
		mask&rightWriteDACL != 0 ||
		mask&rightWriteOwner != 0 ||
		mask&rightGenericWrite != 0
}

// parseSecurityDescriptor parses a raw Windows SECURITY_DESCRIPTOR binary
// blob and returns the DACL ACEs. It handles short, corrupt, or empty
// descriptors gracefully by returning an empty result.
//
// SD layout (self-relative form):
//
//	Offset  Size  Field
//	0       1     Revision
//	1       1     Sbz1
//	2       2     Control (LE)
//	4       4     OffsetOwner (LE)
//	8       4     OffsetGroup (LE)
//	12      4     OffsetSacl (LE)
//	16      4     OffsetDacl (LE)
func parseSecurityDescriptor(sd []byte) parsedSD {
	if len(sd) < 20 {
		return parsedSD{}
	}

	daclOffset := binary.LittleEndian.Uint32(sd[16:20])
	if daclOffset == 0 || int(daclOffset)+8 > len(sd) {
		return parsedSD{}
	}

	return parseDACL(sd, int(daclOffset))
}

// parseDACL parses the ACL structure at the given offset within the SD blob.
//
// ACL layout:
//
//	Offset  Size  Field
//	0       1     AclRevision
//	1       1     Sbz1
//	2       2     AclSize (LE)
//	4       2     AceCount (LE)
//	6       2     Sbz2
func parseDACL(sd []byte, offset int) parsedSD {
	if offset+8 > len(sd) {
		return parsedSD{}
	}

	aceCount := int(binary.LittleEndian.Uint16(sd[offset+4 : offset+6]))
	pos := offset + 8 // start of first ACE

	result := parsedSD{aces: make([]aceEntry, 0, aceCount)}

	for i := 0; i < aceCount; i++ {
		if pos+4 > len(sd) {
			log.Warn().Int("aceIndex", i).Msg("SD: truncated ACE header")
			break
		}

		aceType := sd[pos]
		aceFlags := sd[pos+1]
		aceSize := int(binary.LittleEndian.Uint16(sd[pos+2 : pos+4]))
		if aceSize < 4 || pos+aceSize > len(sd) {
			log.Warn().Int("aceIndex", i).Int("aceSize", aceSize).Msg("SD: invalid ACE size")
			break
		}

		switch aceType {
		case 0x00: // ACCESS_ALLOWED_ACE
			ace, ok := parseBasicACE(sd, pos, aceType)
			if ok {
				ace.aceFlags = aceFlags
				result.aces = append(result.aces, ace)
			}
		case 0x05: // ACCESS_ALLOWED_OBJECT_ACE
			ace, ok := parseObjectACE(sd, pos)
			if ok {
				ace.aceFlags = aceFlags
				result.aces = append(result.aces, ace)
			}
		}

		pos += aceSize
	}

	return result
}

// parseBasicACE extracts an ACCESS_ALLOWED_ACE (type 0) or ACCESS_DENIED_ACE (type 1).
//
// Layout after ACE header (4 bytes):
//
//	Offset  Size  Field
//	4       4     AccessMask (LE)
//	8       var   SID
func parseBasicACE(sd []byte, offset int, aceType uint8) (aceEntry, bool) {
	if offset+8 > len(sd) {
		return aceEntry{}, false
	}
	aceSize := int(binary.LittleEndian.Uint16(sd[offset+2 : offset+4]))
	if offset+aceSize > len(sd) {
		return aceEntry{}, false
	}

	mask := binary.LittleEndian.Uint32(sd[offset+4 : offset+8])
	sidBytes := sd[offset+8 : offset+aceSize]

	sid, err := connection.DecodeSID(sidBytes)
	if err != nil {
		return aceEntry{}, false
	}

	return aceEntry{aceType: aceType, mask: mask, sid: sid}, true
}

// parseObjectACE extracts an ACCESS_ALLOWED_OBJECT_ACE (type 5).
//
// Layout after ACE header (4 bytes):
//
//	Offset  Size  Field
//	4       4     AccessMask (LE)
//	8       4     Flags (LE) — bit 0 = ObjectType present, bit 1 = InheritedObjectType present
//	12      16?   ObjectType GUID (if flags & 1)
//	12/28   16?   InheritedObjectType GUID (if flags & 2)
//	...     var   SID
func parseObjectACE(sd []byte, offset int) (aceEntry, bool) {
	if offset+4 > len(sd) {
		return aceEntry{}, false
	}
	aceSize := int(binary.LittleEndian.Uint16(sd[offset+2 : offset+4]))
	if offset+aceSize > len(sd) || offset+12 > len(sd) {
		return aceEntry{}, false
	}

	mask := binary.LittleEndian.Uint32(sd[offset+4 : offset+8])
	flags := binary.LittleEndian.Uint32(sd[offset+8 : offset+12])

	pos := offset + 12
	var objectGUID string

	if flags&0x01 != 0 {
		if pos+16 > offset+aceSize {
			return aceEntry{}, false
		}
		objectGUID = decodeGUID(sd[pos : pos+16])
		pos += 16
	}

	if flags&0x02 != 0 {
		if pos+16 > offset+aceSize {
			return aceEntry{}, false
		}
		pos += 16 // skip InheritedObjectType
	}

	if pos >= offset+aceSize {
		return aceEntry{}, false
	}

	sid, err := connection.DecodeSID(sd[pos : offset+aceSize])
	if err != nil {
		return aceEntry{}, false
	}

	return aceEntry{aceType: 0x05, mask: mask, sid: sid, objectGUID: objectGUID}, true
}

// rbcdPrincipalSIDs extracts the trustee SIDs from a raw
// msDS-AllowedToActOnBehalfOfOtherIdentity value. The attribute holds a
// self-relative SECURITY_DESCRIPTOR whose DACL names every principal allowed
// to impersonate onto the host, so the SIDs in that DACL are the whole content
// of a resource-based constrained delegation finding.
//
// The result preserves DACL order and is deduplicated. An empty, short, or
// unparseable descriptor yields an empty list.
func rbcdPrincipalSIDs(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}

	parsed := parseSecurityDescriptor(raw)

	seen := make(map[string]bool, len(parsed.aces))
	sids := make([]string, 0, len(parsed.aces))
	for _, ace := range parsed.aces {
		// parseDACL only collects allow ACEs (types 0x00 and 0x05), but guard
		// explicitly so a deny entry can never be reported as a trustee.
		if ace.aceType == 0x01 || ace.sid == "" || seen[ace.sid] {
			continue
		}
		seen[ace.sid] = true
		sids = append(sids, ace.sid)
	}

	return sids
}

// decodeGUID converts a 16-byte binary GUID (mixed-endian as used by AD)
// to its lowercase string form: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
func decodeGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	// Microsoft GUID wire format: first 3 components are little-endian,
	// last 2 are big-endian.
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16],
	)
}
