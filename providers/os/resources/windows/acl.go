// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// AclScript builds the PowerShell that reads a filesystem object's
// discretionary access control list.
//
// Two things are done here rather than left to the caller. The entries are
// read with their SIDs, which the access control list stores, and each SID is
// translated to an account name inside a try/catch. Translating the other way,
// from the name .NET renders back to a SID, fails for principals such as
// APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES (S-1-15-2-1), and an
// entry naming a deleted account keeps the SID as its identity instead of
// taking the whole list down. And the access mask is widened through
// BitConverter rather than cast: FileSystemRights is a signed 32 bit enum, so
// a mask with the generic bits set (0xE0010000, say) is a negative number that
// [uint32] refuses outright with "Value was either too large or too small".
func AclScript(path string) string {
	return `$ErrorActionPreference='Stop'
$p=` + powershell.SingleQuote(path) + `
$a=Get-Acl -LiteralPath $p
[ordered]@{
Path=$p;Owner=[string]$a.Owner;Group=[string]$a.Group;Sddl=[string]$a.Sddl;Protected=$a.AreAccessRulesProtected
OwnerSid=$(try{[string]$a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value}catch{''})
Access=@($a.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])|ForEach-Object{
$s=[string]$_.IdentityReference.Value;$n=$s;try{$n=[string]$_.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value}catch{}
[ordered]@{Identity=$n;Sid=$s;Type=[string]$_.AccessControlType;Rights=[string]$_.FileSystemRights;Mask=[int64][System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([int]$_.FileSystemRights),0);Inherited=$_.IsInherited;InheritanceFlags=[string]$_.InheritanceFlags;PropagationFlags=[string]$_.PropagationFlags}})
}|ConvertTo-Json -Depth 5 -Compress`
}

// Windows file access rights, as defined by the FileSystemRights enumeration
// and the generic rights that appear in a raw access mask.
const (
	AclReadData                     int64 = 0x000001
	AclWriteData                    int64 = 0x000002
	AclAppendData                   int64 = 0x000004
	AclReadExtendedAttributes       int64 = 0x000008
	AclWriteExtendedAttributes      int64 = 0x000010
	AclExecuteFile                  int64 = 0x000020
	AclDeleteSubdirectoriesAndFiles int64 = 0x000040
	AclReadAttributes               int64 = 0x000080
	AclWriteAttributes              int64 = 0x000100
	AclDelete                       int64 = 0x010000
	AclReadPermissions              int64 = 0x020000
	AclChangePermissions            int64 = 0x040000
	AclTakeOwnership                int64 = 0x080000
	AclSynchronize                  int64 = 0x100000
	AclFullControl                  int64 = 0x1F01FF

	AclGenericAll     int64 = 0x10000000
	AclGenericExecute int64 = 0x20000000
	AclGenericWrite   int64 = 0x40000000
	AclGenericRead    int64 = 0x80000000
)

// Groupings behind the derived predicates.
const (
	aclReadMask = AclReadData | AclReadExtendedAttributes | AclReadAttributes |
		AclReadPermissions | AclGenericRead | AclGenericAll

	// Delete counts as write: a principal that can delete a file can change
	// what the path resolves to, which is the question "who can write here"
	// is really asking.
	aclWriteMask = AclWriteData | AclAppendData | AclWriteExtendedAttributes |
		AclWriteAttributes | AclDelete | AclDeleteSubdirectoriesAndFiles |
		AclGenericWrite | AclGenericAll

	aclExecuteMask = AclExecuteFile | AclGenericExecute | AclGenericAll

	aclDeleteMask = AclDelete | AclDeleteSubdirectoriesAndFiles | AclGenericAll

	// Either of these lets a principal rewrite the access control list and
	// grant itself everything else, so they are as strong as full control.
	aclPermissionChangeMask = AclChangePermissions | AclTakeOwnership | AclGenericAll
)

// WindowsAcl is a filesystem object's discretionary access control list.
type WindowsAcl struct {
	Path     string `json:"Path"`
	Owner    string `json:"Owner"`
	OwnerSid string `json:"OwnerSid"`
	Group    string `json:"Group"`
	Sddl     string `json:"Sddl"`
	// Protected is true when inheritance from the parent has been broken.
	Protected bool              `json:"Protected"`
	Access    []WindowsAclEntry `json:"Access"`
}

// WindowsAclEntry is one access control entry.
type WindowsAclEntry struct {
	Identity string `json:"Identity"`
	Sid      string `json:"Sid"`
	// Type is Allow or Deny.
	Type string `json:"Type"`
	// Rights is what .NET names the mask, which is not always a name. A mask
	// carrying generic bits has no label and arrives as a signed decimal
	// string such as "-536805376".
	Rights           string `json:"Rights"`
	Mask             int64  `json:"Mask"`
	Inherited        bool   `json:"Inherited"`
	InheritanceFlags string `json:"InheritanceFlags"`
	PropagationFlags string `json:"PropagationFlags"`
}

// The allows* predicates answer what an entry grants, so every one of them is
// false on a deny entry, whatever its mask: a deny entry for write is not a
// write grant. The covers* helpers answer what the mask names, regardless of
// the entry type.

func (e WindowsAclEntry) coversRead() bool    { return e.Mask&aclReadMask != 0 }
func (e WindowsAclEntry) coversWrite() bool   { return e.Mask&aclWriteMask != 0 }
func (e WindowsAclEntry) coversExecute() bool { return e.Mask&aclExecuteMask != 0 }
func (e WindowsAclEntry) coversDelete() bool  { return e.Mask&aclDeleteMask != 0 }
func (e WindowsAclEntry) coversFullControl() bool {
	return e.Mask&AclGenericAll != 0 || e.Mask&AclFullControl == AclFullControl
}
func (e WindowsAclEntry) coversPermissionChange() bool {
	return e.Mask&aclPermissionChangeMask != 0
}

// AllowsRead reports whether the entry grants any form of read.
func (e WindowsAclEntry) AllowsRead() bool { return e.IsAllow() && e.coversRead() }

// AllowsWrite reports whether the entry grants any form of write, including
// appending, changing attributes, and deleting.
func (e WindowsAclEntry) AllowsWrite() bool { return e.IsAllow() && e.coversWrite() }

// AllowsExecute reports whether the entry grants executing a file or
// traversing a directory.
func (e WindowsAclEntry) AllowsExecute() bool { return e.IsAllow() && e.coversExecute() }

// AllowsDelete reports whether the entry grants deleting the object or its
// children.
func (e WindowsAclEntry) AllowsDelete() bool { return e.IsAllow() && e.coversDelete() }

// AllowsFullControl reports whether the entry grants every right, either as
// the full FileSystemRights set or as the generic all mask.
func (e WindowsAclEntry) AllowsFullControl() bool { return e.IsAllow() && e.coversFullControl() }

// AllowsPermissionChange reports whether the entry lets the principal rewrite
// the access control list or take ownership, either of which lets it grant
// itself every other right.
func (e WindowsAclEntry) AllowsPermissionChange() bool {
	return e.IsAllow() && e.coversPermissionChange()
}

// IsAllow reports whether the entry grants rather than denies.
func (e WindowsAclEntry) IsAllow() bool { return strings.EqualFold(e.Type, "Allow") }

// AllowedWritePrincipals returns the accounts named by allow entries that
// grant any form of write, in the order the entries appear and without
// repeats.
//
// Deny entries are not subtracted. A deny entry only ever removes access, so
// the result is a superset of the principals that can really write: an audit
// asserting that only certain accounts may write reports one that a deny
// entry had already stopped, rather than missing one that can.
func (a *WindowsAcl) AllowedWritePrincipals() []string {
	seen := make(map[string]struct{}, len(a.Access))
	res := []string{}
	for _, e := range a.Access {
		if !e.AllowsWrite() {
			continue
		}
		if _, ok := seen[e.Identity]; ok {
			continue
		}
		seen[e.Identity] = struct{}{}
		res = append(res, e.Identity)
	}
	return res
}

// AclEntryID builds the resource id of an access control entry.
//
// An entry repeats along more dimensions than the principal: the same account
// legitimately appears more than once on one object, once allowing and once
// denying, and once inherited and once set directly, with different rights and
// different propagation each time. All of them are in the id, because
// CreateResource returns the cached first instance for a repeated id, so a
// missing dimension makes the second entry report the first one's rights.
func AclEntryID(path, identity, aceType string, mask int64, inherited bool, inheritanceFlags, propagationFlags string) string {
	var b strings.Builder
	b.WriteString("windows.acl.entry/")
	b.WriteString(path)
	b.WriteString("/")
	b.WriteString(identity)
	b.WriteString("/")
	b.WriteString(aceType)
	b.WriteString("/")
	b.WriteString(strconv.FormatInt(mask, 10))
	if inherited {
		b.WriteString("/inherited")
	} else {
		b.WriteString("/direct")
	}
	b.WriteString("/")
	b.WriteString(inheritanceFlags)
	b.WriteString("/")
	b.WriteString(propagationFlags)
	return b.String()
}

// AclID builds the resource id of an access control list.
func AclID(path string) string {
	return "windows.acl/" + path
}

// ParseWindowsAcl decodes an access control list.
func ParseWindowsAcl(input io.Reader) (*WindowsAcl, error) {
	var res WindowsAcl
	if err := json.NewDecoder(input).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// AclAuditScript builds the PowerShell that reads a filesystem object's
// system access control list, the rules that decide what is audited.
//
// It is a separate command from AclScript rather than an extra flag on it.
// Reading a system access control list requires the SeSecurityPrivilege
// right, which an unelevated session does not hold, and merging the two would
// make an unprivileged session lose the discretionary list as well.
//
// The entries are read with their SIDs and the mask is widened through
// BitConverter for the same reasons as in AclScript: a name does not always
// translate back to its SID, and FileSystemRights is a signed 32 bit enum, so
// a mask carrying the generic bits is a negative number that [uint32] refuses
// outright.
func AclAuditScript(path string) string {
	return `$ErrorActionPreference='Stop'
$p=` + powershell.SingleQuote(path) + `
$a=Get-Acl -LiteralPath $p -Audit
[ordered]@{
Path=$p
Audit=@($a.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier])|ForEach-Object{
$s=[string]$_.IdentityReference.Value;$n=$s;try{$n=[string]$_.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value}catch{}
[ordered]@{Identity=$n;Sid=$s;AuditFlags=[string]$_.AuditFlags;Rights=[string]$_.FileSystemRights;Mask=[int64][System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([int]$_.FileSystemRights),0);Inherited=$_.IsInherited;InheritanceFlags=[string]$_.InheritanceFlags;PropagationFlags=[string]$_.PropagationFlags}})
}|ConvertTo-Json -Depth 5 -Compress`
}

// WindowsAclAudit is a filesystem object's system access control list.
type WindowsAclAudit struct {
	Path string `json:"Path"`
	// Audit is empty on an object that audits nothing, which is a real answer
	// and not the same as a list that could not be read: without
	// SeSecurityPrivilege the command fails and never reaches this decode.
	Audit []WindowsAclAuditEntry `json:"Audit"`
}

// WindowsAclAuditEntry is one audit control entry.
type WindowsAclAuditEntry struct {
	Identity string `json:"Identity"`
	Sid      string `json:"Sid"`
	// AuditFlags is None, Success, Failure, or "Success, Failure".
	AuditFlags string `json:"AuditFlags"`
	// Rights is what .NET names the mask, which is not always a name. A mask
	// carrying generic bits has no label and arrives as a signed decimal
	// string.
	Rights           string `json:"Rights"`
	Mask             int64  `json:"Mask"`
	Inherited        bool   `json:"Inherited"`
	InheritanceFlags string `json:"InheritanceFlags"`
	PropagationFlags string `json:"PropagationFlags"`
}

// hasAuditFlag reports whether the comma separated AuditFlags label contains
// the named flag. The label is matched element by element rather than as a
// substring, so a future flag whose name contains another one cannot be
// mistaken for it.
func hasAuditFlag(flags, name string) bool {
	for f := range strings.SplitSeq(flags, ",") {
		if strings.EqualFold(strings.TrimSpace(f), name) {
			return true
		}
	}
	return false
}

// AuditsSuccess reports whether the entry records successful attempts.
func (e WindowsAclAuditEntry) AuditsSuccess() bool {
	return hasAuditFlag(e.AuditFlags, "Success")
}

// AuditsFailure reports whether the entry records failed attempts.
func (e WindowsAclAuditEntry) AuditsFailure() bool {
	return hasAuditFlag(e.AuditFlags, "Failure")
}

// AclAuditEntryID builds the resource id of an audit control entry.
//
// It carries the same dimensions as AclEntryID, with the audited outcomes in
// place of allow or deny: one principal legitimately appears more than once on
// one object, auditing success on one set of rights and failure on another,
// once inherited and once set directly. A missing dimension makes the second
// entry report the first one's rights, because CreateResource returns the
// cached first instance for a repeated id.
func AclAuditEntryID(path, identity, auditFlags string, mask int64, inherited bool, inheritanceFlags, propagationFlags string) string {
	var b strings.Builder
	b.WriteString("windows.acl.auditEntry/")
	b.WriteString(path)
	b.WriteString("/")
	b.WriteString(identity)
	b.WriteString("/")
	b.WriteString(auditFlags)
	b.WriteString("/")
	b.WriteString(strconv.FormatInt(mask, 10))
	if inherited {
		b.WriteString("/inherited")
	} else {
		b.WriteString("/direct")
	}
	b.WriteString("/")
	b.WriteString(inheritanceFlags)
	b.WriteString("/")
	b.WriteString(propagationFlags)
	return b.String()
}

// ParseWindowsAclAudit decodes a system access control list.
func ParseWindowsAclAudit(input io.Reader) (*WindowsAclAudit, error) {
	var res WindowsAclAudit
	if err := json.NewDecoder(input).Decode(&res); err != nil {
		return nil, err
	}
	if res.Audit == nil {
		res.Audit = []WindowsAclAuditEntry{}
	}
	return &res, nil
}
