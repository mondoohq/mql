// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// The fixtures are the verbatim output of AclScript captured from a Windows
// Server 2022 host: a directory deliberately given a Modify grant to
// BUILTIN\Users and a FullControl deny to ANONYMOUS LOGON, and the stock
// C:\Windows\System32\dns directory.
func loadAcl(t *testing.T, name string) *WindowsAcl {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	require.NoError(t, err)
	defer f.Close()

	res, err := ParseWindowsAcl(f)
	require.NoError(t, err)
	return res
}

func TestParseWindowsAcl(t *testing.T) {
	acl := loadAcl(t, "acl-directory.json")

	assert.Equal(t, `C:\acltest`, acl.Path)
	assert.Equal(t, `BUILTIN\Administrators`, acl.Owner)
	assert.Equal(t, "S-1-5-32-544", acl.OwnerSid)
	assert.Equal(t, `NT AUTHORITY\SYSTEM`, acl.Group)
	assert.False(t, acl.Protected, "the directory still inherits from its parent")
	assert.Contains(t, acl.Sddl, "O:BAG:SY")
	require.Len(t, acl.Access, 7)

	// The deny entry comes first, as Windows orders them.
	deny := acl.Access[0]
	assert.Equal(t, `NT AUTHORITY\ANONYMOUS LOGON`, deny.Identity)
	assert.Equal(t, "S-1-5-7", deny.Sid)
	assert.Equal(t, "Deny", deny.Type)
	assert.False(t, deny.IsAllow())
	assert.Equal(t, AclFullControl, deny.Mask)
	assert.False(t, deny.AllowsFullControl(), "the entry denies full control, it grants nothing")
	assert.False(t, deny.AllowsWrite())
	assert.False(t, deny.AllowsRead())
}

// The rights label cannot be used for assertions, and this is the evidence.
// Two of the shapes in these fixtures defeat a substring match on it.
func TestWindowsAclRightsLabelIsNotAssertable(t *testing.T) {
	acl := loadAcl(t, "acl-directory.json")
	sys := loadAcl(t, "acl-system-directory.json")

	// A principal granted Modify is a writer, but the label never says Write.
	var users WindowsAclEntry
	for _, e := range acl.Access {
		if e.Identity == `BUILTIN\Users` && e.Rights == "Modify, Synchronize" {
			users = e
			break
		}
	}
	require.NotEmpty(t, users.Identity)
	assert.NotContains(t, users.Rights, "Write")
	assert.True(t, users.AllowsWrite(), "Modify grants write even though its label does not say so")

	// A mask with the generic bits set has no label at all and renders as a
	// bare number, so any name-based match misses it entirely.
	var generic WindowsAclEntry
	for _, e := range sys.Access {
		if e.Mask == AclGenericAll {
			generic = e
			break
		}
	}
	require.NotEmpty(t, generic.Identity)
	assert.Equal(t, "268435456", generic.Rights, "GenericAll has no label")
	assert.True(t, generic.AllowsWrite())
	assert.True(t, generic.AllowsFullControl())
	assert.True(t, generic.AllowsPermissionChange())
}

// The whole point of the resource: naming who can change a path.
func TestAllowedWritePrincipals(t *testing.T) {
	acl := loadAcl(t, "acl-directory.json")

	got := acl.AllowedWritePrincipals()
	// BUILTIN\Users and Authenticated Users both hold Modify here, which is
	// exactly the finding an audit of this directory should produce.
	assert.Contains(t, got, `BUILTIN\Users`)
	assert.Contains(t, got, `NT AUTHORITY\Authenticated Users`)
	assert.Contains(t, got, `NT AUTHORITY\SYSTEM`)
	assert.Contains(t, got, `BUILTIN\Administrators`)
	// The deny entry names a principal that cannot write, and a deny is never
	// a grant, so it must not appear.
	assert.NotContains(t, got, `NT AUTHORITY\ANONYMOUS LOGON`)

	// Authenticated Users holds two allow entries on this directory; the
	// principal is reported once.
	count := 0
	for _, p := range got {
		if p == `NT AUTHORITY\Authenticated Users` {
			count++
		}
	}
	assert.Equal(t, 1, count, "a principal with several write entries is listed once")

	// The stock C:\Windows\System32\dns directory. Note CREATOR OWNER: its
	// entry is GenericAll with InheritOnly, meaning whoever creates a child
	// object owns it outright. It is a real write grant and the resource is
	// right to name it, which is the kind of thing a mode-bit view of Windows
	// permissions cannot express at all.
	sys := loadAcl(t, "acl-system-directory.json")
	assert.Equal(t, []string{
		`NT SERVICE\TrustedInstaller`,
		`NT AUTHORITY\SYSTEM`,
		`BUILTIN\Administrators`,
		`CREATOR OWNER`,
	}, sys.AllowedWritePrincipals())

	// BUILTIN\Users holds two entries on that directory, ReadAndExecute and
	// the generic mask 0xA0000000 (read and execute). Neither is a write, so
	// it must not be named. Widening the write mask by one bit too many would
	// report every readable directory as writable.
	assert.NotContains(t, sys.AllowedWritePrincipals(), `BUILTIN\Users`)
}

func TestWindowsAclEntryPredicates(t *testing.T) {
	tests := []struct {
		name             string
		mask             int64
		read             bool
		write            bool
		execute          bool
		del              bool
		full             bool
		permissionChange bool
	}{
		{
			name: "FullControl", mask: AclFullControl,
			read: true, write: true, execute: true, del: true, full: true, permissionChange: true,
		},
		{
			name: "GenericAll with no label", mask: AclGenericAll,
			read: true, write: true, execute: true, del: true, full: true, permissionChange: true,
		},
		{
			// 1245631 = Modify | Synchronize, the value in the fixture.
			name: "Modify", mask: 1245631,
			read: true, write: true, execute: true, del: true, full: false, permissionChange: false,
		},
		{
			// 1179817 = ReadAndExecute | Synchronize, the value in the fixture.
			name: "ReadAndExecute", mask: 1179817,
			read: true, write: false, execute: true, del: false, full: false, permissionChange: false,
		},
		{
			name: "ReadData only", mask: AclReadData,
			read: true,
		},
		{
			name: "WriteData only", mask: AclWriteData,
			write: true,
		},
		{
			// Appending is a write even though nothing existing is replaced.
			name: "AppendData only", mask: AclAppendData,
			write: true,
		},
		{
			// Changing attributes is a write, and is easy to miss.
			name: "WriteAttributes only", mask: AclWriteAttributes,
			write: true,
		},
		{
			// Delete is a write: it changes what the path resolves to.
			name: "Delete only", mask: AclDelete,
			write: true, del: true,
		},
		{
			// Neither of these says "write" but both let the principal grant
			// itself write, so they must be visible.
			name: "ChangePermissions only", mask: AclChangePermissions,
			permissionChange: true,
		},
		{
			name: "TakeOwnership only", mask: AclTakeOwnership,
			permissionChange: true,
		},
		{
			// Synchronize appears on almost every entry and grants nothing.
			name: "Synchronize only", mask: AclSynchronize,
		},
		{
			name: "no rights at all", mask: 0,
		},
		{
			// 3758161920 = 0xE0010000: the generic read, write and execute
			// bits plus Delete. This is the mask that arrives as a negative
			// int32 and must not have been truncated on the way in.
			name: "generic read write execute with delete", mask: 3758161920,
			read: true, write: true, execute: true, del: true, full: false, permissionChange: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := WindowsAclEntry{Type: "Allow", Mask: tc.mask}
			assert.Equal(t, tc.read, e.AllowsRead(), "AllowsRead")
			assert.Equal(t, tc.write, e.AllowsWrite(), "AllowsWrite")
			assert.Equal(t, tc.execute, e.AllowsExecute(), "AllowsExecute")
			assert.Equal(t, tc.del, e.AllowsDelete(), "AllowsDelete")
			assert.Equal(t, tc.full, e.AllowsFullControl(), "AllowsFullControl")
			assert.Equal(t, tc.permissionChange, e.AllowsPermissionChange(), "AllowsPermissionChange")

			// The same mask on a deny entry grants nothing: a check such as
			// entries.where(allowsWrite) must not list a denied principal.
			deny := WindowsAclEntry{Type: "Deny", Mask: tc.mask}
			assert.False(t, deny.AllowsRead(), "deny AllowsRead")
			assert.False(t, deny.AllowsWrite(), "deny AllowsWrite")
			assert.False(t, deny.AllowsExecute(), "deny AllowsExecute")
			assert.False(t, deny.AllowsDelete(), "deny AllowsDelete")
			assert.False(t, deny.AllowsFullControl(), "deny AllowsFullControl")
			assert.False(t, deny.AllowsPermissionChange(), "deny AllowsPermissionChange")
		})
	}
}

// A mask carrying the generic bits is a negative signed 32 bit value on the
// wire. It must arrive widened rather than truncated, or every predicate over
// it reads false and the most privileged entries look like the least.
func TestWindowsAclHighBitMaskSurvives(t *testing.T) {
	acl, err := ParseWindowsAcl(strings.NewReader(`{
		"Path":"C:\\x","Owner":"BUILTIN\\Administrators","Group":"","Sddl":"","Protected":false,"OwnerSid":"",
		"Access":[{"Identity":"NT AUTHORITY\\Authenticated Users","Sid":"S-1-5-11","Type":"Allow",
		"Rights":"-536805376","Mask":3758161920,"Inherited":true,"InheritanceFlags":"ContainerInherit, ObjectInherit","PropagationFlags":"InheritOnly"}]
	}`))
	require.NoError(t, err)
	require.Len(t, acl.Access, 1)

	e := acl.Access[0]
	assert.Equal(t, int64(3758161920), e.Mask)
	assert.Greater(t, e.Mask, int64(0), "the mask must not arrive as a negative int32")
	assert.True(t, e.AllowsWrite())
	assert.Equal(t, []string{`NT AUTHORITY\Authenticated Users`}, acl.AllowedWritePrincipals())
}

// An entry repeats along more dimensions than its principal. The system
// directory fixture contains the case directly: TrustedInstaller appears twice
// as an allow entry, once with FullControl and once with GenericAll. If the id
// missed the mask, the second would be dropped into the first's cache slot and
// report FullControl's rights.
func TestAclEntryIDCarriesEveryDimension(t *testing.T) {
	sys := loadAcl(t, "acl-system-directory.json")

	ids := map[string]int{}
	for _, e := range sys.Access {
		ids[AclEntryID(sys.Path, e.Identity, e.Type, e.Mask, e.Inherited, e.InheritanceFlags, e.PropagationFlags)]++
	}
	assert.Len(t, ids, len(sys.Access), "every entry must get a distinct id")

	base := AclEntryID(`C:\x`, `BUILTIN\Users`, "Allow", AclFullControl, false, "None", "None")
	assert.NotEqual(t, base, AclEntryID(`C:\y`, `BUILTIN\Users`, "Allow", AclFullControl, false, "None", "None"), "path")
	assert.NotEqual(t, base, AclEntryID(`C:\x`, `BUILTIN\Guests`, "Allow", AclFullControl, false, "None", "None"), "identity")
	assert.NotEqual(t, base, AclEntryID(`C:\x`, `BUILTIN\Users`, "Deny", AclFullControl, false, "None", "None"), "allow vs deny")
	assert.NotEqual(t, base, AclEntryID(`C:\x`, `BUILTIN\Users`, "Allow", AclReadData, false, "None", "None"), "mask")
	assert.NotEqual(t, base, AclEntryID(`C:\x`, `BUILTIN\Users`, "Allow", AclFullControl, true, "None", "None"), "inherited")
	assert.NotEqual(t, base, AclEntryID(`C:\x`, `BUILTIN\Users`, "Allow", AclFullControl, false, "ObjectInherit", "None"), "inheritance flags")
	assert.NotEqual(t, base, AclEntryID(`C:\x`, `BUILTIN\Users`, "Allow", AclFullControl, false, "None", "InheritOnly"), "propagation flags")
}

// A path is interpolated into the script, so it has to survive being a Windows
// path and must not be able to close the string it sits in.
func TestAclScriptQuotesThePath(t *testing.T) {
	script := AclScript(`C:\Program Files\App`)
	assert.Contains(t, script, `$p='C:\Program Files\App'`)
	// A backslash keeps its literal meaning inside a single quoted string, so
	// nothing about the path is re-interpreted.
	assert.NotContains(t, script, `C:\\Program`)

	// A quote in the path is doubled rather than ending the string.
	quoted := AclScript(`C:\it's`)
	assert.Contains(t, quoted, `$p='C:\it''s'`)

	// A path that tries to close the string and append a command stays one
	// string literal.
	injected := AclScript(`C:\x'; Remove-Item C:\ -Recurse; '`)
	assert.NotContains(t, injected, `$p='C:\x'; Remove-Item`)
	assert.Contains(t, injected, `''; Remove-Item`)

	// The script has to fit on a Windows command line once encoded.
	assert.Less(t, len(powershell.Encode(AclScript(strings.Repeat("a", 260)))), 8191)
	assert.Less(t, len(powershell.Encode(AclAuditScript(strings.Repeat("a", 260)))), 8191)
}

// The SID comes from the entry itself and the name is translated from it.
// Translating the rendered name back to a SID fails for APPLICATION PACKAGE
// AUTHORITY\ALL APPLICATION PACKAGES (S-1-15-2-1) and ALL RESTRICTED
// APPLICATION PACKAGES (S-1-15-2-2), which left their sid empty.
func TestAclScriptsReadSids(t *testing.T) {
	for name, script := range map[string]string{
		"access": AclScript(`C:\x`),
		"audit":  AclAuditScript(`C:\x`),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Contains(t, script, `($true,$true,[System.Security.Principal.SecurityIdentifier])|ForEach-Object{`)
			assert.Contains(t, script, `$s=[string]$_.IdentityReference.Value`)
			assert.Contains(t, script, `.Translate([System.Security.Principal.NTAccount])`)
			assert.NotContains(t, script, `Translate([System.Security.Principal.SecurityIdentifier])`)
			assert.Contains(t, script, `Identity=$n;Sid=$s;`)
		})
	}
}

// A directory with no entries at all is not the same as a directory anyone can
// write, and an empty list must not be produced from a failed read. The
// resource errors on a failed read; this covers the shape only.
func TestParseWindowsAclEmptyAccess(t *testing.T) {
	acl, err := ParseWindowsAcl(strings.NewReader(
		`{"Path":"C:\\x","Owner":"BUILTIN\\Administrators","Group":"","Sddl":"","Protected":true,"OwnerSid":"S-1-5-32-544","Access":[]}`))
	require.NoError(t, err)

	assert.Empty(t, acl.Access)
	assert.Empty(t, acl.AllowedWritePrincipals())
	assert.True(t, acl.Protected)
}

// An entry whose SID no longer resolves to an account name, an orphaned entry
// left behind by a deleted account, is still reported, with the SID as its
// identity, rather than being dropped from the list.
func TestParseWindowsAclUnresolvableIdentity(t *testing.T) {
	acl, err := ParseWindowsAcl(strings.NewReader(`{
		"Path":"C:\\x","Owner":"BUILTIN\\Administrators","Group":"","Sddl":"","Protected":false,"OwnerSid":"",
		"Access":[
		{"Identity":"S-1-5-21-1111111111-2222222222-3333333333-1013","Sid":"S-1-5-21-1111111111-2222222222-3333333333-1013","Type":"Allow","Rights":"FullControl","Mask":2032127,"Inherited":false,"InheritanceFlags":"None","PropagationFlags":"None"},
		{"Identity":"BUILTIN\\Administrators","Sid":"S-1-5-32-544","Type":"Allow","Rights":"FullControl","Mask":2032127,"Inherited":false,"InheritanceFlags":"None","PropagationFlags":"None"}]
	}`))
	require.NoError(t, err)

	require.Len(t, acl.Access, 2, "an unresolvable account must not shorten the list")
	assert.Equal(t, "S-1-5-21-1111111111-2222222222-3333333333-1013", acl.Access[0].Sid)
	assert.Equal(t, "S-1-5-21-1111111111-2222222222-3333333333-1013", acl.Access[0].Identity)
	// It still counts as a writer, so an audit sees the orphaned grant.
	assert.Contains(t, acl.AllowedWritePrincipals(), "S-1-5-21-1111111111-2222222222-3333333333-1013")
}

func TestParseWindowsAclAudit(t *testing.T) {
	t.Run("a directory auditing failed writes by Everyone", func(t *testing.T) {
		input := `{"Path":"C:\\scratch","Audit":[{"Identity":"Everyone","Sid":"S-1-1-0","AuditFlags":"Failure","Rights":"Write, Delete","Mask":65654,"Inherited":false,"InheritanceFlags":"ContainerInherit, ObjectInherit","PropagationFlags":"None"}]}`

		acl, err := ParseWindowsAclAudit(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, acl.Audit, 1)
		e := acl.Audit[0]
		assert.Equal(t, "Everyone", e.Identity)
		assert.Equal(t, "S-1-1-0", e.Sid)
		assert.Equal(t, "Failure", e.AuditFlags)
		assert.False(t, e.AuditsSuccess())
		assert.True(t, e.AuditsFailure())
		assert.Equal(t, int64(65654), e.Mask)
		assert.False(t, e.Inherited)
	})

	// An object that audits nothing is a real answer and decodes to an empty
	// list. A list that could not be read never reaches this decode: without
	// SeSecurityPrivilege the command fails and the caller reports the error.
	t.Run("an object with no audit rule is an empty list", func(t *testing.T) {
		acl, err := ParseWindowsAclAudit(strings.NewReader(`{"Path":"C:\\scratch","Audit":[]}`))
		require.NoError(t, err)
		assert.Empty(t, acl.Audit)
		assert.NotNil(t, acl.Audit)
	})

	t.Run("an absent Audit key is an empty list rather than nil", func(t *testing.T) {
		acl, err := ParseWindowsAclAudit(strings.NewReader(`{"Path":"C:\\scratch"}`))
		require.NoError(t, err)
		assert.NotNil(t, acl.Audit)
		assert.Empty(t, acl.Audit)
	})

	// FileSystemRights is a signed 32 bit enum, so a mask carrying the generic
	// bits has no label and the script widens it through BitConverter. The
	// value must arrive positive, or a rights comparison silently inverts.
	t.Run("a generic mask stays positive and keeps its raw label", func(t *testing.T) {
		input := `{"Path":"C:\\scratch","Audit":[{"Identity":"BUILTIN\\Administrators","Sid":"S-1-5-32-544","AuditFlags":"Success, Failure","Rights":"-536805376","Mask":3758161920,"Inherited":true,"InheritanceFlags":"None","PropagationFlags":"None"}]}`

		acl, err := ParseWindowsAclAudit(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, acl.Audit, 1)
		e := acl.Audit[0]
		assert.Equal(t, int64(3758161920), e.Mask)
		assert.Positive(t, e.Mask)
		assert.Equal(t, "-536805376", e.Rights)
		assert.True(t, e.AuditsSuccess())
		assert.True(t, e.AuditsFailure())
		assert.True(t, e.Inherited)
	})

	t.Run("malformed output is an error", func(t *testing.T) {
		_, err := ParseWindowsAclAudit(strings.NewReader(`{"Audit":`))
		assert.Error(t, err)
	})
}

func TestWindowsAclAuditEntryFlags(t *testing.T) {
	for _, tc := range []struct {
		flags   string
		success bool
		failure bool
	}{
		{flags: "Success", success: true, failure: false},
		{flags: "Failure", success: false, failure: true},
		{flags: "Success, Failure", success: true, failure: true},
		{flags: "Failure, Success", success: true, failure: true},
		// no spaces after the comma, and a case the API has been seen to vary
		{flags: "Success,Failure", success: true, failure: true},
		{flags: "success, failure", success: true, failure: true},
		// None audits nothing, and neither does an absent label; both must
		// read false rather than defaulting an object into looking audited
		{flags: "None", success: false, failure: false},
		{flags: "", success: false, failure: false},
	} {
		e := WindowsAclAuditEntry{AuditFlags: tc.flags}
		assert.Equal(t, tc.success, e.AuditsSuccess(), "success for %q", tc.flags)
		assert.Equal(t, tc.failure, e.AuditsFailure(), "failure for %q", tc.flags)
	}
}

// A flag is matched element by element, not as a substring, so a label that
// merely contains another flag's name cannot be mistaken for it.
func TestWindowsAclAuditFlagsAreNotSubstringMatched(t *testing.T) {
	e := WindowsAclAuditEntry{AuditFlags: "SuccessfulOnly"}
	assert.False(t, e.AuditsSuccess())
}

// One principal is audited more than once on one object: success on one set of
// rights and failure on another, inherited and set directly. A missing
// dimension makes CreateResource return the cached first instance, so the
// second entry reports the first one's rights.
func TestAclAuditEntryIDDimensions(t *testing.T) {
	base := func() (string, string, string, int64, bool, string, string) {
		return `C:\scratch`, "Everyone", "Success", 65654, false, "None", "None"
	}

	p, id, f, m, i, inh, prop := base()
	ref := AclAuditEntryID(p, id, f, m, i, inh, prop)

	assert.Equal(t, ref, AclAuditEntryID(p, id, f, m, i, inh, prop), "stable")
	assert.NotEqual(t, ref, AclAuditEntryID(p, id, "Failure", m, i, inh, prop), "audited outcomes")
	assert.NotEqual(t, ref, AclAuditEntryID(p, id, f, 1, i, inh, prop), "rights mask")
	assert.NotEqual(t, ref, AclAuditEntryID(p, id, f, m, true, inh, prop), "inherited")
	assert.NotEqual(t, ref, AclAuditEntryID(p, "SYSTEM", f, m, i, inh, prop), "principal")
	assert.NotEqual(t, ref, AclAuditEntryID(`C:\other`, id, f, m, i, inh, prop), "path")
	assert.NotEqual(t, ref, AclAuditEntryID(p, id, f, m, i, "ObjectInherit", prop), "inheritance flags")
	assert.NotEqual(t, ref, AclAuditEntryID(p, id, f, m, i, inh, "InheritOnly"), "propagation flags")

	// and it must not collide with a discretionary entry on the same object
	assert.NotEqual(t, ref, AclEntryID(p, id, f, m, i, inh, prop))
}

func TestAclAuditScript(t *testing.T) {
	script := AclAuditScript(`C:\Program Files\it's here`)
	// single quoting is what makes a Windows path safe to interpolate: no
	// escape sequence is recognized inside it, so a backslash stays a
	// backslash. Only the quote itself needs escaping, by doubling it.
	assert.Contains(t, script, `$p='C:\Program Files\it''s here'`)
	// -Audit is what asks for the system access control list; without it
	// $a.Audit is empty on every object
	assert.Contains(t, script, "-Audit")
	assert.LessOrEqual(t, len(script), PSMaxScriptLength)
}
