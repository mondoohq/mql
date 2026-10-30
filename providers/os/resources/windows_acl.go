// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// mqlWindowsAclInternal caches the one Get-Acl call behind every field, so a
// query that reads the owner, the entries and the write principals of a path
// costs one PowerShell process rather than three.
type mqlWindowsAclInternal struct {
	lock    sync.Mutex
	fetched bool
	data    *windows.WindowsAcl
	// the system access control list is a separate command behind a separate
	// privilege, so it is cached separately: a session that cannot read the
	// audit rules must still be able to read the permissions
	auditFetched bool
	auditData    *windows.WindowsAclAudit
}

func (a *mqlWindowsAcl) id() (string, error) {
	return windows.AclID(a.Path.Data), nil
}

// acl reads the access control list of the path.
//
// A path that cannot be read is an error, never an empty list. An audit of the
// form "only these accounts may write here" has to fail when the path is
// missing or unreadable: an empty entry list satisfies every assertion made
// about it, which is the worst possible answer.
func (a *mqlWindowsAcl) acl() (*windows.WindowsAcl, error) {
	// The guard is read under the lock, never before it. A fast path that
	// tests the flag first is a data race: the goroutine that publishes the
	// result writes the flag and the pointer with no happens-before edge to
	// the reader, so a racing accessor can see the flag set and the data still
	// nil. The lock is uncontended in the common case and the work it guards
	// is a remote command, so there is nothing to win by skipping it.
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.data, nil
	}

	path := a.Path.Data
	if path == "" {
		return nil, errors.New("windows.acl requires a path")
	}

	conn, ok := a.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("windows.acl is not supported on this connection")
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, errors.New("windows.acl requires a connection that can run commands")
	}

	executedCmd, err := conn.RunCommand(powershell.Encode(windows.AclScript(path)))
	if err != nil {
		return nil, err
	}
	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to read the access control list of " + path + ": " + string(stderr))
	}

	data, err := windows.ParseWindowsAcl(executedCmd.Stdout)
	if err != nil {
		return nil, err
	}

	a.data = data
	a.fetched = true
	return a.data, nil
}

func (a *mqlWindowsAcl) owner() (string, error) {
	acl, err := a.acl()
	if err != nil {
		return "", err
	}
	return acl.Owner, nil
}

func (a *mqlWindowsAcl) ownerSid() (string, error) {
	acl, err := a.acl()
	if err != nil {
		return "", err
	}
	return acl.OwnerSid, nil
}

func (a *mqlWindowsAcl) group() (string, error) {
	acl, err := a.acl()
	if err != nil {
		return "", err
	}
	return acl.Group, nil
}

func (a *mqlWindowsAcl) sddl() (string, error) {
	acl, err := a.acl()
	if err != nil {
		return "", err
	}
	return acl.Sddl, nil
}

// inheritanceEnabled inverts the protected flag: Windows reports whether
// inheritance has been blocked, which is the opposite of what a reader expects
// a field called "inheritance" to mean.
func (a *mqlWindowsAcl) inheritanceEnabled() (bool, error) {
	acl, err := a.acl()
	if err != nil {
		return false, err
	}
	return !acl.Protected, nil
}

func (a *mqlWindowsAcl) entries() ([]any, error) {
	acl, err := a.acl()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(acl.Access))
	for _, e := range acl.Access {
		r, err := CreateResource(a.MqlRuntime, "windows.acl.entry", map[string]*llx.RawData{
			// The same account appears more than once on one object: allowing
			// and denying, inherited and set directly, with different rights
			// and different propagation. Every one of those is in the id, or
			// the second entry reports the first one's rights.
			"__id":                   llx.StringData(windows.AclEntryID(acl.Path, e.Identity, e.Type, e.Mask, e.Inherited, e.InheritanceFlags, e.PropagationFlags)),
			"identity":               llx.StringData(e.Identity),
			"sid":                    llx.StringData(e.Sid),
			"type":                   llx.StringData(e.Type),
			"rights":                 llx.StringData(e.Rights),
			"rightsMask":             llx.IntData(e.Mask),
			"allowsRead":             llx.BoolData(e.AllowsRead()),
			"allowsWrite":            llx.BoolData(e.AllowsWrite()),
			"allowsExecute":          llx.BoolData(e.AllowsExecute()),
			"allowsDelete":           llx.BoolData(e.AllowsDelete()),
			"allowsFullControl":      llx.BoolData(e.AllowsFullControl()),
			"allowsPermissionChange": llx.BoolData(e.AllowsPermissionChange()),
			"isInherited":            llx.BoolData(e.Inherited),
			"inheritanceFlags":       llx.StringData(e.InheritanceFlags),
			"propagationFlags":       llx.StringData(e.PropagationFlags),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (a *mqlWindowsAcl) allowedWritePrincipals() ([]any, error) {
	acl, err := a.acl()
	if err != nil {
		return nil, err
	}
	return strSliceToAny(acl.AllowedWritePrincipals()), nil
}

// acl resolves the Windows access control list of a file, so an audit can
// reach it through files.find as well as by naming a path directly.
//
// Null on a system that does not use Windows security descriptors, where
// file.permissions is the right thing to read.
func (s *mqlFile) acl(path string) (*mqlWindowsAcl, error) {
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		s.Acl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pf := conn.Asset().Platform
	if pf == nil || !pf.IsFamily("windows") {
		s.Acl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	o, err := CreateResource(s.MqlRuntime, "windows.acl", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsAcl), nil
}

// auditAcl reads the system access control list of the path, the rules that
// decide what the object audits.
//
// This is a separate command from acl, behind a separate cache, because it is
// behind a separate privilege. Reading a system access control list requires
// SeSecurityPrivilege, which an unelevated session does not hold, and folding
// the two reads together would cost such a session the permissions as well.
//
// A path whose audit rules cannot be read is an error, never an empty list.
// "Nothing is audited here" and "the audit rules could not be read" satisfy an
// audit assertion identically, and only the first is an answer.
func (a *mqlWindowsAcl) auditAcl() (*windows.WindowsAclAudit, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.auditFetched {
		return a.auditData, nil
	}

	path := a.Path.Data
	if path == "" {
		return nil, errors.New("windows.acl requires a path")
	}

	// the message names what was attempted and lets the command's own stderr
	// give the reason. Naming SeSecurityPrivilege here would assert it as the
	// cause even when the real one is a path that does not exist, which is
	// what a missing directory reported before.
	stdout, err := runWindowsPowerShell(a.MqlRuntime, windows.AclAuditScript(path),
		"read the audit rules of "+path)
	if err != nil {
		return nil, err
	}

	data, err := windows.ParseWindowsAclAudit(stdout)
	if err != nil {
		return nil, err
	}

	a.auditData = data
	a.auditFetched = true
	return a.auditData, nil
}

func (a *mqlWindowsAcl) auditEntries() ([]any, error) {
	audit, err := a.auditAcl()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(audit.Audit))
	for _, e := range audit.Audit {
		r, err := CreateResource(a.MqlRuntime, "windows.acl.auditEntry", map[string]*llx.RawData{
			// one principal is audited more than once on one object: success
			// on one set of rights and failure on another, inherited and set
			// directly. Every one of those is in the id, or the second entry
			// reports the first one's rights.
			"__id":             llx.StringData(windows.AclAuditEntryID(audit.Path, e.Identity, e.AuditFlags, e.Mask, e.Inherited, e.InheritanceFlags, e.PropagationFlags)),
			"identity":         llx.StringData(e.Identity),
			"sid":              llx.StringData(e.Sid),
			"auditFlags":       llx.StringData(e.AuditFlags),
			"auditsSuccess":    llx.BoolData(e.AuditsSuccess()),
			"auditsFailure":    llx.BoolData(e.AuditsFailure()),
			"rights":           llx.StringData(e.Rights),
			"rightsMask":       llx.IntData(e.Mask),
			"isInherited":      llx.BoolData(e.Inherited),
			"inheritanceFlags": llx.StringData(e.InheritanceFlags),
			"propagationFlags": llx.StringData(e.PropagationFlags),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}
