// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

// Extended-right GUIDs for DCSync detection (ACCESS_ALLOWED_OBJECT_ACE type 5).
const (
	guidDSReplicationGetChanges    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	guidDSReplicationGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	guidForceChangePassword        = "00299570-246d-11d0-a768-00aa006e0529"
)

// rightTypeLabel returns a human-readable name for the dangerous right.
// For object ACEs (type 5), the objectGUID narrows the right. For basic
// ACEs, only the mask matters.
func rightTypeLabel(ace aceEntry) string {
	if ace.aceType == 0x05 {
		switch ace.objectGUID {
		case guidDSReplicationGetChanges:
			return "DS-Replication-Get-Changes"
		case guidDSReplicationGetChangesAll:
			return "DS-Replication-Get-Changes-All"
		case guidForceChangePassword:
			return "ForceChangePassword"
		}
	}
	if ace.aceType == 0x05 && ace.objectGUID == "" && ace.mask&rightDSControlAccess != 0 {
		return "AllExtendedRights"
	}

	switch {
	case ace.mask&rightGenericAll != 0:
		return "GenericAll"
	case ace.mask&rightWriteOwner != 0:
		return "WriteOwner"
	case ace.mask&rightWriteDACL != 0:
		return "WriteDACL"
	case ace.mask&rightGenericWrite != 0:
		return "GenericWrite"
	default:
		return fmt.Sprintf("0x%08x", ace.mask)
	}
}

// criticalTarget is an AD object to scan for dangerous ACL delegations.
type criticalTarget struct {
	dn         string
	name       string
	targetType string // domain, adminSDHolder, group, computer
}

// discoverCriticalTargets returns the set of AD objects whose DACLs should
// be audited. The list is built from well-known containers and a lightweight
// search for privileged groups and domain controllers.
func discoverCriticalTargets(conn *connection.ActiveDirectoryConnection) ([]criticalTarget, error) {
	baseDN := conn.BaseDN()
	targets := []criticalTarget{
		{dn: baseDN, name: "Domain Head", targetType: "domain"},
		{dn: fmt.Sprintf("CN=AdminSDHolder,CN=System,%s", baseDN), name: "AdminSDHolder", targetType: "adminSDHolder"},
	}

	// Privileged groups: search by well-known RIDs instead of hard-coding
	// names (which vary by language). Domain Admins = 512, Enterprise
	// Admins = 519, Schema Admins = 518, Account Operators = 548,
	// Backup Operators = 551, Server Operators = 549.
	// For domain-relative groups, it's easier to search by adminCount and
	// filter in code. We query groups where adminCount=1 (these are the
	// groups protected by AdminSDHolder = privileged).
	privGroupSearch := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectCategory=group)(adminCount=1))",
		[]string{"distinguishedName", "sAMAccountName"},
		nil,
	)

	privEntries, err := connection.PagedSearch(conn.LDAPConn(), privGroupSearch)
	if err != nil {
		return nil, fmt.Errorf("enumerating privileged groups for ACL scan: %w", err)
	}
	for _, e := range privEntries {
		targets = append(targets, criticalTarget{
			dn:         connection.GetStringAttr(e, "distinguishedName"),
			name:       connection.GetStringAttr(e, "sAMAccountName"),
			targetType: "group",
		})
	}

	// Domain Controllers.
	dcSearch := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"distinguishedName", "sAMAccountName"},
		nil,
	)
	dcEntries, err := connection.PagedSearch(conn.LDAPConn(), dcSearch)
	if err != nil {
		return nil, fmt.Errorf("enumerating domain controllers for ACL scan: %w", err)
	}
	for _, e := range dcEntries {
		targets = append(targets, criticalTarget{
			dn:         connection.GetStringAttr(e, "distinguishedName"),
			name:       connection.GetStringAttr(e, "sAMAccountName"),
			targetType: "computer",
		})
	}

	return targets, nil
}

// scanTargetACL reads the nTSecurityDescriptor for a single target and
// returns all dangerous permission findings.
func scanTargetACL(conn *connection.ActiveDirectoryConnection, target criticalTarget) ([]dangerousPermFinding, error) {
	sdCtrl := ldap.NewControlMicrosoftSDFlags()
	sdCtrl.ControlValue = 0x7 // Owner + Group + DACL

	req := ldap.NewSearchRequest(
		target.dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"nTSecurityDescriptor"},
		[]ldap.Control{sdCtrl},
	)

	sr, err := conn.LDAPConn().Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			log.Debug().Str("dn", target.dn).Msg("ACL target not found, skipping")
			return nil, nil
		}
		return nil, fmt.Errorf("ACL scan for %s: %w", target.dn, err)
	}
	if len(sr.Entries) == 0 {
		return nil, nil
	}

	sd := connection.GetBinaryAttr(sr.Entries[0], "nTSecurityDescriptor")
	if len(sd) == 0 {
		return nil, nil
	}

	parsed := parseSecurityDescriptor(sd)

	var findings []dangerousPermFinding

	// Dedup: same SID + right on the same target only counts once.
	seen := make(map[string]bool)

	for _, ace := range parsed.aces {
		if ace.aceType == 0x01 { // ACCESS_DENIED — skip
			continue
		}
		// Skip inherited ACEs — they come from parent containers and are
		// not direct delegations on this object.
		const inheritedACE = 0x10
		if ace.aceFlags&inheritedACE != 0 {
			continue
		}

		dangerous := false

		switch ace.aceType {
		case 0x05: // Object ACE
			switch ace.objectGUID {
			case guidDSReplicationGetChanges, guidDSReplicationGetChangesAll, guidForceChangePassword:
				dangerous = true
			case "": // Empty objectGUID = All Extended Rights (includes replication)
				if ace.mask&rightDSControlAccess != 0 {
					dangerous = true
				}
			}
			if !dangerous && hasDangerousRights(ace.mask) {
				dangerous = true
			}
		case 0x00: // Basic ACE
			dangerous = hasDangerousRights(ace.mask)
		}

		if !dangerous {
			continue
		}
		label := rightTypeLabel(ace)
		// Dedup on SID + label + mask. The same principal may have multiple
		// ACEs that differ only in InheritedObjectType (controlling which child
		// object classes the right propagates to); we collapse these.
		key := fmt.Sprintf("%s|%s|%d", ace.sid, label, ace.mask)
		if seen[key] {
			continue
		}
		seen[key] = true

		findings = append(findings, dangerousPermFinding{
			targetDN:     target.dn,
			targetName:   target.name,
			targetType:   target.targetType,
			principalSID: ace.sid,
			rightType:    label,
			accessMask:   ace.mask,
		})
	}

	return findings, nil
}

// dangerousPermFinding is the intermediate result before creating MQL resources.
type dangerousPermFinding struct {
	targetDN     string
	targetName   string
	targetType   string
	principalSID string
	rightType    string
	accessMask   uint32
}

func (a *mqlActivedirectory) dangerousPermissions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)

	targets, err := discoverCriticalTargets(conn)
	if err != nil {
		return nil, err
	}
	log.Debug().Int("targetCount", len(targets)).Msg("scanning critical objects for dangerous ACLs")

	var allFindings []dangerousPermFinding
	for _, target := range targets {
		findings, err := scanTargetACL(conn, target)
		if err != nil {
			log.Warn().Err(err).Str("dn", target.dn).Msg("ACL scan failed for target")
			continue
		}
		log.Debug().Int("findings", len(findings)).Str("target", target.name).Msg("ACL target scanned")
		allFindings = append(allFindings, findings...)
	}
	log.Debug().Int("totalFindings", len(allFindings)).Int("targets", len(targets)).Msg("dangerous permission scan complete")

	res := make([]any, 0, len(allFindings))
	for _, f := range allFindings {
		resource, err := CreateResource(a.MqlRuntime, "activedirectory.dangerousPermission",
			map[string]*llx.RawData{
				"targetDN":     llx.StringData(f.targetDN),
				"targetName":   llx.StringData(f.targetName),
				"targetType":   llx.StringData(f.targetType),
				"principalSID": llx.StringData(f.principalSID),
				"rightType":    llx.StringData(f.rightType),
				"accessMask":   llx.IntData(int64(f.accessMask)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}

	return res, nil
}
