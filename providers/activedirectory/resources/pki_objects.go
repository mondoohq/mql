// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/activedirectory/connection"
	"go.mondoo.com/mql/types"
)

// pkiObjectClass picks the most specific objectClass value from a multi-valued
// attribute. If a known PKI class is present, it is preferred; otherwise the
// last value (most specific per LDAP convention) is returned.
func pkiObjectClass(classes []string) string {
	if len(classes) == 0 {
		return ""
	}
	known := map[string]bool{
		"container":              true,
		"certificationAuthority": true,
		"pKIEnrollmentService":   true,
		"msPKI-Enterprise-Oid":   true,
		"cRLDistributionPoint":   true,
	}
	for _, class := range slices.Backward(classes) {
		if known[class] {
			return class
		}
	}
	return classes[len(classes)-1]
}

func (a *mqlActivedirectory) pkiObjects() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)

	baseDN := fmt.Sprintf("CN=Public Key Services,CN=Services,%s", conn.ConfigDN())

	sdCtrl := ldap.NewControlMicrosoftSDFlags()
	sdCtrl.ControlValue = 0x7 // Owner + Group + DACL

	attrs := []string{
		"cn",
		"distinguishedName",
		"objectClass",
		"nTSecurityDescriptor",
		"whenCreated",
		"whenChanged",
	}

	entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		attrs,
		[]ldap.Control{sdCtrl},
	))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			log.Warn().Str("baseDN", baseDN).Msg("CN=Public Key Services not found, skipping PKI objects")
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to query PKI objects: %w", err)
	}

	res := make([]any, 0, len(entries))
	for _, entry := range entries {
		dn := connection.GetStringAttr(entry, "distinguishedName")

		// Skip the base container itself — we only want descendant objects.
		if strings.EqualFold(dn, baseDN) {
			continue
		}

		name := connection.GetStringAttr(entry, "cn")
		classes := connection.GetStringSliceAttr(entry, "objectClass")
		objClass := pkiObjectClass(classes)
		whenCreated := parseADGeneralizedTime(connection.GetStringAttr(entry, "whenCreated"))
		whenChanged := parseADGeneralizedTime(connection.GetStringAttr(entry, "whenChanged"))

		// ESC5: check for dangerous write-equivalent ACLs held by low-priv
		// principals, using the shared SD parser from sd_helpers.go.
		var isVulnESC5 bool
		var dangerousPrincipals []string
		sd := connection.GetBinaryAttr(entry, "nTSecurityDescriptor")
		if len(sd) > 0 {
			parsed := parseSecurityDescriptor(sd)
			for _, ace := range parsed.aces {
				if ace.aceType != 0 { // only ACCESS_ALLOWED
					continue
				}
				if !hasDangerousRights(ace.mask) {
					continue
				}
				if isLowPrivSID(ace.sid) {
					dangerousPrincipals = append(dangerousPrincipals, ace.sid)
				}
			}
			isVulnESC5 = len(dangerousPrincipals) > 0
		}

		principalItems := make([]any, len(dangerousPrincipals))
		for i, p := range dangerousPrincipals {
			principalItems[i] = p
		}

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.pkiObject",
			map[string]*llx.RawData{
				"name":                   llx.StringData(name),
				"distinguishedName":      llx.StringData(dn),
				"objectClass":            llx.StringData(objClass),
				"whenCreated":            llx.TimeData(whenCreated),
				"whenChanged":            llx.TimeData(whenChanged),
				"isVulnerableESC5":       llx.BoolData(isVulnESC5),
				"dangerousAclPrincipals": llx.ArrayData(principalItems, types.String),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	return res, nil
}
