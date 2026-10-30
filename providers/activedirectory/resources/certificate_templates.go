// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/activedirectory/connection"
	"go.mondoo.com/mql/types"
)

// Authentication and enrollment EKU OIDs.
const (
	ekuClientAuth       = "1.3.6.1.5.5.7.3.2"
	ekuPKINITClient     = "1.3.6.1.5.2.3.4"
	ekuSmartCardLogon   = "1.3.6.1.4.1.311.20.2.2"
	ekuAnyPurpose       = "2.5.29.37.0"
	ekuCertRequestAgent = "1.3.6.1.4.1.311.20.2.1"

	// Extended right GUIDs for enrollment permissions (lowercase).
	guidCertificateEnrollment = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	guidAutoEnroll            = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

	// Certificate name flag: enrollee supplies subject.
	ctFlagEnrolleeSuppliesSubject = 0x1

	// Enrollment flag: pend all requests (manager approval).
	ctFlagPendAllRequests = 0x2

	// Enrollment flag: no security extension in issued cert (ESC9).
	ctFlagNoSecurityExtension int64 = 0x00080000
)

// getPublishedTemplates returns the set of certificate template CN names
// published on at least one enrollment service (CA). The result is cached
// on the connection.
func getPublishedTemplates(conn *connection.ActiveDirectoryConnection) (map[string]bool, error) {
	raw, err := conn.CachedFetch("publishedTemplates", func() (any, error) {
		searchBase := "CN=Enrollment Services,CN=Public Key Services,CN=Services," + conn.ConfigDN()

		entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
			searchBase,
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=pKIEnrollmentService)",
			[]string{"certificateTemplates"},
			nil,
		))
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				return make(map[string]bool), nil
			}
			return nil, fmt.Errorf("querying enrollment services: %w", err)
		}

		published := make(map[string]bool)
		for _, entry := range entries {
			for _, tmpl := range connection.GetStringSliceAttr(entry, "certificateTemplates") {
				published[tmpl] = true
			}
		}
		return published, nil
	})
	if err != nil {
		return nil, err
	}
	return raw.(map[string]bool), nil
}

// resolveOIDGroupLinks queries the OID container under Public Key Services for
// enterprise OID objects that have msDS-OIDToGroupLink set (ESC13 prerequisite).
// Returns a map of OID string -> linked group DN. Cached on the connection.
func resolveOIDGroupLinks(conn *connection.ActiveDirectoryConnection) (map[string]string, error) {
	raw, err := conn.CachedFetch("oidGroupLinks", func() (any, error) {
		baseDN := fmt.Sprintf("CN=OID,CN=Public Key Services,CN=Services,%s", conn.ConfigDN())

		entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))",
			[]string{"msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"},
			nil,
		))
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				return make(map[string]string), nil
			}
			return nil, fmt.Errorf("querying OID group links: %w", err)
		}

		links := make(map[string]string, len(entries))
		for _, e := range entries {
			oid := connection.GetStringAttr(e, "msPKI-Cert-Template-OID")
			groupDN := connection.GetStringAttr(e, "msDS-OIDToGroupLink")
			if oid != "" && groupDN != "" {
				links[oid] = groupDN
			}
		}
		return links, nil
	})
	if err != nil {
		return nil, err
	}
	return raw.(map[string]string), nil
}

func (a *mqlActivedirectory) certificateTemplates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	searchBase := "CN=Certificate Templates,CN=Public Key Services,CN=Services," + conn.ConfigDN()

	attrs := []string{
		"cn",
		"displayName",
		"distinguishedName",
		"msPKI-Cert-Template-OID",
		"pKIExtendedKeyUsage",
		"msPKI-Certificate-Name-Flag",
		"msPKI-Enrollment-Flag",
		"msPKI-RA-Signature",
		"msPKI-Template-Schema-Version",
		"pKIExpirationPeriod",
		"msPKI-Certificate-Policy",
		"pKIOverlapPeriod",
		"nTSecurityDescriptor",
		"whenCreated",
		"whenChanged",
	}

	sdCtrl := ldap.NewControlMicrosoftSDFlags()
	sdCtrl.ControlValue = 0x7 // Owner + Group + DACL

	entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=pKICertificateTemplate)",
		attrs,
		[]ldap.Control{sdCtrl},
	))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			log.Warn().Msg("ADCS Certificate Templates container not found, ADCS may not be installed")
			return []any{}, nil
		}
		return nil, fmt.Errorf("querying certificate templates: %w", err)
	}

	publishedSet, err := getPublishedTemplates(conn)
	if err != nil {
		return nil, err
	}

	oidLinks, err := resolveOIDGroupLinks(conn)
	if err != nil {
		return nil, err
	}

	privSets, err := buildPrivilegedMembershipSets(conn)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(entries))

	for _, entry := range entries {
		cn := connection.GetStringAttr(entry, "cn")
		displayName := connection.GetStringAttr(entry, "displayName")
		dn := connection.GetStringAttr(entry, "distinguishedName")
		oid := connection.GetStringAttr(entry, "msPKI-Cert-Template-OID")
		schemaVersion := parseInt64Attr(connection.GetStringAttr(entry, "msPKI-Template-Schema-Version"))
		authorizedSigs := parseInt64Attr(connection.GetStringAttr(entry, "msPKI-RA-Signature"))
		enrollmentFlags := parseInt64Attr(connection.GetStringAttr(entry, "msPKI-Enrollment-Flag"))
		certNameFlags := parseInt64Attr(connection.GetStringAttr(entry, "msPKI-Certificate-Name-Flag"))
		whenCreated := parseADGeneralizedTime(connection.GetStringAttr(entry, "whenCreated"))
		whenChanged := parseADGeneralizedTime(connection.GetStringAttr(entry, "whenChanged"))

		ekus := connection.GetStringSliceAttr(entry, "pKIExtendedKeyUsage")
		ekuSet := make(map[string]bool, len(ekus))
		for _, e := range ekus {
			ekuSet[e] = true
		}

		hasAuthEKU := ekuSet[ekuClientAuth] || ekuSet[ekuPKINITClient] || ekuSet[ekuSmartCardLogon]
		hasAnyPurposeEKU := ekuSet[ekuAnyPurpose]
		hasNoEKU := len(ekus) == 0

		enrolleeSuppliesSubject := certNameFlags&ctFlagEnrolleeSuppliesSubject != 0
		managerApproval := enrollmentFlags&ctFlagPendAllRequests != 0
		noSecurityExtension := enrollmentFlags&ctFlagNoSecurityExtension != 0
		isPublished := publishedSet[cn]

		// Parse security descriptor for enrollment permissions and ESC4.
		sdRaw := connection.GetBinaryAttr(entry, "nTSecurityDescriptor")
		sd := parseSecurityDescriptor(sdRaw)

		enrollPerms, lowPrivEnroll := extractEnrollmentPermissions(sd)
		isESC4 := checkESC4(sd)

		validityPeriod := parseADDuration(entry.GetRawAttributeValue("pKIExpirationPeriod"))
		renewalPeriod := parseADDuration(entry.GetRawAttributeValue("pKIOverlapPeriod"))

		// EKU list for resource field.
		ekusRaw := make([]any, len(ekus))
		for i, v := range ekus {
			ekusRaw[i] = v
		}

		enrollPermsRaw := make([]any, len(enrollPerms))
		for i, v := range enrollPerms {
			enrollPermsRaw[i] = v
		}

		// ESC vulnerability checks.
		isESC1 := isPublished && enrolleeSuppliesSubject && hasAuthEKU &&
			lowPrivEnroll && !managerApproval && authorizedSigs == 0
		isESC2 := isPublished && (hasAnyPurposeEKU || hasNoEKU) &&
			lowPrivEnroll && !managerApproval
		isESC3 := isPublished && ekuSet[ekuCertRequestAgent] && lowPrivEnroll

		// ESC9: CT_FLAG_NO_SECURITY_EXTENSION set, has auth EKU, low-priv enrollment.
		// Without the SID extension the DC cannot enforce strong certificate binding,
		// allowing an attacker to authenticate as another principal.
		isESC9 := isPublished && noSecurityExtension && hasAuthEKU &&
			lowPrivEnroll && !managerApproval

		// Issuance policy OIDs for ESC13 analysis.
		certPolicies := connection.GetStringSliceAttr(entry, "msPKI-Certificate-Policy")
		isESC13 := false
		if isPublished && lowPrivEnroll {
			for _, policyOID := range certPolicies {
				if groupDN, ok := oidLinks[policyOID]; ok {
					if privSets.AllPrivileged[groupDN] {
						isESC13 = true
						break
					}
				}
			}
		}
		certPoliciesRaw := make([]any, len(certPolicies))
		for i, v := range certPolicies {
			certPoliciesRaw[i] = v
		}

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.certificateTemplate",
			map[string]*llx.RawData{
				"name":                         llx.StringData(cn),
				"displayName":                  llx.StringData(displayName),
				"distinguishedName":            llx.StringData(dn),
				"oid":                          llx.StringData(oid),
				"schemaVersion":                llx.IntData(schemaVersion),
				"enrolleeSuppliesSubject":      llx.BoolData(enrolleeSuppliesSubject),
				"extendedKeyUsages":            llx.ArrayData(ekusRaw, types.String),
				"hasAuthenticationEku":         llx.BoolData(hasAuthEKU),
				"hasAnyPurposeEku":             llx.BoolData(hasAnyPurposeEKU),
				"hasNoEku":                     llx.BoolData(hasNoEKU),
				"managerApprovalRequired":      llx.BoolData(managerApproval),
				"authorizedSignaturesRequired": llx.IntData(authorizedSigs),
				"enrollmentFlags":              llx.IntData(enrollmentFlags),
				"certificateNameFlags":         llx.IntData(certNameFlags),
				"validityPeriod":               llx.StringData(validityPeriod),
				"renewalPeriod":                llx.StringData(renewalPeriod),
				"isPublished":                  llx.BoolData(isPublished),
				"isVulnerableESC1":             llx.BoolData(isESC1),
				"isVulnerableESC2":             llx.BoolData(isESC2),
				"isVulnerableESC3":             llx.BoolData(isESC3),
				"isVulnerableESC4":             llx.BoolData(isESC4),
				"noSecurityExtension":          llx.BoolData(noSecurityExtension),
				"isVulnerableESC9":             llx.BoolData(isESC9),
				"issuancePolicies":             llx.ArrayData(certPoliciesRaw, types.String),
				"isVulnerableESC13":            llx.BoolData(isESC13),
				"enrollmentPermissions":        llx.ArrayData(enrollPermsRaw, types.String),
				"lowPrivilegedEnrollment":      llx.BoolData(lowPrivEnroll),
				"whenCreated":                  llx.TimeData(whenCreated),
				"whenChanged":                  llx.TimeData(whenChanged),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	return res, nil
}

// extractEnrollmentPermissions scans the parsed SD for ACEs that grant
// certificate enrollment or auto-enroll rights. Returns the list of SIDs
// with enrollment permission and whether any low-privilege SID has it.
func extractEnrollmentPermissions(sd parsedSD) ([]string, bool) {
	var sids []string
	lowPriv := false

	for _, ace := range sd.aces {
		if ace.aceType == 0x05 {
			// Object ACE: check if the object type GUID matches enrollment rights.
			guid := strings.ToLower(ace.objectGUID)
			if guid != guidCertificateEnrollment && guid != guidAutoEnroll {
				continue
			}
		} else if ace.aceType == 0x00 {
			// Basic allow ACE: check for GenericAll or extended rights (bit 0x100).
			if ace.mask&rightGenericAll == 0 && ace.mask&0x00000100 == 0 {
				continue
			}
		} else {
			continue
		}

		sids = append(sids, ace.sid)
		if isLowPrivSID(ace.sid) {
			lowPriv = true
		}
	}

	return sids, lowPriv
}

// checkESC4 returns true if any non-admin (low-privilege) SID has dangerous
// write permissions on the certificate template.
func checkESC4(sd parsedSD) bool {
	for _, ace := range sd.aces {
		if ace.aceType != 0x00 && ace.aceType != 0x05 {
			continue
		}
		if !hasDangerousRights(ace.mask) {
			continue
		}
		if isLowPrivSID(ace.sid) {
			return true
		}
	}
	return false
}

// parseADDuration converts an 8-byte Active Directory duration value
// (pKIExpirationPeriod, pKIOverlapPeriod) to a human-readable string.
// The value is a negative 64-bit integer counting 100-nanosecond intervals.
func parseADDuration(raw []byte) string {
	if len(raw) != 8 {
		return "unknown"
	}

	// Interpret as signed little-endian 64-bit, negate to get positive interval.
	ticks := int64(binary.LittleEndian.Uint64(raw))
	if ticks >= 0 {
		return "unknown"
	}
	ticks = -ticks

	dur := time.Duration(ticks) * 100 // 100ns per tick

	// Convert to the most human-readable unit.
	const (
		day  = 24 * time.Hour
		week = 7 * day
		year = 365 * day
	)

	switch {
	case dur >= year && dur%year == 0:
		n := dur / year
		return pluralize(int(n), "year")
	case dur >= week && dur%week == 0:
		n := dur / week
		return pluralize(int(n), "week")
	case dur >= day && dur%day == 0:
		n := dur / day
		return pluralize(int(n), "day")
	case dur >= time.Hour && dur%time.Hour == 0:
		n := dur / time.Hour
		return pluralize(int(n), "hour")
	default:
		// Fall back to days if not evenly divisible.
		n := dur / day
		if n == 0 {
			n = 1
		}
		return pluralize(int(n), "day")
	}
}

// pluralize returns "N unit" or "N units" as appropriate.
func pluralize(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
