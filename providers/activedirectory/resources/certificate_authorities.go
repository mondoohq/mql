// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/activedirectory/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlActivedirectory) certificateAuthorities() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	baseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", conn.ConfigDN())

	attrs := []string{
		"cn",
		"distinguishedName",
		"dNSHostName",
		"certificateTemplates",
		"cACertificate",
		"nTSecurityDescriptor",
		"msPKI-Enrollment-Servers",
		"msPKI-RA-Policies",
	}

	sdCtrl := ldap.NewControlMicrosoftSDFlags()
	sdCtrl.ControlValue = 0x7 // Owner + Group + DACL

	entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=pKIEnrollmentService)",
		attrs,
		[]ldap.Control{sdCtrl},
	))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			log.Warn().Msg("ADCS Enrollment Services container not found, ADCS may not be installed")
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to query certificate authorities: %w", err)
	}

	res := make([]any, 0, len(entries))
	for _, entry := range entries {
		name := connection.GetStringAttr(entry, "cn")
		dn := connection.GetStringAttr(entry, "distinguishedName")
		dnsHostname := connection.GetStringAttr(entry, "dNSHostName")

		// Parse certificate expiration and infer whether the Enterprise CA is root
		// or subordinate from the published CA certificate.
		caType := "Enterprise"
		var certExpiration time.Time
		rawCert := entry.GetRawAttributeValue("cACertificate")
		if len(rawCert) > 0 {
			cert, parseErr := x509.ParseCertificate(rawCert)
			if parseErr != nil {
				log.Warn().Err(parseErr).Str("ca", name).Msg("failed to parse cACertificate, using zero time for expiration")
			} else {
				certExpiration = cert.NotAfter.UTC()
				if cert.CheckSignatureFrom(cert) == nil {
					caType = "Enterprise Root"
				} else {
					caType = "Enterprise Subordinate"
				}
			}
		}

		// Template names are CN values, not full DNs.
		templates := connection.GetStringSliceAttr(entry, "certificateTemplates")
		templatesRaw := make([]any, len(templates))
		for i, v := range templates {
			templatesRaw[i] = v
		}

		// ESC7: Check for principals with ManageCA or ManageCertificates rights.
		// The CA enrollment service object uses CA-specific access mask bits:
		//   0x01 = ManageCA (allows reconfiguring EDITF_ATTRIBUTESUBJECTALTNAME2)
		//   0x02 = ManageCertificates (allows issuing/denying pending requests)
		// We also flag generic dangerous rights (GenericAll, WriteDACL, WriteOwner)
		// which implicitly include the CA-specific rights.
		const (
			rightManageCA           uint32 = 0x01
			rightManageCertificates uint32 = 0x02
		)
		var dangerousCAPerms []string
		isVulnerableESC7 := false
		rawSD := connection.GetBinaryAttr(entry, "nTSecurityDescriptor")
		if len(rawSD) > 0 {
			parsed := parseSecurityDescriptor(rawSD)
			seen := make(map[string]bool)
			for _, ace := range parsed.aces {
				if ace.aceType == 0x01 { // DENY — skip
					continue
				}
				const inheritedACE = 0x10
				if ace.aceFlags&inheritedACE != 0 {
					continue
				}
				hasCARight := ace.mask&rightManageCA != 0 || ace.mask&rightManageCertificates != 0
				if hasCARight || hasDangerousRights(ace.mask) {
					if !seen[ace.sid] {
						dangerousCAPerms = append(dangerousCAPerms, ace.sid)
						seen[ace.sid] = true
					}
					if isLowPrivSID(ace.sid) {
						isVulnerableESC7 = true
					}
				}
			}
		}
		dangerousCAPermsRaw := make([]any, len(dangerousCAPerms))
		for i, v := range dangerousCAPerms {
			dangerousCAPermsRaw[i] = v
		}

		// ESC8: Check for HTTP enrollment endpoints.
		// msPKI-Enrollment-Servers is multi-valued; each value is a newline-separated
		// record containing priority, auth type, and URL. Extract URLs and flag HTTP.
		enrollmentServers := connection.GetStringSliceAttr(entry, "msPKI-Enrollment-Servers")
		var httpEndpoints []string
		hasHTTPEnrollment := false
		for _, srv := range enrollmentServers {
			// Each value may contain newline-delimited fields; extract URL lines.
			lines := strings.SplitSeq(srv, "\n")
			for line := range lines {
				trimmed := strings.TrimSpace(line)
				lower := strings.ToLower(trimmed)
				if strings.HasPrefix(lower, "http://") {
					httpEndpoints = append(httpEndpoints, trimmed)
					hasHTTPEnrollment = true
				} else if strings.HasPrefix(lower, "https://") {
					httpEndpoints = append(httpEndpoints, trimmed)
				}
			}
		}
		httpEndpointsRaw := make([]any, len(httpEndpoints))
		for i, v := range httpEndpoints {
			httpEndpointsRaw[i] = v
		}

		// Enrollment agent restrictions: msPKI-RA-Policies is set on the CA when
		// an admin configures restrictions on which enrollment agents can enroll
		// on behalf of which users for which templates.
		raPolicies := connection.GetStringSliceAttr(entry, "msPKI-RA-Policies")
		enrollmentAgentRestrictions := len(raPolicies) > 0

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.certificateAuthority",
			map[string]*llx.RawData{
				"name":                                  llx.StringData(name),
				"distinguishedName":                     llx.StringData(dn),
				"dnsHostname":                           llx.StringData(dnsHostname),
				"caType":                                llx.StringData(caType),
				"certificateTemplates":                  llx.ArrayData(templatesRaw, types.String),
				"certificateExpiration":                 llx.TimeData(certExpiration),
				"isVulnerableESC7":                      llx.BoolData(isVulnerableESC7),
				"dangerousCAPermissions":                llx.ArrayData(dangerousCAPermsRaw, types.String),
				"httpEnrollmentEndpoints":               llx.ArrayData(httpEndpointsRaw, types.String),
				"hasHttpEnrollment":                     llx.BoolData(hasHTTPEnrollment),
				"enrollmentAgentRestrictionsConfigured": llx.BoolData(enrollmentAgentRestrictions),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	return res, nil
}
