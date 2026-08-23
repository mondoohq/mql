// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/activedirectory/connection"
	"go.mondoo.com/mql/types"
)

// parseADGeneralizedTime parses an Active Directory generalized time string
// (format "20060102150405.0Z") into a Go time.Time.
func parseADGeneralizedTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse("20060102150405.0Z", s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func (a *mqlActivedirectoryComputer) id() (string, error) {
	return a.DistinguishedName.Data, nil
}

func (a *mqlActivedirectory) computers() ([]interface{}, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	baseDN := conn.BaseDN()

	attrs := []string{
		"sAMAccountName",
		"dNSHostName",
		"distinguishedName",
		"objectSid",
		"userAccountControl",
		"operatingSystem",
		"operatingSystemVersion",
		"operatingSystemServicePack",
		"pwdLastSet",
		"lastLogonTimestamp",
		"whenCreated",
		"servicePrincipalName",
		"description",
		"msDS-AllowedToDelegateTo",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
		"ms-Mcs-AdmPwdExpirationTime",
		"msLAPS-PasswordExpirationTime",
	}

	result, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=computer)",
		attrs,
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to query computers: %w", err)
	}

	now := time.Now().UTC()
	res := make([]interface{}, 0, len(result))

	for _, entry := range result {
		samAccountName := connection.GetStringAttr(entry, "sAMAccountName")
		dn := connection.GetStringAttr(entry, "distinguishedName")
		uac := parseInt64Attr(connection.GetStringAttr(entry, "userAccountControl"))

		// Use dNSHostName as the display name, falling back to sAMAccountName.
		name := connection.GetStringAttr(entry, "dNSHostName")
		if name == "" {
			name = samAccountName
		}

		// SID
		sid := ""
		rawSid := connection.GetBinaryAttr(entry, "objectSid")
		if len(rawSid) > 0 {
			decoded, decErr := connection.DecodeSID(rawSid)
			if decErr != nil {
				log.Warn().Err(decErr).Str("dn", dn).Msg("failed to decode computer SID")
			} else {
				sid = decoded
			}
		}

		osName := connection.GetStringAttr(entry, "operatingSystem")
		osVersion := connection.GetStringAttr(entry, "operatingSystemVersion")
		osSP := connection.GetStringAttr(entry, "operatingSystemServicePack")
		desc := connection.GetStringAttr(entry, "description")

		pwdLastSet := connection.FileTimeToTime(parseInt64Attr(connection.GetStringAttr(entry, "pwdLastSet")))
		lastLogon := connection.FileTimeToTime(parseInt64Attr(connection.GetStringAttr(entry, "lastLogonTimestamp")))
		whenCreated := parseADGeneralizedTime(connection.GetStringAttr(entry, "whenCreated"))

		// Password age and last-logon staleness.
		var passwordAgeDays int64 = -1
		if !pwdLastSet.IsZero() {
			passwordAgeDays = int64(now.Sub(pwdLastSet).Hours() / 24)
		}

		var daysSinceLastLogon int64 = -1
		if !lastLogon.IsZero() {
			daysSinceLastLogon = int64(now.Sub(lastLogon).Hours() / 24)
		}

		isStale := daysSinceLastLogon >= 0 && daysSinceLastLogon > 90

		enabled := !uacHasFlag(uac, UACAccountDisable)
		unconstrainedDelegation := uacHasFlag(uac, UACTrustedForDelegation)
		isDomainController := uacHasFlag(uac, UACServerTrustAccount)
		protocolTransition := uacHasFlag(uac, UACTrustedToAuthForDelegation)

		// Constrained delegation
		delegateTargets := connection.GetStringSliceAttr(entry, "msDS-AllowedToDelegateTo")
		constrainedDelegation := len(delegateTargets) > 0
		delegateTargetsRaw := make([]interface{}, len(delegateTargets))
		for i, v := range delegateTargets {
			delegateTargetsRaw[i] = v
		}

		// Resource-Based Constrained Delegation (RBCD). The attribute is a
		// security descriptor; the principals named in its DACL are the
		// accounts that can impersonate onto this host.
		rbcdRaw := entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
		rbcd := len(rbcdRaw) > 0
		rbcdPrincipals := rbcdPrincipalSIDs(rbcdRaw)
		rbcdPrincipalsRaw := make([]interface{}, len(rbcdPrincipals))
		for i, v := range rbcdPrincipals {
			rbcdPrincipalsRaw[i] = v
		}

		// Service principal names
		spns := connection.GetStringSliceAttr(entry, "servicePrincipalName")
		spnsRaw := make([]interface{}, len(spns))
		for i, v := range spns {
			spnsRaw[i] = v
		}

		// LAPS
		legacyLaps := connection.GetStringAttr(entry, "ms-Mcs-AdmPwdExpirationTime")
		windowsLaps := connection.GetStringAttr(entry, "msLAPS-PasswordExpirationTime")
		lapsEnabled := legacyLaps != "" || windowsLaps != ""

		var lapsExpirationTime time.Time
		// Prefer Windows LAPS over legacy.
		if windowsLaps != "" {
			lapsExpirationTime = connection.FileTimeToTime(parseInt64Attr(windowsLaps))
		} else if legacyLaps != "" {
			lapsExpirationTime = connection.FileTimeToTime(parseInt64Attr(legacyLaps))
		}

		ouPath := extractOU(dn)

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.computer",
			map[string]*llx.RawData{
				"sAMAccountName":               llx.StringData(samAccountName),
				"name":                         llx.StringData(name),
				"distinguishedName":            llx.StringData(dn),
				"sid":                          llx.StringData(sid),
				"enabled":                      llx.BoolData(enabled),
				"operatingSystem":              llx.StringData(osName),
				"operatingSystemVersion":       llx.StringData(osVersion),
				"operatingSystemServicePack":   llx.StringData(osSP),
				"pwdLastSet":                   llx.TimeData(pwdLastSet),
				"lastLogonTimestamp":           llx.TimeData(lastLogon),
				"whenCreated":                  llx.TimeData(whenCreated),
				"passwordAgeDays":              llx.IntData(passwordAgeDays),
				"daysSinceLastLogon":           llx.IntData(daysSinceLastLogon),
				"isStale":                      llx.BoolData(isStale),
				"userAccountControl":           llx.IntData(uac),
				"unconstrainedDelegation":      llx.BoolData(unconstrainedDelegation),
				"constrainedDelegation":        llx.BoolData(constrainedDelegation),
				"constrainedDelegationTargets": llx.ArrayData(delegateTargetsRaw, types.String),
				"rbcd":                         llx.BoolData(rbcd),
				"rbcdPrincipals":               llx.ArrayData(rbcdPrincipalsRaw, types.String),
				"servicePrincipalNames":        llx.ArrayData(spnsRaw, types.String),
				"lapsEnabled":                  llx.BoolData(lapsEnabled),
				"lapsExpirationTime":           llx.TimeData(lapsExpirationTime),
				"description":                  llx.StringData(desc),
				"ouPath":                       llx.StringData(ouPath),
				"isDomainController":           llx.BoolData(isDomainController),
				"protocolTransition":           llx.BoolData(protocolTransition),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	return res, nil
}
