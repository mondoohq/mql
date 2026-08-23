// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/activedirectory/connection"
	"go.mondoo.com/mql/types"
)

// userObjectFilter matches every object the activedirectory.user resource
// represents: ordinary user accounts and Group Managed Service Accounts.
const userObjectFilter = "(|(&(objectCategory=person)(objectClass=user))(objectClass=msDS-GroupManagedServiceAccount))"

// extractOU returns the OU path from a DN by removing the object's own RDN.
func extractOU(dn string) string {
	idx := strings.Index(dn, ",")
	if idx < 0 || idx >= len(dn)-1 {
		return ""
	}
	return dn[idx+1:]
}

func (a *mqlActivedirectoryUser) id() (string, error) {
	return a.DistinguishedName.Data, nil
}

func (a *mqlActivedirectory) users() ([]interface{}, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	baseDN := conn.BaseDN()

	filter := userObjectFilter
	attrs := []string{
		"sAMAccountName",
		"userPrincipalName",
		"displayName",
		"distinguishedName",
		"objectSid",
		"userAccountControl",
		"adminCount",
		"servicePrincipalName",
		"pwdLastSet",
		"lastLogonTimestamp",
		"whenCreated",
		"description",
		"mail",
		"memberOf",
		"primaryGroupID",
		"sIDHistory",
		"msDS-AllowedToDelegateTo",
		"objectClass",
	}

	entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attrs,
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}

	now := time.Now().UTC()
	res := make([]interface{}, 0, len(entries))
	for _, entry := range entries {
		samAccountName := connection.GetStringAttr(entry, "sAMAccountName")
		dn := connection.GetStringAttr(entry, "distinguishedName")
		upn := connection.GetStringAttr(entry, "userPrincipalName")
		displayName := connection.GetStringAttr(entry, "displayName")

		sid, err := connection.DecodeSID(connection.GetBinaryAttr(entry, "objectSid"))
		if err != nil {
			log.Warn().Err(err).Str("user", dn).Msg("failed to decode user SID")
			sid = ""
		}

		// UAC flags
		uac := parseInt64Attr(entry.GetAttributeValue("userAccountControl"))
		enabled := !uacHasFlag(uac, UACAccountDisable)
		passwordNeverExpires := uacHasFlag(uac, UACDontExpirePassword)
		passwordNotRequired := uacHasFlag(uac, UACPasswordNotRequired)
		kerberosPreAuthNotRequired := uacHasFlag(uac, UACDontRequirePreauth)
		sensitiveAndCannotBeDelegated := uacHasFlag(uac, UACNotDelegated)
		useDesKeyOnly := uacHasFlag(uac, UACUseDesKeyOnly)
		reversibleEncryption := uacHasFlag(uac, UACEncryptedTextPwdAllowed)

		adminCount := entry.GetAttributeValue("adminCount") == "1"

		// SPNs and kerberoastable check
		spns := connection.GetStringSliceAttr(entry, "servicePrincipalName")
		kerberoastable := enabled && len(spns) > 0 &&
			samAccountName != "krbtgt" &&
			!strings.HasSuffix(samAccountName, "$")

		// Timestamps
		pwdLastSet := connection.FileTimeToTime(parseInt64Attr(entry.GetAttributeValue("pwdLastSet")))
		lastLogon := connection.FileTimeToTime(parseInt64Attr(entry.GetAttributeValue("lastLogonTimestamp")))
		whenCreated := parseADGeneralizedTime(entry.GetAttributeValue("whenCreated"))

		// Computed age fields
		var passwordAgeDays int64
		if !pwdLastSet.IsZero() {
			passwordAgeDays = int64(now.Sub(pwdLastSet).Hours() / 24)
		}

		var daysSinceLastLogon int64 = -1
		if !lastLogon.IsZero() {
			daysSinceLastLogon = int64(now.Sub(lastLogon).Hours() / 24)
		}

		isStale := daysSinceLastLogon >= 0 && daysSinceLastLogon > 90

		// Group memberships as []interface{} for llx
		memberOfSlice := connection.GetStringSliceAttr(entry, "memberOf")
		memberOfIface := make([]interface{}, len(memberOfSlice))
		for i, m := range memberOfSlice {
			memberOfIface[i] = m
		}

		// Primary group membership never appears in memberOf, so expose the
		// RID directly for rules that assert on it.
		primaryGroupID := parseInt64Attr(entry.GetAttributeValue("primaryGroupID"))

		email := entry.GetAttributeValue("mail")
		description := entry.GetAttributeValue("description")
		ouPath := extractOU(dn)

		// SID History — binary multi-value attribute, decode each raw value.
		sidHistory := decodeSIDHistory(entry)

		// Constrained delegation targets
		constrainedTargets := connection.GetStringSliceAttr(entry, "msDS-AllowedToDelegateTo")

		// Detect Group Managed Service Accounts by objectClass.
		objectClasses := connection.GetStringSliceAttr(entry, "objectClass")
		isGMSA := false
		for _, oc := range objectClasses {
			if strings.EqualFold(oc, "msDS-GroupManagedServiceAccount") {
				isGMSA = true
				break
			}
		}

		// Convert string slices to []interface{} for llx array data
		spnIface := make([]interface{}, len(spns))
		for i, s := range spns {
			spnIface[i] = s
		}
		sidHistIface := make([]interface{}, len(sidHistory))
		for i, s := range sidHistory {
			sidHistIface[i] = s
		}
		constrainedIface := make([]interface{}, len(constrainedTargets))
		for i, s := range constrainedTargets {
			constrainedIface[i] = s
		}

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.user",
			map[string]*llx.RawData{
				"sAMAccountName":                llx.StringData(samAccountName),
				"userPrincipalName":             llx.StringData(upn),
				"displayName":                   llx.StringData(displayName),
				"distinguishedName":             llx.StringData(dn),
				"sid":                           llx.StringData(sid),
				"enabled":                       llx.BoolData(enabled),
				"passwordNeverExpires":          llx.BoolData(passwordNeverExpires),
				"passwordNotRequired":           llx.BoolData(passwordNotRequired),
				"kerberosPreAuthNotRequired":    llx.BoolData(kerberosPreAuthNotRequired),
				"sensitiveAndCannotBeDelegated": llx.BoolData(sensitiveAndCannotBeDelegated),
				"useDesKeyOnly":                 llx.BoolData(useDesKeyOnly),
				"reversibleEncryption":          llx.BoolData(reversibleEncryption),
				"userAccountControl":            llx.IntData(uac),
				"adminCount":                    llx.BoolData(adminCount),
				"servicePrincipalNames":         llx.ArrayData(spnIface, types.String),
				"kerberoastable":                llx.BoolData(kerberoastable),
				"pwdLastSet":                    llx.TimeData(pwdLastSet),
				"lastLogonTimestamp":            llx.TimeData(lastLogon),
				"whenCreated":                   llx.TimeData(whenCreated),
				"passwordAgeDays":               llx.IntData(passwordAgeDays),
				"daysSinceLastLogon":            llx.IntData(daysSinceLastLogon),
				"isStale":                       llx.BoolData(isStale),
				"memberOf":                      llx.ArrayData(memberOfIface, types.String),
				"primaryGroupId":                llx.IntData(primaryGroupID),
				"description":                   llx.StringData(description),
				"email":                         llx.StringData(email),
				"ouPath":                        llx.StringData(ouPath),
				"sidHistory":                    llx.ArrayData(sidHistIface, types.String),
				"constrainedDelegationTargets":  llx.ArrayData(constrainedIface, types.String),
				"isGMSA":                        llx.BoolData(isGMSA),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	return res, nil
}

type userPrivilegeFlags struct {
	protectedUser     bool
	isDomainAdmin     bool
	isEnterpriseAdmin bool
	isSchemaAdmin     bool
	isPrivileged      bool
}

func (a *mqlActivedirectoryUser) privilegeFlags() (userPrivilegeFlags, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	sets, err := buildPrivilegedMembershipSets(conn)
	if err != nil {
		return userPrivilegeFlags{}, err
	}

	userDN := a.DistinguishedName.Data
	return userPrivilegeFlags{
		protectedUser:     sets.ProtectedUsers[userDN],
		isDomainAdmin:     sets.DomainAdmins[userDN],
		isEnterpriseAdmin: sets.EnterpriseAdmins[userDN],
		isSchemaAdmin:     sets.SchemaAdmins[userDN],
		isPrivileged:      sets.AllPrivileged[userDN],
	}, nil
}

func (a *mqlActivedirectoryUser) protectedUser() (bool, error) {
	flags, err := a.privilegeFlags()
	if err != nil {
		return false, err
	}
	return flags.protectedUser, nil
}

func (a *mqlActivedirectoryUser) isDomainAdmin() (bool, error) {
	flags, err := a.privilegeFlags()
	if err != nil {
		return false, err
	}
	return flags.isDomainAdmin, nil
}

func (a *mqlActivedirectoryUser) isEnterpriseAdmin() (bool, error) {
	flags, err := a.privilegeFlags()
	if err != nil {
		return false, err
	}
	return flags.isEnterpriseAdmin, nil
}

func (a *mqlActivedirectoryUser) isSchemaAdmin() (bool, error) {
	flags, err := a.privilegeFlags()
	if err != nil {
		return false, err
	}
	return flags.isSchemaAdmin, nil
}

func (a *mqlActivedirectoryUser) isPrivileged() (bool, error) {
	flags, err := a.privilegeFlags()
	if err != nil {
		return false, err
	}
	return flags.isPrivileged, nil
}

// decodeSIDHistory extracts and decodes the multi-value binary sIDHistory
// attribute from an LDAP entry. Each raw value is a binary SID.
func decodeSIDHistory(entry *ldap.Entry) []string {
	for _, attr := range entry.Attributes {
		if !strings.EqualFold(attr.Name, "sIDHistory") {
			continue
		}
		var sids []string
		for _, raw := range attr.ByteValues {
			sid, err := connection.DecodeSID(raw)
			if err != nil {
				log.Warn().Err(err).Msg("failed to decode sIDHistory value")
				continue
			}
			sids = append(sids, sid)
		}
		return sids
	}
	return nil
}
