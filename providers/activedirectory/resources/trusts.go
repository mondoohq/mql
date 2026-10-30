// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

func (a *mqlActivedirectory) trusts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	baseDN := conn.BaseDN()
	searchBase := "CN=System," + baseDN

	attrs := []string{
		"cn",
		"trustPartner",
		"trustType",
		"trustDirection",
		"trustAttributes",
		"securityIdentifier",
		"whenCreated",
	}

	entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=trustedDomain)",
		attrs,
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to query trusts: %w", err)
	}

	sourceDomain := dnToDomain(baseDN)
	res := make([]any, 0, len(entries))

	for _, entry := range entries {
		targetDomain := connection.GetStringAttr(entry, "trustPartner")
		trustTypeRaw := parseInt64Attr(connection.GetStringAttr(entry, "trustType"))
		trustDirRaw := parseInt64Attr(connection.GetStringAttr(entry, "trustDirection"))
		trustAttrs := parseInt64Attr(connection.GetStringAttr(entry, "trustAttributes"))
		whenCreated := parseADGeneralizedTime(connection.GetStringAttr(entry, "whenCreated"))

		trustTypeStr := parseTrustType(sourceDomain, targetDomain, trustTypeRaw, trustAttrs)
		trustDirStr := parseTrustDirection(trustDirRaw)

		isTransitive := (trustAttrs & trustAttrNonTransitive) == 0
		sidFilteringEnabled := trustHasSIDFilteringEnabled(trustAttrs)
		selectiveAuth := trustUsesSelectiveAuthentication(trustAttrs)
		tgtDelegation := trustAllowsTGTDelegation(trustAttrs)
		isAzureADTrust := trustTypeRaw == trustTypeAAD
		sidHistoryEnabled := trustHasSIDHistoryEnabled(trustAttrs)
		aesEncryption := trustUsesAES(trustAttrs)
		rc4Encryption := trustUsesRC4(trustTypeRaw, trustAttrs)

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.trust",
			map[string]*llx.RawData{
				"targetDomain":            llx.StringData(targetDomain),
				"sourceDomain":            llx.StringData(sourceDomain),
				"trustType":               llx.StringData(trustTypeStr),
				"trustDirection":          llx.StringData(trustDirStr),
				"sidFilteringEnabled":     llx.BoolData(sidFilteringEnabled),
				"sidHistoryEnabled":       llx.BoolData(sidHistoryEnabled),
				"selectiveAuthentication": llx.BoolData(selectiveAuth),
				"aesEncryption":           llx.BoolData(aesEncryption),
				"rc4Encryption":           llx.BoolData(rc4Encryption),
				"tgtDelegation":           llx.BoolData(tgtDelegation),
				"whenCreated":             llx.TimeData(whenCreated),
				"isAzureADTrust":          llx.BoolData(isAzureADTrust),
				"isTransitive":            llx.BoolData(isTransitive),
				"trustAttributes":         llx.IntData(trustAttrs),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	return res, nil
}

// parseTrustDirection maps the AD trustDirection integer attribute to a label.
func parseTrustDirection(dir int64) string {
	switch dir {
	case 0:
		return "Disabled"
	case 1:
		return "Inbound"
	case 2:
		return "Outbound"
	case 3:
		return "Bidirectional"
	default:
		return "Unknown"
	}
}
