// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

// classifyZoneType provides a naming-based fallback when a zone is missing the
// TYPE dnsProperty. AD-integrated zones normally publish the type directly in
// dNSProperty, but lab and migration data can be incomplete.
func classifyZoneType(zoneName string) string {
	if strings.HasPrefix(zoneName, "_msdcs.") {
		return "ForestDnsZones"
	}
	if zoneName == "RootDNSServers" || zoneName == "..Cache" {
		return "Cache"
	}
	return "Primary"
}

func (a *mqlActivedirectory) dnsZones() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)

	domainDN := conn.DomainDnsZonesDN()
	forestDN := conn.ForestDnsZonesDN()

	// Collect entries from both partitions, dedup by DN.
	seen := make(map[string]struct{})
	var allEntries []*ldap.Entry

	partitions := []string{}
	if domainDN != "" {
		partitions = append(partitions, domainDN)
	}
	if forestDN != "" && forestDN != domainDN {
		partitions = append(partitions, forestDN)
	}

	attrs := []string{"name", "distinguishedName", "dnsProperty"}

	for _, partDN := range partitions {
		baseDN := fmt.Sprintf("CN=MicrosoftDNS,%s", partDN)

		entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=dnsZone)",
			attrs,
			nil,
		))
		if err != nil {
			// The MicrosoftDNS container may not exist if AD-integrated DNS
			// is not configured for this partition.
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				log.Debug().Str("baseDN", baseDN).Msg("MicrosoftDNS container not found, skipping partition")
				continue
			}
			return nil, fmt.Errorf("failed to query DNS zones in %s: %w", baseDN, err)
		}

		for _, entry := range entries {
			dn := connection.GetStringAttr(entry, "distinguishedName")
			if _, exists := seen[dn]; exists {
				continue
			}
			seen[dn] = struct{}{}
			allEntries = append(allEntries, entry)
		}
	}

	res := make([]any, 0, len(allEntries))
	for _, entry := range allEntries {
		name := connection.GetStringAttr(entry, "name")
		dn := connection.GetStringAttr(entry, "distinguishedName")
		zoneType, dynamicUpdate, secureOnly := deriveDNSZoneSettings(entry.GetRawAttributeValues("dnsProperty"))
		if zoneType == "Unknown" {
			zoneType = classifyZoneType(name)
		}

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.dnsZone",
			map[string]*llx.RawData{
				"name":              llx.StringData(name),
				"distinguishedName": llx.StringData(dn),
				"zoneType":          llx.StringData(zoneType),
				"dynamicUpdate":     llx.BoolData(dynamicUpdate),
				"secureOnly":        llx.BoolData(secureOnly),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	return res, nil
}
