// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/registrar"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

type mqlCloudflareAccountRegistrarDomainInternal struct {
	// accountID is the account that owns the registration, used to prefer
	// that account's zone when the domain is added to more than one account.
	accountID string
}

// registrarDomainArgs maps a Registrar registration onto resource fields. The
// registration's expiry is null while a registration or transfer is pending.
func registrarDomainArgs(accountID string, reg registrar.Registration) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":        llx.StringData("cloudflare.account.registrarDomain@" + accountID + "/" + reg.DomainName),
		"name":        llx.StringData(reg.DomainName),
		"locked":      llx.BoolData(reg.Locked),
		"autoRenew":   llx.BoolData(reg.AutoRenew),
		"privacyMode": llx.StringData(string(reg.PrivacyMode)),
		"status":      llx.StringData(string(reg.Status)),
		"expiresAt":   timeOrNil(reg.ExpiresAt),
		"createdAt":   timeOrNil(reg.CreatedAt),
	}
}

// registrarDomains lists the domains the account registered through
// Cloudflare Registrar. An account without Registrar access degrades to an
// empty list like the other gated collections.
func (c *mqlCloudflareAccount) registrarDomains() ([]any, error) {
	if c.Id.Data == "" {
		return nil, errNoAccountBound
	}
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	result := []any{}
	iter := conn.Cf.Registrar.Registrations.ListAutoPaging(context.TODO(), registrar.RegistrationListParams{
		AccountID: cloudflare.F(c.Id.Data),
	})
	for iter.Next() {
		res, err := CreateResource(c.MqlRuntime, "cloudflare.account.registrarDomain", registrarDomainArgs(c.Id.Data, iter.Current()))
		if err != nil {
			return nil, err
		}
		res.(*mqlCloudflareAccountRegistrarDomain).accountID = c.Id.Data
		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

// zone resolves the zone serving the domain from the zones the connection can
// list, by name.
func (d *mqlCloudflareAccountRegistrarDomain) zone() (*mqlCloudflareZone, error) {
	list, err := listedZones(d.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if zone := zoneNamed(list, d.Name.Data, d.accountID); zone != nil {
		return zone, nil
	}
	d.Zone.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
