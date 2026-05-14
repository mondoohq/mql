// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/rippling/connection"
)

func (c *mqlRipplingCompany) id() (string, error) {
	return "rippling.company/" + c.Id.Data, c.Id.Error
}

func newMqlRipplingCompany(runtime *plugin.Runtime, c *connection.Company) (*mqlRipplingCompany, error) {
	addr := c.Address
	if addr == nil {
		addr = &connection.NestedAddress{}
	}
	r, err := CreateResource(runtime, "rippling.company", map[string]*llx.RawData{
		"id":              llx.StringData(c.ID),
		"name":            llx.StringData(c.Name),
		"legalName":       llx.StringData(c.LegalName),
		"workEmail":       llx.StringData(c.WorkEmail),
		"phone":           llx.StringData(c.Phone),
		"primaryEmail":    llx.StringData(c.PrimaryEmail),
		"tin":             llx.StringData(c.Tin),
		"needsOnboarding": llx.BoolData(c.NeedsOnboard),
		"createdAt":       llx.TimeData(c.CreatedAt.Time),
		"streetLine1":     llx.StringData(addr.StreetLine1),
		"streetLine2":     llx.StringData(addr.StreetLine2),
		"city":            llx.StringData(addr.City),
		"state":           llx.StringData(addr.State),
		"zip":             llx.StringData(addr.Zip),
		"country":         llx.StringData(addr.Country),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlRipplingCompany), nil
}
