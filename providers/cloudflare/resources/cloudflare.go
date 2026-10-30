// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zones"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// accountRecord mirrors an account list entry. We decode it via the client's
// generic Get so account pagination follows result_info.total_pages.
type accountRecord struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Settings *struct {
		EnforceTwoFactor bool `json:"enforce_twofactor"`
	} `json:"settings"`
	CreatedOn time.Time `json:"created_on"`
}

func (r *mqlCloudflare) id() (string, error) {
	return "cloudflare", nil
}

func (c *mqlCloudflare) zones() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var res []any
	iter := conn.Cf.Zones.ListAutoPaging(context.Background(), zones.ZoneListParams{})
	for iter.Next() {
		zone := iter.Current()

		acc, err := NewResource(c.MqlRuntime, "cloudflare.zone.account", map[string]*llx.RawData{
			"id":   llx.StringData(zone.Account.ID),
			"name": llx.StringData(zone.Account.Name),
		})
		if err != nil {
			return nil, err
		}

		owner, err := NewResource(c.MqlRuntime, "cloudflare.zone.owner", map[string]*llx.RawData{
			"id":        llx.StringData(zone.Owner.ID),
			"name":      llx.StringData(zone.Owner.Name),
			"ownerType": llx.StringData(zone.Owner.Type),
		})
		if err != nil {
			return nil, err
		}

		r, err := NewResource(c.MqlRuntime, "cloudflare.zone", map[string]*llx.RawData{
			"id":   llx.StringData(zone.ID),
			"name": llx.StringData(zone.Name),

			"nameServers":         llx.ArrayData(convert.SliceAnyToInterface(zone.NameServers), types.String),
			"originalNameServers": llx.ArrayData(convert.SliceAnyToInterface(zone.OriginalNameServers), types.String),

			"status": llx.StringData(string(zone.Status)),
			"paused": llx.BoolData(zone.Paused),
			"type":   llx.StringData(string(zone.Type)),

			"account": llx.ResourceData(acc, acc.MqlName()),
			"owner":   llx.ResourceData(owner, owner.MqlName()),

			"createdOn":  llx.TimeData(zone.CreatedOn),
			"modifiedOn": llx.TimeData(zone.ModifiedOn),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (c *mqlCloudflare) accounts() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	accountsList, err := cfGetPaged[accountRecord](conn, "accounts")
	if err != nil {
		return nil, err
	}

	var result []any
	for i := range accountsList {
		acc := accountsList[i]

		enforceTwoFactor := false
		if acc.Settings != nil {
			enforceTwoFactor = acc.Settings.EnforceTwoFactor
		}
		settings, err := NewResource(c.MqlRuntime, "cloudflare.account.settings", map[string]*llx.RawData{
			"__id":             llx.StringData("cloudflare.account.settings@" + acc.ID),
			"enforceTwoFactor": llx.BoolData(enforceTwoFactor),
		})
		if err != nil {
			return nil, err
		}

		res, err := NewResource(c.MqlRuntime, "cloudflare.account", map[string]*llx.RawData{
			"id":        llx.StringData(acc.ID),
			"name":      llx.StringData(acc.Name),
			"type":      llx.StringData(acc.Type),
			"settings":  llx.ResourceData(settings, settings.MqlName()),
			"createdOn": llx.TimeData(acc.CreatedOn),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}
