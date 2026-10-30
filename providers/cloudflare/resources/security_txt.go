// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// securityTxt returns the vulnerability disclosure policy Cloudflare publishes
// at /.well-known/security.txt for the zone.
func (c *mqlCloudflareZone) securityTxt() (*mqlCloudflareZoneSecurityTxt, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result struct {
			Enabled            bool       `json:"enabled"`
			Contact            []string   `json:"contact"`
			Expires            *time.Time `json:"expires"`
			Encryption         []string   `json:"encryption"`
			Acknowledgments    []string   `json:"acknowledgments"`
			Canonical          []string   `json:"canonical"`
			Policy             []string   `json:"policy"`
			Hiring             []string   `json:"hiring"`
			PreferredLanguages string     `json:"preferred_languages"`
		} `json:"result"`
	}
	uri := fmt.Sprintf("zones/%s/security-center/securitytxt", c.Id.Data)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		if isUnavailable(err) {
			c.SecurityTxt.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	txt := env.Result
	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.securityTxt", map[string]*llx.RawData{
		"__id":               llx.StringData("cloudflare.zone.securityTxt@" + c.Id.Data),
		"enabled":            llx.BoolData(txt.Enabled),
		"contact":            llx.ArrayData(convert.SliceAnyToInterface(txt.Contact), types.String),
		"expires":            llx.TimeDataPtr(txt.Expires),
		"encryption":         llx.ArrayData(convert.SliceAnyToInterface(txt.Encryption), types.String),
		"acknowledgments":    llx.ArrayData(convert.SliceAnyToInterface(txt.Acknowledgments), types.String),
		"canonical":          llx.ArrayData(convert.SliceAnyToInterface(txt.Canonical), types.String),
		"policy":             llx.ArrayData(convert.SliceAnyToInterface(txt.Policy), types.String),
		"hiring":             llx.ArrayData(convert.SliceAnyToInterface(txt.Hiring), types.String),
		"preferredLanguages": llx.StringData(txt.PreferredLanguages),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCloudflareZoneSecurityTxt), nil
}
