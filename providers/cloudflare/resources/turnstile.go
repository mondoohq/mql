// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// turnstileWidget mirrors a Turnstile challenge widget, decoded via the
// client's generic Get. The endpoint also returns the widget's secret key,
// which is deliberately left out of this shape so it never reaches the schema.
type turnstileWidget struct {
	Sitekey        string     `json:"sitekey"`
	Name           string     `json:"name"`
	Mode           string     `json:"mode"`
	Region         string     `json:"region"`
	ClearanceLevel string     `json:"clearance_level"`
	Domains        []string   `json:"domains"`
	BotFightMode   bool       `json:"bot_fight_mode"`
	EphemeralID    bool       `json:"ephemeral_id"`
	Offlabel       bool       `json:"offlabel"`
	CreatedOn      *time.Time `json:"created_on"`
	ModifiedOn     *time.Time `json:"modified_on"`
}

// turnstileWidgets lists the challenge widgets defined for the account.
func (c *mqlCloudflareAccount) turnstileWidgets() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	widgets, err := cfGetPaged[turnstileWidget](conn, fmt.Sprintf("accounts/%s/challenges/widgets", c.Id.Data))
	if err != nil {
		return degradedList(err)
	}

	results := make([]any, 0, len(widgets))
	for i := range widgets {
		w := widgets[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.turnstile.widget", map[string]*llx.RawData{
			"__id":               llx.StringData("cloudflare.turnstile.widget@" + c.Id.Data + "/" + w.Sitekey),
			"sitekey":            llx.StringData(w.Sitekey),
			"name":               llx.StringData(w.Name),
			"mode":               llx.StringData(w.Mode),
			"region":             llx.StringData(w.Region),
			"clearanceLevel":     llx.StringData(w.ClearanceLevel),
			"domains":            llx.ArrayData(convert.SliceAnyToInterface(w.Domains), types.String),
			"botFightMode":       llx.BoolData(w.BotFightMode),
			"ephemeralIdEnabled": llx.BoolData(w.EphemeralID),
			"offlabel":           llx.BoolData(w.Offlabel),
			"createdOn":          llx.TimeDataPtr(w.CreatedOn),
			"modifiedOn":         llx.TimeDataPtr(w.ModifiedOn),
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}
