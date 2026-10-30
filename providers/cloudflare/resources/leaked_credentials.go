// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

// leakedCredentialDetection is a custom detection expression, decoded via the
// client's generic Get. The username and password fields hold ruleset
// expressions that locate those values in a request, never the values.
type leakedCredentialDetection struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type mqlCloudflareZoneLeakedCredentialChecksInternal struct {
	zoneID string
}

// leakedCredentialChecks reports whether the zone screens incoming credentials
// against known breach corpora, and exposes the custom expressions that tell
// Cloudflare where to find them.
func (c *mqlCloudflareZone) leakedCredentialChecks() (*mqlCloudflareZoneLeakedCredentialChecks, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result struct {
			Enabled bool `json:"enabled"`
		} `json:"result"`
	}
	uri := fmt.Sprintf("zones/%s/leaked-credential-checks", c.Id.Data)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		if isUnavailable(err) {
			c.LeakedCredentialChecks.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.leakedCredentialChecks", map[string]*llx.RawData{
		"__id":    llx.StringData("cloudflare.zone.leakedCredentialChecks@" + c.Id.Data),
		"enabled": llx.BoolData(env.Result.Enabled),
	})
	if err != nil {
		return nil, err
	}

	checks := res.(*mqlCloudflareZoneLeakedCredentialChecks)
	checks.zoneID = c.Id.Data
	return checks, nil
}

func (c *mqlCloudflareZoneLeakedCredentialChecks) detections() ([]any, error) {
	if c.zoneID == "" {
		return []any{}, nil
	}
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	detections, err := cfGetPaged[leakedCredentialDetection](conn, fmt.Sprintf("zones/%s/leaked-credential-checks/detections", c.zoneID))
	if err != nil {
		return degradedList(err)
	}

	results := make([]any, 0, len(detections))
	for i := range detections {
		d := detections[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.leakedCredentialChecks.detection", map[string]*llx.RawData{
			"__id":     llx.StringData("cloudflare.zone.leakedCredentialChecks.detection@" + c.zoneID + "/" + d.ID),
			"id":       llx.StringData(d.ID),
			"username": llx.StringData(d.Username),
			"password": llx.StringData(d.Password),
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}
