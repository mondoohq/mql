// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/dns"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

func (c *mqlCloudflareZone) dnssec() (*mqlCloudflareZoneDnssec, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	ds, err := conn.Cf.DNS.DNSSEC.Get(context.TODO(), dns.DNSSECGetParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	if err != nil {
		// DNSSEC may not be available on all plans (403/404)
		if isUnavailable(err) {
			c.Dnssec.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	// When DNSSEC is disabled the algorithm/key/digest/DS fields are not
	// meaningful — omit them from the args so the runtime never caches the
	// API zero-values and the fields surface as null when queried.
	args := map[string]*llx.RawData{
		"__id":       llx.StringData("cloudflare.zone.dnssec@" + c.Id.Data),
		"status":     llx.StringData(string(ds.Status)),
		"flags":      llx.IntData(int64(ds.Flags)),
		"modifiedOn": llx.TimeData(ds.ModifiedOn),
	}
	if string(ds.Status) != "disabled" {
		args["algorithm"] = llx.StringData(ds.Algorithm)
		args["keyType"] = llx.StringData(ds.KeyType)
		args["digestType"] = llx.StringData(ds.DigestType)
		args["digestAlgorithm"] = llx.StringData(ds.DigestAlgorithm)
		args["digest"] = llx.StringData(ds.Digest)
		args["ds"] = llx.StringData(ds.DS)
		args["keyTag"] = llx.IntData(int64(ds.KeyTag))
		args["publicKey"] = llx.StringData(ds.PublicKey)
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.dnssec", args)
	if err != nil {
		return nil, err
	}

	mqlDnssec := res.(*mqlCloudflareZoneDnssec)

	// Mark the omitted fields as explicitly null so the runtime doesn't try
	// to recompute them when accessed.
	if string(ds.Status) == "disabled" {
		nullState := plugin.StateIsSet | plugin.StateIsNull
		mqlDnssec.Algorithm.State = nullState
		mqlDnssec.KeyType.State = nullState
		mqlDnssec.DigestType.State = nullState
		mqlDnssec.DigestAlgorithm.State = nullState
		mqlDnssec.Digest.State = nullState
		mqlDnssec.Ds.State = nullState
		mqlDnssec.KeyTag.State = nullState
		mqlDnssec.PublicKey.State = nullState
	}

	return mqlDnssec, nil
}
