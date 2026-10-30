// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net"

	"github.com/cockroachdb/errors"
	"github.com/ipinfo/go/v2/ipinfo"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ipinfo/connection"
)

// queryIPWithSDK queries IP information using the ipinfo Go SDK
func queryIPWithSDK(token string, queryIP net.IP) (*ipinfo.Core, error) {
	sdkClient := ipinfo.NewClient(nil, nil, token)

	// Query the IP
	var info *ipinfo.Core
	var err error
	if queryIP == nil {
		info, err = sdkClient.GetIPInfo(nil)
	} else {
		info, err = sdkClient.GetIPInfo(queryIP)
	}

	if err != nil {
		return nil, errors.Wrap(err, "failed to query with ipinfo SDK")
	}

	return info, nil
}

// requestedIP extracts the optional `ip` argument. It returns (nil, nil) when
// no ip was supplied (meaning: query the caller's own public IP), and an error
// when the argument is present but malformed. Kept separate from initIpinfo so
// the arg handling is unit-testable without a live API call.
func requestedIP(args map[string]*llx.RawData) (net.IP, error) {
	ip, ok := args["ip"]
	if !ok {
		return nil, nil
	}
	ipVal, ok := ip.Value.(llx.RawIP)
	if !ok {
		return nil, errors.New("ip must be of type ip")
	}
	if ipVal.IP == nil {
		return nil, errors.New("ip cannot be empty")
	}
	return ipVal.IP, nil
}

func initIpinfo(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	log.Debug().Str("args", fmt.Sprintf("%+v", args)).Msg("initIpinfo called")

	conn := runtime.Connection.(*connection.IpinfoConnection)
	token := conn.Token()

	// queryIP is nil when no ip arg was given → query the caller's public IP.
	queryIP, err := requestedIP(args)
	if err != nil {
		return nil, nil, err
	}
	log.Debug().
		Str("queryIP", func() string {
			if queryIP == nil {
				return "nil (public IP)"
			}
			return queryIP.String()
		}()).
		Msg("querying ipinfo")

	// Query IP information using the appropriate method
	info, err := queryIPWithSDK(token, queryIP)
	if err != nil {
		log.Debug().Err(err).Msg("ipinfo query failed")
		return nil, nil, err
	}

	if info == nil {
		return nil, nil, errors.New("ipinfo query returned no data")
	}

	log.Debug().
		Str("response_ip", info.IP.String()).
		Str("response_hostname", info.Hostname).
		Bool("response_bogon", info.Bogon).
		Interface("full_response", info).
		Msg("ipinfo response")

	res := make(map[string]*llx.RawData)
	if queryIP != nil {
		res["requested_ip"] = llx.IPData(llx.RawIP{IP: queryIP})
	} else {
		res["requested_ip"] = llx.NilData
	}

	// Build the returned IP directly from the SDK's net.IP rather than
	// round-tripping through String()+ParseIP (matches requested_ip above).
	res["returned_ip"] = llx.IPData(llx.RawIP{IP: info.IP})
	res["hostname"] = llx.StringData(info.Hostname)
	res["bogon"] = llx.BoolData(info.Bogon)
	res["city"] = llx.StringData(info.City)
	res["region"] = llx.StringData(info.Region)
	res["country"] = llx.StringData(info.Country)
	res["country_name"] = llx.StringData(info.CountryName)
	res["is_eu"] = llx.BoolData(info.IsEU)
	res["location"] = llx.StringData(info.Location)
	res["org"] = llx.StringData(info.Org)
	res["postal"] = llx.StringData(info.Postal)
	res["timezone"] = llx.StringData(info.Timezone)

	return res, nil, nil
}

func (c *mqlIpinfo) id() (string, error) {
	if c.Requested_ip.Error != nil {
		return "", c.Requested_ip.Error
	}
	// Identity is the *requested* IP (the query), not the returned IP. A query
	// for the caller's own public IP (requested = null) and an explicit query
	// for that same address return the same IP but are different queries; keying
	// on the returned IP collided them in the cache and crossed their
	// requested_ip values. A null requested IP means "self".
	if c.Requested_ip.IsNull() || c.Requested_ip.Data.IP == nil {
		return "ipinfo\x00self", nil
	}
	return "ipinfo\x00" + c.Requested_ip.Data.String(), nil
}
