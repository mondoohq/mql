// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"sync"
	"sync/atomic"

	polardb "github.com/alibabacloud-go/polardb-20170801/v10/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// polardbApplicationAttributeState memoizes the application's detail record,
// which the NAT-mapping fields all read. A failed read is deliberately not
// cached, so a later access retries instead of permanently reporting an
// application as unpublished when nobody ever managed to read it.
type polardbApplicationAttributeState struct {
	attrLock    sync.Mutex
	attrFetched atomic.Bool
	attr        *polardb.DescribeApplicationAttributeResponseBody
}

// applicationAttribute reads the application detail once and hands the same
// record to every caller. The error is returned rather than swallowed: the
// fields built on it report reachability, and an unread detail must surface as
// an error rather than as "not reachable", which would pass an exposure check
// on data nobody read.
func (r *mqlAlicloudPolardbApplication) applicationAttribute() (*polardb.DescribeApplicationAttributeResponseBody, error) {
	if r.attrFetched.Load() {
		return r.attr, nil
	}
	r.attrLock.Lock()
	defer r.attrLock.Unlock()
	if r.attrFetched.Load() {
		return r.attr, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeApplicationAttribute(&polardb.DescribeApplicationAttributeRequest{
		ApplicationId: new(r.applicationId),
	})
	if err != nil {
		return nil, err
	}
	if resp != nil {
		r.attr = resp.Body
	}
	r.attrFetched.Store(true)
	return r.attr, nil
}

// vpcNatGateway resolves the VPC NAT gateway that carries the application's NAT
// mapping. A gateway that cannot be read (one outside the scanned regions, or
// one the credential has no access to) resolves to null rather than failing the
// application query; dnatMappings still reports the published ports.
func (r *mqlAlicloudPolardbApplication) vpcNatGateway() (*mqlAlicloudVpcNatGateway, error) {
	attr, err := r.applicationAttribute()
	if err != nil {
		return nil, err
	}

	gatewayID := ""
	if attr != nil {
		gatewayID = polardbStr(attr.VpcNatGatewayId)
	}
	if gatewayID == "" {
		r.VpcNatGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	gateway, err := resolveVpcNatGateway(r.MqlRuntime, r.region, gatewayID)
	if err != nil {
		log.Warn().Err(err).Str("natGatewayId", gatewayID).Str("application", r.applicationId).
			Msg("alicloud> unable to resolve the NAT gateway of a PolarDB application")
		r.VpcNatGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if gateway == nil {
		r.VpcNatGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gateway, nil
}

// natMappingSnatIpAddress reports the SNAT address bound to the application's
// vSwitch, or null when the application has no NAT mapping. Null rather than an
// empty string, because a blank address would read as an address that is set
// and empty.
func (r *mqlAlicloudPolardbApplication) natMappingSnatIpAddress() (string, error) {
	attr, err := r.applicationAttribute()
	if err != nil {
		return "", err
	}
	address := ""
	if attr != nil {
		address = polardbStr(attr.NatMappingSnatIpAddress)
	}
	if address == "" {
		r.NatMappingSnatIpAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return address, nil
}

// dnatMappings lists the DNAT entries that publish the application's ports
// through the NAT gateway.
func (r *mqlAlicloudPolardbApplication) dnatMappings() ([]any, error) {
	attr, err := r.applicationAttribute()
	if err != nil {
		return nil, err
	}

	res := []any{}
	if attr == nil {
		return res, nil
	}
	for _, m := range attr.DnatMappings {
		if m == nil {
			continue
		}
		entry, err := newPolardbApplicationDnatMapping(r.MqlRuntime, r.region, r.applicationId, m)
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

// polardbDnatMappingKey builds the identifying suffix of a DNAT entry's cache
// key. EntryId is the natural key, but it is optional in the response, so an
// entry without one falls back to the port triple it maps. Two entries on one
// application cannot share that triple, and without the fallback they would
// share a cache key and the second would report the first one's values.
func polardbDnatMappingKey(m *polardb.DescribeApplicationAttributeResponseBodyDnatMappings) string {
	if m == nil {
		return ""
	}
	if id := polardbStr(m.EntryId); id != "" {
		return id
	}
	return polardbStr(m.PortName) + "/" +
		strconv.FormatInt(int64(tea.Int32Value(m.FrontPort)), 10) + "/" +
		strconv.FormatInt(int64(tea.Int32Value(m.BackendPort)), 10)
}

func newPolardbApplicationDnatMapping(runtime *plugin.Runtime, region, applicationID string, m *polardb.DescribeApplicationAttributeResponseBodyDnatMappings) (*mqlAlicloudPolardbApplicationDnatMapping, error) {
	resource, err := CreateResource(runtime, "alicloud.polardb.application.dnatMapping", map[string]*llx.RawData{
		"__id":          llx.StringData(region + "/" + applicationID + "/dnat/" + polardbDnatMappingKey(m)),
		"entryId":       llx.StringDataPtr(m.EntryId),
		"accessAddress": llx.StringDataPtr(m.AccessAddress),
		"frontPort":     llx.IntDataPtr(m.FrontPort),
		"backendPort":   llx.IntDataPtr(m.BackendPort),
		"portName":      llx.StringDataPtr(m.PortName),
		"status":        llx.StringDataPtr(m.Status),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudPolardbApplicationDnatMapping), nil
}
