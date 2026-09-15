// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/directconnect"
	dctypes "github.com/aws/aws-sdk-go-v2/service/directconnect/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsDirectconnect) id() (string, error) {
	return "aws.directconnect", nil
}

func (a *mqlAwsDirectconnectConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsDirectconnectVirtualInterface) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsDirectconnectGateway) id() (string, error) {
	return a.Id.Data, nil
}

// directConnectTagsToMap converts Direct Connect tags, which carry their own Tag
// type rather than the shared EC2 one.
func directConnectTagsToMap(tags []dctypes.Tag) map[string]any {
	res := map[string]any{}
	for _, tag := range tags {
		res[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
	}
	return res
}

func (a *mqlAwsDirectconnect) connections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getConnections(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

// walkPages drives a NextToken-paginated Direct Connect operation. fetch is
// called once per page with the token for that page (nil for the first) and
// returns the token the service handed back.
//
// The walk stops when the service stops handing back a token, and also when it
// hands back the token it was just given. Direct Connect ships no paginator for
// these operations, so the loop is hand-written, and a service that echoes the
// request token would otherwise re-collect the same page forever.
func walkPages(fetch func(nextToken *string) (*string, error)) error {
	var token *string
	for {
		next, err := fetch(token)
		if err != nil {
			return err
		}
		if next == nil || *next == "" {
			return nil
		}
		if token != nil && *next == *token {
			return nil
		}
		token = next
	}
}

func (a *mqlAwsDirectconnect) getConnections(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.DirectConnect(region)
			res := []any{}
			// DescribeConnections caps a page at 100 and pages with NextToken.
			skipRegion := false
			err := walkPages(func(nextToken *string) (*string, error) {
				resp, err := svc.DescribeConnections(context.Background(), &directconnect.DescribeConnectionsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("skipping direct connect connections for region")
						skipRegion = true
						return nil, nil
					}
					return nil, err
				}
				for _, dcConn := range resp.Connections {
					mqlDcConn, err := CreateResource(a.MqlRuntime, ResourceAwsDirectconnectConnection,
						map[string]*llx.RawData{
							"id":                   llx.StringDataPtr(dcConn.ConnectionId),
							"name":                 llx.StringDataPtr(dcConn.ConnectionName),
							"state":                llx.StringData(string(dcConn.ConnectionState)),
							"location":             llx.StringDataPtr(dcConn.Location),
							"bandwidth":            llx.StringDataPtr(dcConn.Bandwidth),
							"vlan":                 llx.IntData(int64(dcConn.Vlan)),
							"region":               llx.StringData(region),
							"ownerAccount":         llx.StringDataPtr(dcConn.OwnerAccount),
							"partnerName":          llx.StringDataPtr(dcConn.PartnerName),
							"providerName":         llx.StringDataPtr(dcConn.ProviderName),
							"macSecCapable":        llx.BoolDataPtr(dcConn.MacSecCapable),
							"encryptionMode":       llx.StringDataPtr(dcConn.EncryptionMode),
							"portEncryptionStatus": llx.StringDataPtr(dcConn.PortEncryptionStatus),
							"jumboFrameCapable":    llx.BoolDataPtr(dcConn.JumboFrameCapable),
							"hasLogicalRedundancy": llx.StringData(string(dcConn.HasLogicalRedundancy)),
							"lagId":                llx.StringDataPtr(dcConn.LagId),
							"awsDevice":            llx.StringDataPtr(dcConn.AwsDeviceV2),
							"tags":                 llx.MapData(directConnectTagsToMap(dcConn.Tags), types.String),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlDcConn)
				}
				return resp.NextToken, nil
			})
			if err != nil {
				return nil, err
			}
			if skipRegion {
				return jobpool.JobResult([]any{}), nil
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsDirectconnect) virtualInterfaces() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getVirtualInterfaces(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsDirectconnect) getVirtualInterfaces(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.DirectConnect(region)
			res := []any{}
			// DescribeVirtualInterfaces caps a page at 100 and pages with
			// NextToken, and ships no paginator either.
			skipRegion := false
			err := walkPages(func(nextToken *string) (*string, error) {
				resp, err := svc.DescribeVirtualInterfaces(context.Background(), &directconnect.DescribeVirtualInterfacesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("skipping direct connect virtual interfaces for region")
						skipRegion = true
						return nil, nil
					}
					return nil, err
				}
				for _, vif := range resp.VirtualInterfaces {
					mqlVif, err := newMqlAwsDirectconnectVirtualInterface(a.MqlRuntime, region, vif)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlVif)
				}
				return resp.NextToken, nil
			})
			if err != nil {
				return nil, err
			}
			if skipRegion {
				return jobpool.JobResult([]any{}), nil
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsDirectconnectVirtualInterface(runtime *plugin.Runtime, region string, vif dctypes.VirtualInterface) (plugin.Resource, error) {
	// BGP peers are reduced to the fields that describe the session. AuthKey is
	// the BGP MD5 secret and is deliberately dropped rather than published.
	bgpPeers := []any{}
	for _, peer := range vif.BgpPeers {
		bgpPeers = append(bgpPeers, map[string]any{
			"bgpPeerId":       convert.ToValue(peer.BgpPeerId),
			"asn":             int64(peer.Asn),
			"addressFamily":   string(peer.AddressFamily),
			"amazonAddress":   convert.ToValue(peer.AmazonAddress),
			"customerAddress": convert.ToValue(peer.CustomerAddress),
			"bgpPeerState":    string(peer.BgpPeerState),
			"bgpStatus":       string(peer.BgpStatus),
		})
	}

	prefixes := []any{}
	for _, prefix := range vif.RouteFilterPrefixes {
		if cidr := convert.ToValue(prefix.Cidr); cidr != "" {
			prefixes = append(prefixes, cidr)
		}
	}

	mqlVif, err := CreateResource(runtime, ResourceAwsDirectconnectVirtualInterface,
		map[string]*llx.RawData{
			"id":                  llx.StringDataPtr(vif.VirtualInterfaceId),
			"name":                llx.StringDataPtr(vif.VirtualInterfaceName),
			"type":                llx.StringDataPtr(vif.VirtualInterfaceType),
			"state":               llx.StringData(string(vif.VirtualInterfaceState)),
			"vlan":                llx.IntData(int64(vif.Vlan)),
			"region":              llx.StringData(region),
			"ownerAccount":        llx.StringDataPtr(vif.OwnerAccount),
			"asn":                 llx.IntData(int64(vif.Asn)),
			"amazonSideAsn":       llx.IntDataDefault(vif.AmazonSideAsn, 0),
			"addressFamily":       llx.StringData(string(vif.AddressFamily)),
			"amazonAddress":       llx.StringDataPtr(vif.AmazonAddress),
			"customerAddress":     llx.StringDataPtr(vif.CustomerAddress),
			"bgpPeers":            llx.ArrayData(bgpPeers, types.Any),
			"routeFilterPrefixes": llx.ArrayData(prefixes, types.String),
			"mtu":                 llx.IntDataDefault(vif.Mtu, 0),
			"jumboFrameCapable":   llx.BoolDataPtr(vif.JumboFrameCapable),
			"siteLinkEnabled":     llx.BoolDataPtr(vif.SiteLinkEnabled),
			"tags":                llx.MapData(directConnectTagsToMap(vif.Tags), types.String),
		})
	if err != nil {
		return nil, err
	}
	internal := mqlVif.(*mqlAwsDirectconnectVirtualInterface)
	internal.cacheConnectionId = convert.ToValue(vif.ConnectionId)
	internal.cacheGatewayId = convert.ToValue(vif.DirectConnectGatewayId)
	internal.cacheVirtualGatewayId = convert.ToValue(vif.VirtualGatewayId)
	return mqlVif, nil
}

// gateways lists Direct Connect gateways. They are account-global rather than
// regional -- every region returns the same set -- so this queries one region
// instead of looping and deduplicating.
func (a *mqlAwsDirectconnect) gateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}
	if len(regions) == 0 {
		return []any{}, nil
	}

	svc := conn.DirectConnect(regions[0])
	ctx := context.Background()
	res := []any{}
	var nextToken *string
	for {
		resp, err := svc.DescribeDirectConnectGateways(ctx, &directconnect.DescribeDirectConnectGatewaysInput{
			NextToken: nextToken,
		})
		if err != nil {
			if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, gw := range resp.DirectConnectGateways {
			mqlGw, err := CreateResource(a.MqlRuntime, ResourceAwsDirectconnectGateway,
				map[string]*llx.RawData{
					"id":               llx.StringDataPtr(gw.DirectConnectGatewayId),
					"name":             llx.StringDataPtr(gw.DirectConnectGatewayName),
					"state":            llx.StringData(string(gw.DirectConnectGatewayState)),
					"amazonSideAsn":    llx.IntDataDefault(gw.AmazonSideAsn, 0),
					"ownerAccount":     llx.StringDataPtr(gw.OwnerAccount),
					"stateChangeError": llx.StringDataPtr(gw.StateChangeError),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGw)
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

type mqlAwsDirectconnectVirtualInterfaceInternal struct {
	cacheConnectionId     string
	cacheGatewayId        string
	cacheVirtualGatewayId string
}

// virtualGateway resolves the virtual private gateway the interface attaches to.
// A virtual interface attaches either to a Direct Connect gateway or to a virtual
// private gateway, so this is null whenever gateway() is set instead.
func (a *mqlAwsDirectconnectVirtualInterface) virtualGateway() (*mqlAwsVpcVpnGateway, error) {
	if a.cacheVirtualGatewayId == "" {
		a.VirtualGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsVpcVpnGateway,
		map[string]*llx.RawData{"id": llx.StringData(a.cacheVirtualGatewayId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcVpnGateway), nil
}

// directConnectSingleton returns the account-wide aws.directconnect resource, so
// cross-references resolve against one cached enumeration rather than refetching.
func directConnectSingleton(runtime *plugin.Runtime) (*mqlAwsDirectconnect, error) {
	obj, err := CreateResource(runtime, ResourceAwsDirectconnect, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlAwsDirectconnect), nil
}

// connection resolves the physical connection the virtual interface runs over by
// matching against the account's connection list, which is cached after the
// first read.
func (a *mqlAwsDirectconnectVirtualInterface) connection() (*mqlAwsDirectconnectConnection, error) {
	if a.cacheConnectionId == "" {
		a.Connection.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	dc, err := directConnectSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	conns := dc.GetConnections()
	if conns.Error != nil {
		return nil, conns.Error
	}
	for _, c := range conns.Data {
		dcConn, ok := c.(*mqlAwsDirectconnectConnection)
		if ok && dcConn.Id.Data == a.cacheConnectionId {
			return dcConn, nil
		}
	}
	a.Connection.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// gateway resolves the Direct Connect gateway the virtual interface attaches to.
// A virtual interface attaches either to a gateway or to a virtual private
// gateway, so this is null whenever virtualGatewayId is set instead.
func (a *mqlAwsDirectconnectVirtualInterface) gateway() (*mqlAwsDirectconnectGateway, error) {
	if a.cacheGatewayId == "" {
		a.Gateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	dc, err := directConnectSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	gateways := dc.GetGateways()
	if gateways.Error != nil {
		return nil, gateways.Error
	}
	for _, g := range gateways.Data {
		gw, ok := g.(*mqlAwsDirectconnectGateway)
		if ok && gw.Id.Data == a.cacheGatewayId {
			return gw, nil
		}
	}
	a.Gateway.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// virtualInterfaces returns the virtual interfaces carried over this connection.
func (a *mqlAwsDirectconnectConnection) virtualInterfaces() ([]any, error) {
	dc, err := directConnectSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	vifs := dc.GetVirtualInterfaces()
	if vifs.Error != nil {
		return nil, vifs.Error
	}
	res := []any{}
	for _, v := range vifs.Data {
		vif, ok := v.(*mqlAwsDirectconnectVirtualInterface)
		if ok && vif.cacheConnectionId == a.Id.Data {
			res = append(res, vif)
		}
	}
	return res, nil
}
