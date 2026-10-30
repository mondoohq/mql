// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/cloud"
)

func (c *mqlCloud) provider() (string, error) {
	conn := c.MqlRuntime.Connection.(shared.Connection)
	osCloud, err := cloud.Resolve(conn)
	if err != nil {
		return "", err
	}
	return string(osCloud.Provider()), nil
}

func (c *mqlCloud) instance() (*mqlCloudInstance, error) {
	log.Debug().Msg("os.cloud> instance")
	raw, err := NewResource(c.MqlRuntime, "cloudInstance", nil)
	if err != nil {
		return nil, err
	}

	conn := c.MqlRuntime.Connection.(shared.Connection)
	osCloud, err := cloud.Resolve(conn)
	if err != nil {
		return nil, err
	}
	instanceMd, err := osCloud.Instance()
	if err != nil {
		return nil, err
	}

	cloudInstance := raw.(*mqlCloudInstance)
	cloudInstance.instanceMd = instanceMd
	return cloudInstance, nil
}

type mqlCloudInstanceInternal struct {
	instanceMd *cloud.InstanceMetadata
}

func (i *mqlCloudInstance) id() (string, error) {
	if i.instanceMd != nil {
		return i.instanceMd.MqlID(), nil
	}
	return "", nil
}

func (i *mqlCloudInstance) publicHostname() (value string, err error) {
	if i.instanceMd != nil {
		value = i.instanceMd.PublicHostname
	}
	return
}

func (i *mqlCloudInstance) privateHostname() (value string, err error) {
	if i.instanceMd != nil {
		value = i.instanceMd.PrivateHostname
	}
	return
}

func (i *mqlCloudInstance) privateIpv4() (value []any, err error) {
	if i.instanceMd != nil {
		var resource plugin.Resource
		for _, ipaddress := range i.instanceMd.PrivateIpv4 {
			resource, err = NewResource(i.MqlRuntime, "ipAddress", map[string]*llx.RawData{
				"__id":      llx.StringData(ipaddress.IP),
				"ip":        llx.IPData(llx.ParseIP(ipaddress.IP)),
				"subnet":    llx.IPData(llx.ParseIP(ipaddress.Subnet)),
				"cidr":      llx.IPData(llx.ParseIP(ipaddress.CIDR)),
				"broadcast": llx.IPData(llx.ParseIP(ipaddress.Broadcast)),
				"gateway":   llx.IPData(llx.ParseIP(ipaddress.Gateway)),
			})
			if err != nil {
				return
			}
			value = append(value, resource)
		}
	}
	return
}

func (i *mqlCloudInstance) publicIpv4() (value []any, err error) {
	if i.instanceMd != nil {
		var resource plugin.Resource
		for _, ipaddress := range i.instanceMd.PublicIpv4 {
			resource, err = NewResource(i.MqlRuntime, "ipAddress", map[string]*llx.RawData{
				"__id":      llx.StringData(ipaddress.IP),
				"ip":        llx.IPData(llx.ParseIP(ipaddress.IP)),
				"subnet":    llx.IPData(llx.ParseIP(ipaddress.Subnet)),
				"cidr":      llx.IPData(llx.ParseIP(ipaddress.CIDR)),
				"broadcast": llx.IPData(llx.ParseIP(ipaddress.Broadcast)),
				"gateway":   llx.IPData(llx.ParseIP(ipaddress.Gateway)),
			})
			if err != nil {
				return
			}
			value = append(value, resource)
		}
	}
	return
}

func (i *mqlCloudInstance) metadata() (value any, err error) {
	if i.instanceMd != nil {
		value, err = convert.JsonToDict(i.instanceMd.Metadata)
	}
	return
}
