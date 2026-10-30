// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// Bridge driver options that decide what containers on a network can reach.
// The bridge driver turns inter-container communication and masquerading on
// unless the network sets the option to false.
const (
	dockerBridgeOptICC             = "com.docker.network.bridge.enable_icc"
	dockerBridgeOptIPMasquerade    = "com.docker.network.bridge.enable_ip_masquerade"
	dockerBridgeOptHostBindingIPv4 = "com.docker.network.bridge.host_binding_ipv4"
)

// dockerContainerEndpoint is one network a container is connected to, as the
// container listing reports it.
type dockerContainerEndpoint struct {
	// name is the network's name, the key of the container's network map.
	name string
	// networkID is empty for a container that was created but never started:
	// the engine assigns the endpoint when the container starts.
	networkID string
}

// dockerContainerEndpoints lists the networks a container from the container
// listing is connected to.
func dockerContainerEndpoints(c container.Summary) []dockerContainerEndpoint {
	if c.NetworkSettings == nil {
		return nil
	}
	res := make([]dockerContainerEndpoint, 0, len(c.NetworkSettings.Networks))
	for name, ep := range c.NetworkSettings.Networks {
		e := dockerContainerEndpoint{name: name}
		if ep != nil {
			e.networkID = ep.NetworkID
		}
		res = append(res, e)
	}
	return res
}

// connectedTo reports whether the endpoint is on the network with the given
// ID and name. A container that never started carries only the network's
// name, which is unique on a host.
func (e dockerContainerEndpoint) connectedTo(networkID, networkName string) bool {
	if e.networkID != "" {
		return e.networkID == networkID
	}
	return e.name == networkName
}

// dockerBridgeBoolOption reads an on/off option of the bridge driver. The
// second result is false for a network of another driver, where the option
// means nothing. An absent or unparsable value reads as the driver's default,
// which is on.
func dockerBridgeBoolOption(driver string, options map[string]any, key string) (bool, bool) {
	if driver != "bridge" {
		return false, false
	}
	v, ok := options[key].(string)
	if !ok {
		return true, true
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return true, true
	}
	return b, true
}

// dockerBridgeHostBinding reads the default host address a bridge network
// binds published ports to. The second result is false when the network is
// not a bridge or does not set it.
func dockerBridgeHostBinding(driver string, options map[string]any) (string, bool) {
	if driver != "bridge" {
		return "", false
	}
	v, ok := options[dockerBridgeOptHostBindingIPv4].(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

type dockerNetworkSubnet struct {
	subnet  string
	gateway string
	ipRange string
}

// dockerNetworkSubnets lists a network's address ranges. An unset gateway or
// range is the zero value, which reads as empty rather than "invalid IP".
func dockerNetworkSubnets(ipam network.IPAM) []dockerNetworkSubnet {
	res := make([]dockerNetworkSubnet, 0, len(ipam.Config))
	for _, c := range ipam.Config {
		s := dockerNetworkSubnet{}
		if c.Subnet.IsValid() {
			s.subnet = c.Subnet.String()
		}
		if c.Gateway.IsValid() {
			s.gateway = c.Gateway.String()
		}
		if c.IPRange.IsValid() {
			s.ipRange = c.IPRange.String()
		}
		res = append(res, s)
	}
	return res
}

func dockerTimeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (p *mqlDocker) networks() ([]any, error) {
	cl, err := dockerClient(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	defer cl.Close()

	list, err := cl.NetworkList(context.Background(), client.NetworkListOptions{})
	if err != nil {
		return nil, classifyDockerError(err)
	}

	res := make([]any, 0, len(list.Items))
	for _, n := range list.Items {
		subnets := []any{}
		for _, s := range dockerNetworkSubnets(n.IPAM) {
			r, err := CreateResource(p.MqlRuntime, "docker.network.subnet", map[string]*llx.RawData{
				"__id":    llx.StringData("docker.network.subnet/" + n.ID + "/" + s.subnet + "/" + s.ipRange),
				"subnet":  llx.StringData(s.subnet),
				"gateway": llx.StringData(s.gateway),
				"ipRange": llx.StringData(s.ipRange),
			})
			if err != nil {
				return nil, err
			}
			subnets = append(subnets, r)
		}

		r, err := CreateResource(p.MqlRuntime, "docker.network", map[string]*llx.RawData{
			"id":          llx.StringData(n.ID),
			"name":        llx.StringData(n.Name),
			"driver":      llx.StringData(n.Driver),
			"scope":       llx.StringData(n.Scope),
			"internal":    llx.BoolData(n.Internal),
			"attachable":  llx.BoolData(n.Attachable),
			"ingress":     llx.BoolData(n.Ingress),
			"ipv4Enabled": llx.BoolData(n.EnableIPv4),
			"ipv6Enabled": llx.BoolData(n.EnableIPv6),
			"subnets":     llx.ArrayData(subnets, types.Resource("docker.network.subnet")),
			"options":     llx.MapData(convert.MapToInterfaceMap(n.Options), types.String),
			"labels":      llx.MapData(convert.MapToInterfaceMap(n.Labels), types.String),
			"createdAt":   llx.TimeDataPtr(dockerTimeOrNil(n.Created)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (p *mqlDockerNetwork) id() (string, error) {
	return "docker.network/" + p.Id.Data, nil
}

func (p *mqlDockerNetwork) icc() (bool, error) {
	v, ok := dockerBridgeBoolOption(p.Driver.Data, p.Options.Data, dockerBridgeOptICC)
	if !ok {
		p.Icc.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return v, nil
}

func (p *mqlDockerNetwork) ipMasquerade() (bool, error) {
	v, ok := dockerBridgeBoolOption(p.Driver.Data, p.Options.Data, dockerBridgeOptIPMasquerade)
	if !ok {
		p.IpMasquerade.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return v, nil
}

func (p *mqlDockerNetwork) hostBindingIpv4() (string, error) {
	v, ok := dockerBridgeHostBinding(p.Driver.Data, p.Options.Data)
	if !ok {
		p.HostBindingIpv4.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return v, nil
}

// containers lists the containers connected to the network, from the
// container list every network shares. The network listing does not carry
// them, and inspecting each network would cost one call per network.
func (p *mqlDockerNetwork) containers() ([]any, error) {
	all, err := dockerHostContainers(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, c := range all {
		for _, ep := range c.endpoints {
			if ep.connectedTo(p.Id.Data, p.Name.Data) {
				res = append(res, c)
				break
			}
		}
	}
	return res, nil
}

// networks lists the networks the container is connected to, from the
// network list every container shares.
func (p *mqlDockerContainer) networks() ([]any, error) {
	d, err := NewResource(p.MqlRuntime, "docker", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	all := d.(*mqlDocker).GetNetworks()
	if all.Error != nil {
		return nil, all.Error
	}
	res := []any{}
	for _, x := range all.Data {
		n, ok := x.(*mqlDockerNetwork)
		if !ok {
			continue
		}
		for _, ep := range p.endpoints {
			if ep.connectedTo(n.Id.Data, n.Name.Data) {
				res = append(res, n)
				break
			}
		}
	}
	return res, nil
}

// dockerHostContainers returns the host's container list, read once per scan.
func dockerHostContainers(runtime *plugin.Runtime) ([]*mqlDockerContainer, error) {
	d, err := NewResource(runtime, "docker", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	all := d.(*mqlDocker).GetContainers()
	if all.Error != nil {
		return nil, all.Error
	}
	res := make([]*mqlDockerContainer, 0, len(all.Data))
	for _, x := range all.Data {
		if c, ok := x.(*mqlDockerContainer); ok {
			res = append(res, c)
		}
	}
	return res, nil
}

func initDockerNetwork(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}
	name, err := podmanNameArg("docker.network", args)
	if err != nil {
		return nil, nil, err
	}

	d, err := NewResource(runtime, "docker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	networks := d.(*mqlDocker).GetNetworks()
	if networks.Error != nil {
		return nil, nil, networks.Error
	}
	for _, x := range networks.Data {
		if n, ok := x.(*mqlDockerNetwork); ok && n.Name.Data == name {
			return nil, n, nil
		}
	}
	return nil, nil, fmt.Errorf("docker.network with name %q not found", name)
}
