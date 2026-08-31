// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/frr"
	"go.mondoo.com/mql/types"
)

// This file exposes the daemons other than BGP: the interior gateway
// protocols, the BFD sessions, the policy based routing maps, the segment
// routing block, and the settings of the daemon itself. They are read from
// the same parsed file as the rest of frr.config, so they cost no extra read.

func (s *mqlFrrConfig) ospf(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	instances := s.cfg.OSPFInstances()
	res := make([]any, 0, len(instances))
	for i := range instances {
		o := &instances[i]
		id := s.__id + "#ospf/" + strconv.FormatInt(o.Version, 10) + "/" + vrfKey(o.VRF)
		obj, err := CreateResource(s.MqlRuntime, "frr.config.ospfInstance", map[string]*llx.RawData{
			"__id":                        llx.StringData(id),
			"version":                     llx.IntData(o.Version),
			"vrf":                         llx.StringData(o.VRF),
			"routerId":                    llx.StringData(o.RouterID),
			"areas":                       llx.ArrayData(frr.OSPFAreasAsDicts(o.Areas), types.Dict),
			"networks":                    llx.ArrayData(frr.OSPFNetworksAsDicts(o.Networks), types.Dict),
			"passiveInterfaceDefault":     llx.BoolData(o.PassiveInterfaceDefault),
			"passiveInterfaces":           llx.ArrayData(stringSliceToAny(o.PassiveInterfaces), types.String),
			"noPassiveInterfaces":         llx.ArrayData(stringSliceToAny(o.NoPassiveInterfaces), types.String),
			"redistribute":                llx.ArrayData(stringSliceToAny(o.Redistribute), types.String),
			"defaultInformationOriginate": llx.BoolData(o.DefaultInformationOriginate),
			"logAdjacencyChanges":         llx.BoolData(o.LogAdjacencyChanges),
			"maxMetricRouterLsa":          llx.StringData(o.MaxMetricRouterLsa),
			"params":                      llx.MapData(stringMapToAny(o.Params), types.String),
			"file":                        llx.StringData(o.File),
			"startLine":                   llx.IntData(int64(o.StartLine)),
			"raw":                         llx.StringData(o.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) isis(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	instances := s.cfg.ISISInstances()
	res := make([]any, 0, len(instances))
	for i := range instances {
		v := &instances[i]
		obj, err := CreateResource(s.MqlRuntime, "frr.config.isisInstance", map[string]*llx.RawData{
			"__id":                llx.StringData(s.__id + "#isis/" + v.Tag),
			"tag":                 llx.StringData(v.Tag),
			"vrf":                 llx.StringData(v.VRF),
			"net":                 llx.StringData(v.Net),
			"isType":              llx.StringData(v.IsType),
			"metricStyle":         llx.StringData(v.MetricStyle),
			"areaPasswordSet":     llx.BoolData(v.AreaPasswordSet),
			"areaPasswordMode":    llx.StringData(v.AreaPasswordMode),
			"domainPasswordSet":   llx.BoolData(v.DomainPasswordSet),
			"domainPasswordMode":  llx.StringData(v.DomainPasswordMode),
			"authenticationMode":  llx.StringData(v.AuthenticationMode),
			"redistribute":        llx.ArrayData(stringSliceToAny(v.Redistribute), types.String),
			"logAdjacencyChanges": llx.BoolData(v.LogAdjacencyChanges),
			"params":              llx.MapData(stringMapToAny(v.Params), types.String),
			"file":                llx.StringData(v.File),
			"startLine":           llx.IntData(int64(v.StartLine)),
			"raw":                 llx.StringData(v.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) bfdPeers(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	peers := s.cfg.BFDPeers()
	res := make([]any, 0, len(peers))
	for i := range peers {
		p := &peers[i]
		obj, err := CreateResource(s.MqlRuntime, "frr.config.bfdPeer", map[string]*llx.RawData{
			"__id":             llx.StringData(s.__id + "#bfd/" + p.Kind + "/" + p.Name),
			"kind":             llx.StringData(p.Kind),
			"name":             llx.StringData(p.Name),
			"interface":        llx.StringData(p.Interface),
			"localAddress":     llx.StringData(p.LocalAddress),
			"vrf":              llx.StringData(p.VRF),
			"multiHop":         llx.BoolData(p.MultiHop),
			"profile":          llx.StringData(p.Profile),
			"detectMultiplier": llx.IntData(p.DetectMultiplier),
			"receiveInterval":  llx.IntData(p.ReceiveInterval),
			"transmitInterval": llx.IntData(p.TransmitInterval),
			"echoMode":         llx.BoolData(p.EchoMode),
			"echoInterval":     llx.IntData(p.EchoInterval),
			"passiveMode":      llx.BoolData(p.PassiveMode),
			"shutdown":         llx.BoolData(p.Shutdown),
			"minimumTtl":       llx.IntData(p.MinimumTTL),
			"params":           llx.MapData(stringMapToAny(p.Params), types.String),
			"file":             llx.StringData(p.File),
			"startLine":        llx.IntData(int64(p.StartLine)),
			"raw":              llx.StringData(p.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) pbrMaps(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	maps := s.cfg.PBRMaps()
	res := make([]any, 0, len(maps))
	for i := range maps {
		m := &maps[i]
		obj, err := CreateResource(s.MqlRuntime, "frr.config.pbrMap", map[string]*llx.RawData{
			"__id":  llx.StringData(s.__id + "#pbrMap/" + m.Name),
			"name":  llx.StringData(m.Name),
			"rules": llx.ArrayData(frr.PBRRulesAsDicts(m.Rules), types.Dict),
			"file":  llx.StringData(m.File),
			"line":  llx.IntData(int64(m.Line)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) segmentRouting(file *mqlFile) (*mqlFrrConfigSegmentRoutingSettings, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	sr, configured := s.cfg.SegmentRoutingBlock()
	obj, err := CreateResource(s.MqlRuntime, "frr.config.segmentRoutingSettings", map[string]*llx.RawData{
		"__id":         llx.StringData(s.__id + "#segmentRouting"),
		"configured":   llx.BoolData(configured),
		"mplsEnabled":  llx.BoolData(sr.MPLSEnabled),
		"srv6Locators": llx.ArrayData(frr.SRv6LocatorsAsDicts(sr.SRv6Locators), types.Dict),
		"params":       llx.MapData(stringMapToAny(sr.Params), types.String),
		"file":         llx.StringData(sr.File),
		"startLine":    llx.IntData(int64(sr.StartLine)),
		"raw":          llx.StringData(sr.Raw),
	})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlFrrConfigSegmentRoutingSettings), nil
}

func (s *mqlFrrConfig) service(file *mqlFile) (*mqlFrrConfigServiceSettings, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	svc := s.cfg.ServiceSettings()
	obj, err := CreateResource(s.MqlRuntime, "frr.config.serviceSettings", map[string]*llx.RawData{
		"__id":                  llx.StringData(s.__id + "#service"),
		"logTargets":            llx.ArrayData(frr.LogTargetsAsDicts(svc.LogTargets), types.Dict),
		"passwordSet":           llx.BoolData(svc.PasswordSet),
		"enablePasswordSet":     llx.BoolData(svc.EnablePasswordSet),
		"agentxEnabled":         llx.BoolData(svc.AgentxEnabled),
		"integratedVtyshConfig": llx.BoolData(svc.IntegratedVtyshConfig),
		"advancedVty":           llx.BoolData(svc.AdvancedVty),
		"logCommands":           llx.BoolData(svc.LogCommands),
		"users":                 llx.ArrayData(frr.VtyshUsersAsDicts(svc.Users), types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlFrrConfigServiceSettings), nil
}

// interfaceProtocolArgs adds the routing protocol settings of one interface
// to the arguments of its resource.
func interfaceProtocolArgs(args map[string]*llx.RawData, p *frr.InterfaceProtocols) {
	args["ospfArea"] = llx.StringData(p.OSPFArea)
	args["ospfAuthentication"] = llx.StringData(p.OSPFAuthentication)
	args["ospfAuthenticationKeySet"] = llx.BoolData(p.OSPFAuthenticationKeySet)
	args["ospfMessageDigestKeySet"] = llx.BoolData(p.OSPFMessageDigestKeySet)
	args["ospfCost"] = llx.IntData(p.OSPFCost)
	args["ospfPriority"] = llx.IntData(p.OSPFPriority)
	args["ospfHelloInterval"] = llx.IntData(p.OSPFHelloInterval)
	args["ospfDeadInterval"] = llx.IntData(p.OSPFDeadInterval)
	args["ospfNetworkType"] = llx.StringData(p.OSPFNetworkType)
	args["ospfPassive"] = llx.BoolData(p.OSPFPassive)
	args["isisTag"] = llx.StringData(p.ISISTag)
	args["isisPasswordSet"] = llx.BoolData(p.ISISPasswordSet)
	args["isisAuthenticationMode"] = llx.StringData(p.ISISAuthenticationMode)
	args["isisNetworkType"] = llx.StringData(p.ISISNetworkType)
	args["isisCircuitType"] = llx.StringData(p.ISISCircuitType)
	args["pimEnabled"] = llx.BoolData(p.PIMEnabled)
	args["igmpEnabled"] = llx.BoolData(p.IGMPEnabled)
	args["bfdEnabled"] = llx.BoolData(p.BFDEnabled)
}
