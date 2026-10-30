// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
	"go.mondoo.com/mql/types"
)

func stringsToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func stringList(in []string) *llx.RawData {
	return llx.ArrayData(stringsToAny(in), types.String)
}

// ---------------------------------------------------------------------------
// SDN controllers, IPAMs, DNS
// ---------------------------------------------------------------------------

func (r *mqlProxmox) sdnControllers() ([]any, error) {
	controllers, err := proxmoxConn(r).GetSDNControllers()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(controllers))
	for i, c := range controllers {
		res, err := CreateResource(r.MqlRuntime, "proxmox.sdn.controller", map[string]*llx.RawData{
			"__id":         llx.StringData("proxmox.sdn.controller/" + c.Controller),
			"controller":   llx.StringData(c.Controller),
			"type":         llx.StringData(c.Type),
			"node":         llx.StringData(c.Node),
			"nodes":        llx.StringData(c.Nodes),
			"state":        llx.StringData(c.State),
			"asn":          llx.IntData(int64(c.ASN)),
			"peers":        llx.StringData(c.Peers),
			"ebgp":         llx.BoolData(c.EBGP.Bool()),
			"ebgpMultihop": llx.IntData(int64(c.EBGPMultihop)),
			"bgpMode":      llx.StringData(c.BGPMode),
			"loopback":     llx.StringData(c.Loopback),
			"isisDomain":   llx.StringData(c.ISISDomain),
			"isisNet":      llx.StringData(c.ISISNet),
			"isisIfaces":   llx.StringData(c.ISISIfaces),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) sdnIpams() ([]any, error) {
	ipams, err := proxmoxConn(r).GetSDNIpams()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(ipams))
	for i, ipam := range ipams {
		res, err := CreateResource(r.MqlRuntime, "proxmox.sdn.ipam", map[string]*llx.RawData{
			"__id": llx.StringData("proxmox.sdn.ipam/" + ipam.IPAM),
			"ipam": llx.StringData(ipam.IPAM),
			"type": llx.StringData(ipam.Type),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) sdnDnsServers() ([]any, error) {
	servers, err := proxmoxConn(r).GetSDNDnsServers()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(servers))
	for i, s := range servers {
		res, err := CreateResource(r.MqlRuntime, "proxmox.sdn.dns", map[string]*llx.RawData{
			"__id": llx.StringData("proxmox.sdn.dns/" + s.DNS),
			"dns":  llx.StringData(s.DNS),
			"type": llx.StringData(s.Type),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

func (r *mqlProxmox) notificationTargets() ([]any, error) {
	targets, err := proxmoxConn(r).GetNotificationTargets()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(targets))
	for i, t := range targets {
		res, err := CreateResource(r.MqlRuntime, "proxmox.notification.target", map[string]*llx.RawData{
			"__id":     llx.StringData("proxmox.notification.target/" + t.Name),
			"name":     llx.StringData(t.Name),
			"type":     llx.StringData(t.Type),
			"origin":   llx.StringData(t.Origin),
			"disabled": llx.BoolData(t.Disable.Bool()),
			"comment":  llx.StringData(t.Comment),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) notificationMatchers() ([]any, error) {
	matchers, err := proxmoxConn(r).GetNotificationMatchers()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(matchers))
	for i, m := range matchers {
		res, err := CreateResource(r.MqlRuntime, "proxmox.notification.matcher", map[string]*llx.RawData{
			"__id":          llx.StringData("proxmox.notification.matcher/" + m.Name),
			"name":          llx.StringData(m.Name),
			"mode":          llx.StringData(m.Mode),
			"matchSeverity": stringList(m.MatchSeverity),
			"matchField":    stringList(m.MatchField),
			"matchCalendar": stringList(m.MatchCalendar),
			"invertMatch":   llx.BoolData(m.InvertMatch.Bool()),
			"targets":       stringList(m.Target),
			"origin":        llx.StringData(m.Origin),
			"disabled":      llx.BoolData(m.Disable.Bool()),
			"comment":       llx.StringData(m.Comment),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) smtpEndpoints() ([]any, error) {
	endpoints, err := proxmoxConn(r).GetSMTPEndpoints()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(endpoints))
	for i, e := range endpoints {
		res, err := CreateResource(r.MqlRuntime, "proxmox.notification.smtpEndpoint", map[string]*llx.RawData{
			"__id":        llx.StringData("proxmox.notification.smtpEndpoint/" + e.Name),
			"name":        llx.StringData(e.Name),
			"server":      llx.StringData(e.Server),
			"port":        llx.IntData(int64(e.Port)),
			"mode":        llx.StringData(e.Mode),
			"fromAddress": llx.StringData(e.FromAddress),
			"author":      llx.StringData(e.Author),
			"username":    llx.StringData(e.Username),
			"mailto":      stringList(e.Mailto),
			"mailtoUser":  stringList(e.MailtoUser),
			"origin":      llx.StringData(e.Origin),
			"disabled":    llx.BoolData(e.Disable.Bool()),
			"comment":     llx.StringData(e.Comment),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) sendmailEndpoints() ([]any, error) {
	endpoints, err := proxmoxConn(r).GetSendmailEndpoints()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(endpoints))
	for i, e := range endpoints {
		res, err := CreateResource(r.MqlRuntime, "proxmox.notification.sendmailEndpoint", map[string]*llx.RawData{
			"__id":        llx.StringData("proxmox.notification.sendmailEndpoint/" + e.Name),
			"name":        llx.StringData(e.Name),
			"fromAddress": llx.StringData(e.FromAddress),
			"author":      llx.StringData(e.Author),
			"mailto":      stringList(e.Mailto),
			"mailtoUser":  stringList(e.MailtoUser),
			"origin":      llx.StringData(e.Origin),
			"disabled":    llx.BoolData(e.Disable.Bool()),
			"comment":     llx.StringData(e.Comment),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) gotifyEndpoints() ([]any, error) {
	endpoints, err := proxmoxConn(r).GetGotifyEndpoints()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(endpoints))
	for i, e := range endpoints {
		res, err := CreateResource(r.MqlRuntime, "proxmox.notification.gotifyEndpoint", map[string]*llx.RawData{
			"__id":     llx.StringData("proxmox.notification.gotifyEndpoint/" + e.Name),
			"name":     llx.StringData(e.Name),
			"server":   llx.StringData(e.Server),
			"origin":   llx.StringData(e.Origin),
			"disabled": llx.BoolData(e.Disable.Bool()),
			"comment":  llx.StringData(e.Comment),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) webhookEndpoints() ([]any, error) {
	endpoints, err := proxmoxConn(r).GetWebhookEndpoints()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(endpoints))
	for i, e := range endpoints {
		res, err := CreateResource(r.MqlRuntime, "proxmox.notification.webhookEndpoint", map[string]*llx.RawData{
			"__id":   llx.StringData("proxmox.notification.webhookEndpoint/" + e.Name),
			"name":   llx.StringData(e.Name),
			"url":    llx.StringData(e.URL),
			"method": llx.StringData(e.Method),
			// Only the names travel: a header or secret value can itself be
			// an API token, and a scan result is not the place for one.
			"headerNames": stringList(connection.PropertyStringNames(e.Header)),
			"secretNames": stringList(connection.PropertyStringNames(e.Secret)),
			"origin":      llx.StringData(e.Origin),
			"disabled":    llx.BoolData(e.Disable.Bool()),
			"comment":     llx.StringData(e.Comment),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// Metric servers
// ---------------------------------------------------------------------------

func (r *mqlProxmox) metricServers() ([]any, error) {
	servers, err := proxmoxConn(r).GetMetricServers()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(servers))
	for i, s := range servers {
		res, err := CreateResource(r.MqlRuntime, "proxmox.metricServer", map[string]*llx.RawData{
			"__id":     llx.StringData("proxmox.metricServer/" + s.ID),
			"id":       llx.StringData(s.ID),
			"type":     llx.StringData(s.Type),
			"server":   llx.StringData(s.Server),
			"port":     llx.IntData(int64(s.Port)),
			"disabled": llx.BoolData(s.Disable.Bool()),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// ACME
// ---------------------------------------------------------------------------

func (r *mqlProxmox) acmeAccounts() ([]any, error) {
	accounts, err := proxmoxConn(r).GetACMEAccounts()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(accounts))
	for i, a := range accounts {
		res, err := CreateResource(r.MqlRuntime, "proxmox.acme.account", map[string]*llx.RawData{
			"__id": llx.StringData("proxmox.acme.account/" + a.Name),
			"name": llx.StringData(a.Name),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) acmePlugins() ([]any, error) {
	plugins, err := proxmoxConn(r).GetACMEPlugins()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(plugins))
	for i, p := range plugins {
		res, err := CreateResource(r.MqlRuntime, "proxmox.acme.plugin", map[string]*llx.RawData{
			"__id":            llx.StringData("proxmox.acme.plugin/" + p.Plugin),
			"plugin":          llx.StringData(p.Plugin),
			"type":            llx.StringData(p.Type),
			"api":             llx.StringData(p.API),
			"nodes":           llx.StringData(p.Nodes),
			"disabled":        llx.BoolData(p.Disable.Bool()),
			"validationDelay": llx.IntData(int64(p.ValidationDelay)),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// Corosync
// ---------------------------------------------------------------------------

func (r *mqlProxmox) corosync() (*mqlProxmoxCorosync, error) {
	res, err := CreateResource(r.MqlRuntime, "proxmox.corosync", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxCorosync), nil
}

func (r *mqlProxmoxCorosync) id() (string, error) {
	return "proxmox.corosync", nil
}

func corosyncConn(r *mqlProxmoxCorosync) *connection.PveConnection {
	return r.MqlRuntime.Connection.(*connection.PveConnection)
}

func (r *mqlProxmoxCorosync) nodes() ([]any, error) {
	cfg, err := corosyncConn(r).GetCorosyncConfig()
	if err != nil || cfg == nil {
		return []any{}, err
	}
	list := make([]any, len(cfg.NodeList))
	for i, n := range cfg.NodeList {
		res, err := CreateResource(r.MqlRuntime, "proxmox.corosync.node", map[string]*llx.RawData{
			"__id":                   llx.StringData("proxmox.corosync.node/" + n.Name),
			"name":                   llx.StringData(n.Name),
			"nodeId":                 llx.IntData(int64(n.NodeID)),
			"quorumVotes":            llx.IntData(int64(n.QuorumVotes)),
			"ring0Address":           llx.StringData(n.Ring0Addr),
			"ring1Address":           llx.StringData(n.Ring1Addr),
			"apiAddress":             llx.StringData(n.PveAddr),
			"certificateFingerprint": llx.StringData(n.PveFP),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxCorosync) preferredNode() (string, error) {
	cfg, err := corosyncConn(r).GetCorosyncConfig()
	if err != nil || cfg == nil {
		return "", err
	}
	return cfg.PreferredNode, nil
}

func (r *mqlProxmoxCorosync) configDigest() (string, error) {
	cfg, err := corosyncConn(r).GetCorosyncConfig()
	if err != nil || cfg == nil {
		return "", err
	}
	return cfg.ConfigDigest, nil
}

func (r *mqlProxmoxCorosync) totem() (any, error) {
	cfg, err := corosyncConn(r).GetCorosyncConfig()
	if err != nil || cfg == nil || cfg.Totem == nil {
		return map[string]any{}, err
	}
	return cfg.Totem, nil
}

func (r *mqlProxmoxCorosync) qdevice() (any, error) {
	qdevice, err := corosyncConn(r).GetQDevice()
	if err != nil {
		return nil, err
	}
	if qdevice == nil {
		return map[string]any{}, nil
	}
	return qdevice, nil
}

// ---------------------------------------------------------------------------
// Device mappings
// ---------------------------------------------------------------------------

func mappingEntries(m connection.DeviceMapping) *llx.RawData {
	entries := make([]any, len(m.Map))
	for i, e := range m.Map {
		entries[i] = e
	}
	return llx.ArrayData(entries, types.Dict)
}

func (r *mqlProxmox) pciMappings() ([]any, error) {
	mappings, err := proxmoxConn(r).GetPCIMappings()
	if err != nil {
		return nil, err
	}
	return deviceMappingsToResources(r.MqlRuntime, "proxmox.mapping.pci", mappings)
}

func (r *mqlProxmox) usbMappings() ([]any, error) {
	mappings, err := proxmoxConn(r).GetUSBMappings()
	if err != nil {
		return nil, err
	}
	return deviceMappingsToResources(r.MqlRuntime, "proxmox.mapping.usb", mappings)
}

func deviceMappingsToResources(runtime *plugin.Runtime, resource string, mappings []connection.DeviceMapping) ([]any, error) {
	list := make([]any, len(mappings))
	for i, m := range mappings {
		res, err := CreateResource(runtime, resource, map[string]*llx.RawData{
			"__id":        llx.StringData(resource + "/" + m.ID),
			"id":          llx.StringData(m.ID),
			"description": llx.StringData(m.Description),
			"entries":     mappingEntries(m),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}
