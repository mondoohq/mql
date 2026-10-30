// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

type mqlProxmoxNodeInternal struct {
	nodeName   string
	statusOnce sync.Once
	nodeStatus *connection.NodeStatus
	statusErr  error
}

func nodeConn(r *mqlProxmoxNode) *connection.PveConnection {
	return r.MqlRuntime.Connection.(*connection.PveConnection)
}

func (r *mqlProxmoxNode) id() (string, error) {
	return "proxmox.node/" + r.Name.Data, nil
}

func (r *mqlProxmoxNode) ensureStatus() {
	r.statusOnce.Do(func() {
		r.nodeStatus, r.statusErr = nodeConn(r).GetNodeStatus(r.Name.Data)
	})
}

func (r *mqlProxmoxNode) cpuModel() (string, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return "", r.statusErr
	}
	return r.nodeStatus.CPUInfo.Model, nil
}

func (r *mqlProxmoxNode) cpuSockets() (int64, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return 0, r.statusErr
	}
	return int64(r.nodeStatus.CPUInfo.Sockets), nil
}

func (r *mqlProxmoxNode) cpuCores() (int64, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return 0, r.statusErr
	}
	return int64(r.nodeStatus.CPUInfo.Cores), nil
}

func (r *mqlProxmoxNode) cpuUsage() (float64, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return 0, r.statusErr
	}
	return r.nodeStatus.CPU, nil
}

func (r *mqlProxmoxNode) memTotal() (int64, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return 0, r.statusErr
	}
	return r.nodeStatus.Memory.Total, nil
}

func (r *mqlProxmoxNode) memUsed() (int64, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return 0, r.statusErr
	}
	return r.nodeStatus.Memory.Used, nil
}

func (r *mqlProxmoxNode) memFree() (int64, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return 0, r.statusErr
	}
	return r.nodeStatus.Memory.Free, nil
}

func (r *mqlProxmoxNode) swapTotal() (int64, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return 0, r.statusErr
	}
	return r.nodeStatus.Swap.Total, nil
}

func (r *mqlProxmoxNode) swapUsed() (int64, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return 0, r.statusErr
	}
	return r.nodeStatus.Swap.Used, nil
}

func (r *mqlProxmoxNode) kernelVersion() (string, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return "", r.statusErr
	}
	return r.nodeStatus.KVersion, nil
}

func (r *mqlProxmoxNode) pveVersion() (string, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return "", r.statusErr
	}
	return r.nodeStatus.PVEVer, nil
}

func (r *mqlProxmoxNode) uptime() (int64, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return 0, r.statusErr
	}
	return r.nodeStatus.Uptime, nil
}

func (r *mqlProxmoxNode) cpuFlags() (string, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return "", r.statusErr
	}
	return r.nodeStatus.CPUInfo.Flags, nil
}

// bootKernel and pendingReboot report null. /nodes/<n>/status carries the
// running kernel and the boot mode, but nothing names the kernel the node
// boots next, so there is no second value to compare. Reading a key the API
// never sends left these as an empty string and a confident false, which an
// audit for pending reboots passed on every node.
func (r *mqlProxmoxNode) bootKernel() (string, error) {
	r.BootKernel.State = plugin.StateIsSet | plugin.StateIsNull
	return "", nil
}

func (r *mqlProxmoxNode) pendingReboot() (bool, error) {
	r.PendingReboot.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func (r *mqlProxmoxNode) secureBoot() (bool, error) {
	r.ensureStatus()
	if r.statusErr != nil {
		return false, r.statusErr
	}
	return r.nodeStatus.BootInfo.SecureBoot.Bool(), nil
}

func (r *mqlProxmoxNode) networks() ([]any, error) {
	conn := nodeConn(r)
	ifaces, err := conn.GetNodeNetworks(r.Name.Data)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(ifaces))
	for i, ifc := range ifaces {
		res, err := CreateResource(r.MqlRuntime, "proxmox.network", map[string]*llx.RawData{
			"__id":        llx.StringData("proxmox.network/" + r.Name.Data + "/" + ifc.Iface),
			"iface":       llx.StringData(ifc.Iface),
			"type":        llx.StringData(ifc.Type),
			"active":      llx.BoolData(ifc.Active == 1),
			"method":      llx.StringData(ifc.Method),
			"address":     llx.StringData(ifc.Address),
			"netmask":     llx.StringData(ifc.Netmask),
			"gateway":     llx.StringData(ifc.Gateway),
			"bridgePorts": llx.StringData(ifc.BridgePorts),
			"cidr":        llx.StringData(ifc.CIDR),
			"autostart":   llx.BoolData(ifc.Autostart == 1),
			"comments":    llx.StringData(ifc.Comments),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxNode) dns() (*mqlProxmoxDns, error) {
	conn := nodeConn(r)
	d, err := conn.GetNodeDNS(r.Name.Data)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "proxmox.dns", map[string]*llx.RawData{
		"__id":   llx.StringData("proxmox.dns/" + r.Name.Data),
		"search": llx.StringData(d.Search),
		"dns1":   llx.StringData(d.DNS1),
		"dns2":   llx.StringData(d.DNS2),
		"dns3":   llx.StringData(d.DNS3),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxDns), nil
}

func (r *mqlProxmoxNode) services() ([]any, error) {
	conn := nodeConn(r)
	svcs, err := conn.GetNodeServices(r.Name.Data)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(svcs))
	for i, s := range svcs {
		res, err := CreateResource(r.MqlRuntime, "proxmox.service", map[string]*llx.RawData{
			"__id":          llx.StringData("proxmox.service/" + r.Name.Data + "/" + s.Name),
			"name":          llx.StringData(s.Name),
			"state":         llx.StringData(s.State),
			"description":   llx.StringData(s.Description),
			"unitFileState": llx.StringData(s.UnitFileState),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxNode) timezone() (string, error) {
	conn := nodeConn(r)
	t, err := conn.GetNodeTime(r.Name.Data)
	if err != nil {
		return "", err
	}
	return t.Timezone, nil
}

func (r *mqlProxmoxNode) storages() ([]any, error) {
	conn := nodeConn(r)
	storages, err := conn.GetNodeStorage(r.Name.Data)
	if err != nil {
		return nil, err
	}
	return storageInfoToResources(r.MqlRuntime, storages, r.Name.Data)
}

func (r *mqlProxmoxNode) certificates() ([]any, error) {
	conn := nodeConn(r)
	certs, err := conn.GetNodeCertificates(r.Name.Data)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(certs))
	for i, c := range certs {
		var san []any
		for _, s := range c.San {
			san = append(san, s)
		}
		res, err := CreateResource(r.MqlRuntime, "proxmox.certificate", map[string]*llx.RawData{
			"__id":          llx.StringData("proxmox.certificate/" + r.Name.Data + "/" + c.Fingerprint),
			"filename":      llx.StringData(c.Filename),
			"fingerprint":   llx.StringData(c.Fingerprint),
			"issuer":        llx.StringData(c.Issuer),
			"notAfter":      llx.TimeData(time.Unix(c.NotAfter, 0).UTC()),
			"notBefore":     llx.TimeData(time.Unix(c.NotBefore, 0).UTC()),
			"publicKeyBits": llx.IntData(int64(c.PublicKeyBits)),
			"publicKeyType": llx.StringData(c.PublicKeyType),
			"san":           llx.ArrayData(san, "\x02"),
			"subject":       llx.StringData(c.Subject),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxNode) subscription() (*mqlProxmoxSubscription, error) {
	conn := nodeConn(r)
	sub, err := conn.GetNodeSubscription(r.Name.Data)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "proxmox.subscription", map[string]*llx.RawData{
		"__id":        llx.StringData("proxmox.subscription/" + r.Name.Data + "/" + sub.ServerID),
		"status":      llx.StringData(sub.Status),
		"serverId":    llx.StringData(sub.ServerID),
		"productName": llx.StringData(sub.ProductName),
		"regDate":     llx.StringData(sub.RegDate),
		"nextDueDate": llx.StringData(sub.NextDueDate),
		"level":       llx.StringData(sub.Level),
		"key":         llx.StringData(sub.Key),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxSubscription), nil
}

func (r *mqlProxmoxNode) repositories() ([]any, error) {
	conn := nodeConn(r)
	repoInfo, err := conn.GetNodeRepositories(r.Name.Data)
	if err != nil {
		return nil, err
	}
	var list []any
	for _, file := range repoInfo.Files {
		// idx is per-file so the resulting `<path>:<idx>` matches what
		// the path string implies (the n-th entry inside that file).
		for idx, repo := range file.Repositories {
			repoID := fmt.Sprintf("%s:%d", file.Path, idx)
			name := repo.Comment
			if name == "" && len(repo.URIs) > 0 {
				name = repo.URIs[0]
			}
			var types, uris, suites, components []any
			for _, t := range repo.Types {
				types = append(types, t)
			}
			for _, u := range repo.URIs {
				uris = append(uris, u)
			}
			for _, s := range repo.Suites {
				suites = append(suites, s)
			}
			for _, c := range repo.Components {
				components = append(components, c)
			}
			// Signed-By is one of several deb822 options the API returns
			// as a {Key, Values} list; pull the first matching entry.
			var signedBy string
			for _, opt := range repo.Options {
				if opt.Key == "Signed-By" && len(opt.Values) > 0 {
					signedBy = opt.Values[0]
					break
				}
			}
			res, err := CreateResource(r.MqlRuntime, "proxmox.repository", map[string]*llx.RawData{
				"__id":       llx.StringData("proxmox.repository/" + r.Name.Data + "/" + repoID),
				"id":         llx.StringData(repoID),
				"name":       llx.StringData(name),
				"enabled":    llx.BoolData(repo.Enabled),
				"types":      llx.ArrayData(types, "\x02"),
				"uris":       llx.ArrayData(uris, "\x02"),
				"suites":     llx.ArrayData(suites, "\x02"),
				"components": llx.ArrayData(components, "\x02"),
				"fileType":   llx.StringData(file.FileType),
				"signedBy":   llx.StringData(signedBy),
			})
			if err != nil {
				return nil, err
			}
			list = append(list, res)
		}
	}
	return list, nil
}

func (r *mqlProxmoxNode) updates() ([]any, error) {
	conn := nodeConn(r)
	updates, err := conn.GetNodeUpdates(r.Name.Data)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(updates))
	for i, u := range updates {
		severity := "optional"
		if u.Priority == "important" || u.Priority == "required" {
			severity = "important"
		}
		if u.Priority == "standard" {
			severity = "recommended"
		}
		res, err := CreateResource(r.MqlRuntime, "proxmox.node.update", map[string]*llx.RawData{
			"__id":             llx.StringData("proxmox.node.update/" + r.Name.Data + "/" + u.Package),
			"package":          llx.StringData(u.Package),
			"installedVersion": llx.StringData(u.OldVersion),
			"newVersion":       llx.StringData(u.NewVersion),
			"severity":         llx.StringData(severity),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxNode) firewallRules() ([]any, error) {
	conn := nodeConn(r)
	rules, err := conn.GetNodeFirewallRules(r.Name.Data)
	if err != nil {
		return nil, err
	}
	return firewallRulesToResources(r.MqlRuntime, rules, "node/"+r.Name.Data)
}

func (r *mqlProxmoxNode) vms() ([]any, error) {
	conn := nodeConn(r)
	vms, err := conn.GetNodeVMs(r.Name.Data)
	if err != nil {
		return nil, err
	}
	return vmInfoToResources(r.MqlRuntime, vms)
}
