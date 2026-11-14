// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/yugabyte/connection"
)

// initYugabyteCluster reads the cluster identity, release, and replication
// factor from the master on the host.
func initYugabyteCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	conn := ybConnection(runtime)
	cfg, err := conn.ClusterConfig()
	if err != nil {
		return nil, nil, err
	}
	version, err := conn.Version()
	if err != nil {
		return nil, nil, err
	}
	args["__id"] = llx.StringData(connection.NewYugabyteClusterIdentifier(cfg.ClusterUUID))
	args["uuid"] = llx.StringData(cfg.ClusterUUID)
	args["version"] = llx.StringData(version.VersionNumber)
	args["replicationFactor"] = llx.IntData(cfg.ReplicationInfo.LiveReplicas.NumReplicas)
	return args, nil, nil
}

func (r *mqlYugabyteCluster) masters() ([]any, error) {
	conn := ybConnection(r.MqlRuntime)
	entries, err := conn.Masters()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	list := make([]any, 0, len(entries))
	for _, m := range entries {
		uptime := llx.NilData
		if secs, ok := m.Uptime(now); ok {
			uptime = llx.IntData(secs)
		}
		res, err := CreateResource(r.MqlRuntime, "yugabyte.master", map[string]*llx.RawData{
			"__id":       llx.StringData("yugabyte.master/" + m.InstanceID.PermanentUUID),
			"uuid":       llx.StringData(m.InstanceID.PermanentUUID),
			"address":    llx.StringData(m.HTTPAddress()),
			"rpcAddress": llx.StringData(m.RPCAddress()),
			"status":     llx.StringData(m.Status()),
			"isLeader":   llx.BoolData(m.Role == "LEADER"),
			"uptime":     uptime,
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlYugabyteCluster) tservers() ([]any, error) {
	conn := ybConnection(r.MqlRuntime)
	entries, err := conn.TabletServers()
	if err != nil {
		return nil, err
	}
	list := make([]any, 0, len(entries))
	for _, ts := range entries {
		res, err := CreateResource(r.MqlRuntime, "yugabyte.tserver", map[string]*llx.RawData{
			"__id":    llx.StringData("yugabyte.tserver/" + ts.UUID),
			"uuid":    llx.StringData(ts.UUID),
			"address": llx.StringData(ts.Address),
			"status":  llx.StringData(ts.Status),
			"uptime":  llx.IntData(ts.UptimeSeconds),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlYugabyteCluster) health() (map[string]any, error) {
	h, err := ybConnection(r.MqlRuntime).Health()
	if err != nil {
		return nil, err
	}
	return healthDict(h), nil
}

func healthDict(h connection.Health) map[string]any {
	return map[string]any{
		"deadNodes":              toAnySlice(h.DeadNodes),
		"underReplicatedTablets": toAnySlice(h.UnderReplicatedTablets),
		"leaderlessTablets":      toAnySlice(h.LeaderlessTablets),
		"mostRecentUptime":       h.MostRecentUptime,
	}
}

func (r *mqlYugabyteCluster) ysql() (*mqlYugabyteYsql, error) {
	res, err := CreateResource(r.MqlRuntime, "yugabyte.ysql", map[string]*llx.RawData{
		"__id": llx.StringData("yugabyte.ysql"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlYugabyteYsql), nil
}

func (r *mqlYugabyteCluster) ycql() (*mqlYugabyteYcql, error) {
	res, err := CreateResource(r.MqlRuntime, "yugabyte.ycql", map[string]*llx.RawData{
		"__id": llx.StringData("yugabyte.ycql"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlYugabyteYcql), nil
}

func (r *mqlYugabyteMaster) flags() ([]any, error) {
	conn := ybConnection(r.MqlRuntime)
	addr := conn.ServerAddress(r.Uuid.Data, r.Address.Data, conn.MasterEndpoint())
	return serverFlags(r.MqlRuntime, "master/"+r.Uuid.Data, addr)
}

func (r *mqlYugabyteTserver) flags() ([]any, error) {
	conn := ybConnection(r.MqlRuntime)
	addr := conn.ServerAddress(r.Uuid.Data, r.Address.Data, conn.TserverEndpoint())
	return serverFlags(r.MqlRuntime, "tserver/"+r.Uuid.Data, addr)
}

// serverFlags reads the flags of the server at addr. An unreachable server
// fails only its own flags.
func serverFlags(runtime *plugin.Runtime, server, addr string) ([]any, error) {
	if addr == "" {
		return nil, fmt.Errorf("yugabyte %s reports no HTTP address", server)
	}
	flags, err := ybConnection(runtime).Varz(addr)
	if err != nil {
		return nil, err
	}
	list := make([]any, 0, len(flags))
	for _, f := range flags {
		res, err := CreateResource(runtime, "yugabyte.flag", map[string]*llx.RawData{
			"__id":  llx.StringData("yugabyte.flag/" + server + "/" + f.Name),
			"name":  llx.StringData(f.Name),
			"value": llx.StringData(f.Value),
			"type":  llx.StringData(f.Type),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// tserverFlagEverywhere reports whether every tablet server of the cluster
// runs with the boolean flag name set to true. A tablet server whose flags
// cannot be read fails the answer.
func tserverFlagEverywhere(runtime *plugin.Runtime, name string) (bool, error) {
	conn := ybConnection(runtime)
	tservers, err := conn.TabletServers()
	if err != nil {
		return false, err
	}
	values := make([]map[string]string, 0, len(tservers))
	for _, ts := range tservers {
		addr := conn.ServerAddress(ts.UUID, ts.Address, conn.TserverEndpoint())
		flags, err := conn.Varz(addr)
		if err != nil {
			return false, fmt.Errorf("tablet server %s: %w", ts.UUID, err)
		}
		m := make(map[string]string, len(flags))
		for _, f := range flags {
			m[f.Name] = f.Value
		}
		values = append(values, m)
	}
	return flagTrueOnAll(values, name)
}

// flagTrueOnAll reports whether the flag is true on every server, given
// each server's flags. No servers, or a server that does not report the
// flag, is an error rather than an answer.
func flagTrueOnAll(servers []map[string]string, name string) (bool, error) {
	if len(servers) == 0 {
		return false, fmt.Errorf("the cluster reports no tablet servers to read %s from", name)
	}
	all := true
	for _, flags := range servers {
		v, ok := flags[name]
		if !ok {
			return false, fmt.Errorf("a tablet server does not report the %s flag", name)
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return false, fmt.Errorf("flag %s has the value %q, not a boolean", name, v)
		}
		all = all && b
	}
	return all, nil
}
