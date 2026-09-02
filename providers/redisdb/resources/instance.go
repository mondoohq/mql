// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/redisdb/connection"
)

// initRedisdbInstance fetches server identity from INFO and the security-
// relevant configuration from CONFIG GET, populating the instance's fields. The
// config map is cached so the config sub-resource resolves without a re-fetch.
func initRedisdbInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	conn := redisdbConnection(runtime)
	client, err := conn.Client()
	if err != nil {
		return nil, nil, err
	}
	ctx := conn.Context()

	infoText, err := client.Info(ctx, "server").Result()
	if err != nil {
		return nil, nil, err
	}
	info := connection.ParseInfo(infoText)

	// CONFIG GET drives the posture fields. Reading it needs the config ACL
	// category; when the credential is denied, degrade gracefully by leaving
	// those fields null rather than failing the whole asset.
	configReadable := true
	cfg, err := client.ConfigGet(ctx, "*").Result()
	if err != nil {
		if !isNoPerm(err) {
			return nil, nil, err
		}
		configReadable = false
		cfg = map[string]string{}
	}

	isValkey := info["valkey_version"] != "" || info["server_name"] == "valkey"
	// Redis reports the server mode as redis_mode; Valkey uses server_mode.
	mode := info["redis_mode"]
	if mode == "" {
		mode = info["server_mode"]
	}

	// INFO-derived identity is always available.
	args["__id"] = llx.StringData(conn.ServerID())
	args["version"] = llx.StringData(info["redis_version"])
	args["isValkey"] = llx.BoolData(isValkey)
	args["valkeyVersion"] = llx.StringData(info["valkey_version"])
	args["mode"] = llx.StringData(mode)
	args["os"] = llx.StringData(info["os"])
	args["runId"] = llx.StringData(info["run_id"])

	res, err := CreateResource(runtime, "redisdb.instance", args)
	if err != nil {
		return nil, nil, err
	}
	inst := res.(*mqlRedisdbInstance)
	inst.configCache = cfg
	inst.configReadable = configReadable
	inst.setConfigFields(cfg, configReadable)
	return nil, res, nil
}

// setConfigFields populates the CONFIG GET-derived posture fields. When the
// config was not readable they are set to null so a denied read is never
// reported as an insecure value.
func (r *mqlRedisdbInstance) setConfigFields(cfg map[string]string, readable bool) {
	if !readable {
		null := plugin.StateIsSet | plugin.StateIsNull
		r.ProtectedMode = plugin.TValue[bool]{State: null}
		r.Bind = plugin.TValue[[]any]{State: null}
		r.BindsAllInterfaces = plugin.TValue[bool]{State: null}
		r.RequirepassSet = plugin.TValue[bool]{State: null}
		r.Port = plugin.TValue[int64]{State: null}
		r.TlsPort = plugin.TValue[int64]{State: null}
		r.TlsEnabled = plugin.TValue[bool]{State: null}
		r.TlsAuthClients = plugin.TValue[string]{State: null}
		r.AclFile = plugin.TValue[string]{State: null}
		r.AclPubsubDefault = plugin.TValue[string]{State: null}
		return
	}

	bind := strings.Fields(cfg["bind"])
	bindList := make([]any, 0, len(bind))
	for _, b := range bind {
		bindList = append(bindList, b)
	}
	tlsPort := atoiOr(cfg["tls-port"], 0)
	set := plugin.StateIsSet

	r.ProtectedMode = plugin.TValue[bool]{Data: cfg["protected-mode"] == "yes", State: set}
	r.Bind = plugin.TValue[[]any]{Data: bindList, State: set}
	r.BindsAllInterfaces = plugin.TValue[bool]{Data: bindsAll(bind), State: set}
	r.RequirepassSet = plugin.TValue[bool]{Data: cfg["requirepass"] != "", State: set}
	// The configured plaintext port, not the port the server happens to be
	// serving on. INFO's tcp_port reports whichever listener is active, so on a
	// TLS-only server -- "port 0" with a TLS listener bound -- it reports the
	// TLS port, and reading it here would make a correctly configured server
	// indistinguishable from one still accepting cleartext connections.
	r.Port = plugin.TValue[int64]{Data: atoiOr(cfg["port"], 0), State: set}
	r.TlsPort = plugin.TValue[int64]{Data: tlsPort, State: set}
	r.TlsEnabled = plugin.TValue[bool]{Data: tlsPort != 0, State: set}
	r.TlsAuthClients = plugin.TValue[string]{Data: cfg["tls-auth-clients"], State: set}
	r.AclFile = plugin.TValue[string]{Data: cfg["aclfile"], State: set}
	// Governs what an access-control user with no channel rules can reach, so
	// an empty channelPatterns list only means "no channels" when this is
	// resetchannels.
	r.AclPubsubDefault = plugin.TValue[string]{Data: cfg["acl-pubsub-default"], State: set}
}

// bindsAll reports whether a bind list exposes the server on all interfaces:
// an empty list (no bind configured) or a wildcard address.
func bindsAll(bind []string) bool {
	if len(bind) == 0 {
		return true
	}
	for _, b := range bind {
		if b == "0.0.0.0" || b == "*" || b == "::" || b == "::*" {
			return true
		}
	}
	return false
}

func (r *mqlRedisdbInstance) config() (*mqlRedisdbConfig, error) {
	// When CONFIG GET was denied there is nothing to report; mark the field null
	// rather than panicking on the nil cache or fabricating zero values.
	if !r.configReadable || r.configCache == nil {
		r.Config.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	cfg := r.configCache
	res, err := CreateResource(r.MqlRuntime, "redisdb.config", map[string]*llx.RawData{
		"__id":            llx.StringData(r.__id + "/config"),
		"save":            llx.StringData(cfg["save"]),
		"rdbEnabled":      llx.BoolData(strings.TrimSpace(cfg["save"]) != ""),
		"appendOnly":      llx.BoolData(cfg["appendonly"] == "yes"),
		"appendFsync":     llx.StringData(cfg["appendfsync"]),
		"maxmemory":       llx.IntData(atoiOr(cfg["maxmemory"], 0)),
		"maxmemoryPolicy": llx.StringData(cfg["maxmemory-policy"]),
		"logfile":         llx.StringData(cfg["logfile"]),
		"dir":             llx.StringData(cfg["dir"]),
		"dbFilename":      llx.StringData(cfg["dbfilename"]),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlRedisdbConfig), nil
}
