// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
)

// maxResponseBytes caps what is read from one HTTP response; a varz with
// every flag is about 200 KB.
const maxResponseBytes = 32 << 20

// get fetches path from the server at the HTTP address addr and returns the
// body. Failures are classified by what the server answered.
func (c *YugabyteConnection) get(ctx context.Context, addr, path string) ([]byte, error) {
	client, err := c.HTTPClient()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL(addr, path), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, transportError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, llx.Unavailable(err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, httpError(addr+path, resp.StatusCode, body)
	}
	return body, nil
}

// transportError classifies a request that got no answer. A certificate
// the client refused is a configuration problem, not an unavailable server,
// and is returned as is.
func transportError(err error) error {
	var verifyErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &verifyErr) || errors.As(err, &hostErr) || errors.As(err, &authErr) || errors.As(err, &invalidErr) {
		return err
	}
	return llx.Unavailable(err)
}

// httpError classifies a non-200 answer of a YugabyteDB server.
func httpError(target string, code int, body []byte) error {
	msg := strings.TrimSpace(stripTags(string(body)))
	if len(msg) > 300 {
		msg = msg[:300]
	}
	err := fmt.Errorf("GET %s: HTTP %d: %s", target, code, msg)
	switch {
	case code == http.StatusUnauthorized:
		return llx.Unauthenticated(err)
	case code == http.StatusForbidden:
		return llx.Forbidden(err)
	case code >= 500:
		return llx.Unavailable(err)
	default:
		// A master that cannot find its leader answers 404 with a message
		// saying so; anything else is returned as is.
		return err
	}
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

func stripTags(s string) string {
	return tagRe.ReplaceAllString(s, " ")
}

// getJSON fetches path from addr and decodes the JSON answer into v.
func (c *YugabyteConnection) getJSON(ctx context.Context, addr, path string, v any) error {
	body, err := c.get(ctx, addr, path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return llx.MalformedData(fmt.Errorf("GET %s%s: %w", addr, path, err))
	}
	return nil
}

func defaultCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// VersionInfo is the answer of /api/v1/version.
type VersionInfo struct {
	VersionNumber    string `json:"version_number"`
	BuildNumber      string `json:"build_number"`
	BuildType        string `json:"build_type"`
	GitHash          string `json:"git_hash"`
	YSQLMajorVersion int    `json:"ysql_major_version"`
}

// ClusterConfig is the part of /api/v1/cluster-config the provider reads.
type ClusterConfig struct {
	ClusterUUID     string `json:"cluster_uuid"`
	UniverseUUID    string `json:"universe_uuid"`
	ReplicationInfo struct {
		LiveReplicas struct {
			NumReplicas int64 `json:"num_replicas"`
		} `json:"live_replicas"`
	} `json:"replication_info"`
}

// HostPort is an address as the master reports it.
type HostPort struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (h HostPort) String() string {
	if h.Host == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

func firstAddress(list []HostPort) string {
	if len(list) == 0 {
		return ""
	}
	return list[0].String()
}

// MasterEntry is one master of /api/v1/masters.
type MasterEntry struct {
	InstanceID struct {
		PermanentUUID string `json:"permanent_uuid"`
		StartTimeUs   int64  `json:"start_time_us"`
	} `json:"instance_id"`
	Registration struct {
		PrivateRPCAddresses []HostPort `json:"private_rpc_addresses"`
		BroadcastAddresses  []HostPort `json:"broadcast_addresses"`
		HTTPAddresses       []HostPort `json:"http_addresses"`
	} `json:"registration"`
	Role  string `json:"role"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// RPCAddress returns the address other servers reach the master at.
func (m MasterEntry) RPCAddress() string {
	if a := firstAddress(m.Registration.BroadcastAddresses); a != "" {
		return a
	}
	return firstAddress(m.Registration.PrivateRPCAddresses)
}

// HTTPAddress returns the master's HTTP address.
func (m MasterEntry) HTTPAddress() string {
	return firstAddress(m.Registration.HTTPAddresses)
}

// Status returns "ALIVE", or the code of the error the leader got when it
// asked the master.
func (m MasterEntry) Status() string {
	if m.Error != nil {
		if m.Error.Code != "" {
			return m.Error.Code
		}
		return "ERROR"
	}
	return "ALIVE"
}

// Uptime returns the seconds since the master started, relative to now,
// and false when the master did not report when it started, as a master
// that does not answer.
func (m MasterEntry) Uptime(now time.Time) (int64, bool) {
	if m.InstanceID.StartTimeUs <= 0 {
		return 0, false
	}
	started := time.UnixMicro(m.InstanceID.StartTimeUs)
	if now.Before(started) {
		return 0, true
	}
	return int64(now.Sub(started) / time.Second), true
}

// TserverEntry is one tablet server of /api/v1/tablet-servers.
type TserverEntry struct {
	UUID          string
	Address       string
	Status        string `json:"status"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	PermanentUUID string `json:"permanent_uuid"`
}

// ParseTabletServers parses /api/v1/tablet-servers, which groups the tablet
// servers by placement UUID and keys each by its HTTP address. The result
// is sorted by address.
func ParseTabletServers(data []byte) ([]TserverEntry, error) {
	var raw map[string]map[string]TserverEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	list := []TserverEntry{}
	for _, byAddr := range raw {
		for addr, ts := range byAddr {
			ts.Address = addr
			ts.UUID = ts.PermanentUUID
			list = append(list, ts)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Address < list[j].Address })
	return list, nil
}

// Health is the cluster health the leader master reports.
type Health struct {
	DeadNodes              []string `json:"dead_nodes"`
	UnderReplicatedTablets []string `json:"under_replicated_tablets"`
	MostRecentUptime       int64    `json:"most_recent_uptime"`
	LeaderlessTablets      []string `json:"-"`
}

// leaderlessTablets is /api/v1/tablet-replication. Its entries are objects
// in newer releases.
type leaderlessTablets struct {
	LeaderlessTablets []json.RawMessage `json:"leaderless_tablets"`
}

// tabletIDs returns the tablet IDs of a list whose entries are either IDs
// or objects carrying a tablet_uuid or tablet_id.
func tabletIDs(list []json.RawMessage) []string {
	out := make([]string, 0, len(list))
	for _, raw := range list {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			out = append(out, s)
			continue
		}
		var obj struct {
			TabletUUID string `json:"tablet_uuid"`
			TabletID   string `json:"tablet_id"`
		}
		if json.Unmarshal(raw, &obj) == nil {
			if obj.TabletUUID != "" {
				out = append(out, obj.TabletUUID)
			} else if obj.TabletID != "" {
				out = append(out, obj.TabletID)
			}
		}
	}
	return out
}

// Flag is one flag of /api/v1/varz.
type Flag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

// ParseVarz parses /api/v1/varz.
func ParseVarz(data []byte) ([]Flag, error) {
	var v struct {
		Flags []Flag `json:"flags"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	if v.Flags == nil {
		return nil, errors.New("varz answer has no flags")
	}
	return v.Flags, nil
}

// Version reads the release of the master on the host.
func (c *YugabyteConnection) Version() (VersionInfo, error) {
	v, err := c.Memo("version", func() (any, error) {
		ctx, cancel := defaultCtx()
		defer cancel()
		var info VersionInfo
		err := c.getJSON(ctx, c.MasterEndpoint(), "/api/v1/version", &info)
		return info, err
	})
	if err != nil {
		return VersionInfo{}, err
	}
	return v.(VersionInfo), nil
}

// ClusterConfig reads the cluster configuration from the leader master.
func (c *YugabyteConnection) ClusterConfig() (ClusterConfig, error) {
	v, err := c.Memo("clusterConfig", func() (any, error) {
		ctx, cancel := defaultCtx()
		defer cancel()
		var cfg ClusterConfig
		if err := c.getJSON(ctx, c.MasterEndpoint(), "/api/v1/cluster-config", &cfg); err != nil {
			return cfg, err
		}
		if cfg.ClusterUUID == "" {
			return cfg, ErrNoCluster
		}
		return cfg, nil
	})
	if err != nil {
		return ClusterConfig{}, err
	}
	return v.(ClusterConfig), nil
}

// Masters lists the masters of the cluster.
func (c *YugabyteConnection) Masters() ([]MasterEntry, error) {
	v, err := c.Memo("masters", func() (any, error) {
		ctx, cancel := defaultCtx()
		defer cancel()
		var res struct {
			Masters []MasterEntry `json:"masters"`
		}
		err := c.getJSON(ctx, c.MasterEndpoint(), "/api/v1/masters", &res)
		return res.Masters, err
	})
	if err != nil {
		return nil, err
	}
	return v.([]MasterEntry), nil
}

// TabletServers lists the tablet servers of the cluster.
func (c *YugabyteConnection) TabletServers() ([]TserverEntry, error) {
	v, err := c.Memo("tservers", func() (any, error) {
		ctx, cancel := defaultCtx()
		defer cancel()
		body, err := c.get(ctx, c.MasterEndpoint(), "/api/v1/tablet-servers")
		if err != nil {
			return nil, err
		}
		list, err := ParseTabletServers(body)
		if err != nil {
			return nil, llx.MalformedData(err)
		}
		return list, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]TserverEntry), nil
}

// Health reads the cluster health from the leader master.
func (c *YugabyteConnection) Health() (Health, error) {
	v, err := c.Memo("health", func() (any, error) {
		ctx, cancel := defaultCtx()
		defer cancel()
		var h Health
		if err := c.getJSON(ctx, c.MasterEndpoint(), "/api/v1/health-check", &h); err != nil {
			return h, err
		}
		var lt leaderlessTablets
		if err := c.getJSON(ctx, c.MasterEndpoint(), "/api/v1/tablet-replication", &lt); err != nil {
			return h, err
		}
		h.LeaderlessTablets = tabletIDs(lt.LeaderlessTablets)
		if h.DeadNodes == nil {
			h.DeadNodes = []string{}
		}
		if h.UnderReplicatedTablets == nil {
			h.UnderReplicatedTablets = []string{}
		}
		return h, nil
	})
	if err != nil {
		return Health{}, err
	}
	return v.(Health), nil
}

// Varz reads the flags of the server at the HTTP address addr.
func (c *YugabyteConnection) Varz(addr string) ([]Flag, error) {
	v, err := c.Memo("varz/"+addr, func() (any, error) {
		ctx, cancel := defaultCtx()
		defer cancel()
		body, err := c.get(ctx, addr, "/api/v1/varz")
		if err != nil {
			return nil, err
		}
		flags, err := ParseVarz(body)
		if err != nil {
			return nil, llx.MalformedData(fmt.Errorf("GET %s/api/v1/varz: %w", addr, err))
		}
		return flags, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]Flag), nil
}

// serverUUIDRe matches the footer every page of the YugabyteDB web UI
// carries, "server uuid <uuid>".
var serverUUIDRe = regexp.MustCompile(`server uuid ([0-9a-fA-F-]{32,36})`)

// ParseServerUUID returns the UUID in the footer of a web UI page, or "".
func ParseServerUUID(page []byte) string {
	m := serverUUIDRe.FindSubmatch(page)
	if m == nil {
		return ""
	}
	return normalizeUUID(string(m[1]))
}

// normalizeUUID lowercases a UUID and drops its dashes; the master API
// reports server UUIDs without dashes.
func normalizeUUID(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "-", ""))
}

// SameUUID reports whether two server UUIDs are equal, with or without
// dashes.
func SameUUID(a, b string) bool {
	return a != "" && normalizeUUID(a) == normalizeUUID(b)
}

// ServerUUID returns the UUID of the server at the HTTP address addr. The
// HTTP API has no endpoint for it; the web UI prints it in the footer of
// every page, of which /tls is one of the smallest.
func (c *YugabyteConnection) ServerUUID(addr string) (string, error) {
	v, err := c.Memo("uuid/"+addr, func() (any, error) {
		ctx, cancel := defaultCtx()
		defer cancel()
		body, err := c.get(ctx, addr, "/tls")
		if err != nil {
			return "", err
		}
		if id := ParseServerUUID(body); id != "" {
			return id, nil
		}
		return "", llx.MalformedData(fmt.Errorf("%s does not report its server uuid", addr))
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// ServerAddress returns the HTTP address to read a server's own pages at.
// The server the scanner connects to, at the host and the configured port
// (local), is read there: the address the master reports may be one only
// the cluster can reach, such as a container's name behind published ports.
// Every other server is read at its reported address.
func (c *YugabyteConnection) ServerAddress(uuid, reported, local string) string {
	if reported == local {
		return reported
	}
	if id, err := c.ServerUUID(local); err == nil && SameUUID(id, uuid) {
		return local
	}
	return reported
}
