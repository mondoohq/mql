// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mikrotik/connection"
	"go.mondoo.com/mql/types"
)

func mikrotikConn(runtime *plugin.Runtime) *connection.MikrotikConnection {
	return runtime.Connection.(*connection.MikrotikConnection)
}

// parseInt converts a RouterOS numeric attribute to an int64, returning 0 when
// the value is empty or not a number.
func parseInt(s string) int64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// parseBool converts a RouterOS boolean attribute to a bool. RouterOS reports
// flags as "true"/"false" and occasionally "yes"/"no".
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes":
		return true
	default:
		return false
	}
}

// splitList turns a RouterOS comma-separated attribute (e.g. NTP servers,
// group policies, pool ranges) into a slice suitable for llx.ArrayData,
// trimming whitespace and dropping empty entries.
func splitList(s string) []any {
	if strings.TrimSpace(s) == "" {
		return []any{}
	}
	parts := strings.Split(s, ",")
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// boolField returns the RouterOS boolean at key as a resource field value, or
// null when the device did not report the attribute at all. RouterOS omits
// attributes it has no value for, and a menu that was never configured returns
// no rows rather than defaults, so a fabricated false would read as a security
// flag that was checked when nothing was.
func boolField(row map[string]string, key string) *llx.RawData {
	v, ok := row[key]
	if !ok {
		return llx.NilData
	}
	return llx.BoolData(parseBool(v))
}

// intField returns the RouterOS numeric attribute at key, or null when the
// device did not report it, so an unreported counter or size does not read as
// a genuine zero.
func intField(row map[string]string, key string) *llx.RawData {
	v, ok := row[key]
	if !ok {
		return llx.NilData
	}
	return llx.IntData(parseInt(v))
}

// listField splits a RouterOS comma-separated attribute into a list, or
// returns null when the device did not report the attribute, keeping "the
// device does not offer this setting" distinct from "the setting is empty".
func listField(row map[string]string, key string) *llx.RawData {
	v, ok := row[key]
	if !ok {
		return llx.NilData
	}
	return llx.ArrayData(splitList(v), types.String)
}

// presenceField reports whether the device holds a value for a secret
// attribute (an IPsec pre-shared key, a RADIUS shared secret, a private key)
// without reading the secret itself into the result. It is null when the menu
// does not carry the attribute at all.
func presenceField(row map[string]string, key string) *llx.RawData {
	v, ok := row[key]
	if !ok {
		return llx.NilData
	}
	return llx.BoolData(strings.TrimSpace(v) != "")
}

// rowID builds a resource cache key from the RouterOS row handle. RouterOS
// includes its internal ".id" handle (e.g. "*1A") in every print reply; it is
// unique within a menu and stable while the device keeps its current
// configuration, but it is not an identifier that survives a config reload, so
// the fallback composes a key from the row's own attributes.
func rowID(prefix string, row map[string]string, fallback ...string) string {
	id := row[".id"]
	if id == "" {
		id = strings.Join(fallback, "/")
	}
	return prefix + id
}

// errNoMenu reports a menu that returned no records, which on RouterOS means
// the subsystem is absent or was never configured rather than that it is set
// to its defaults.
func errNoMenu(menu string) error {
	return fmt.Errorf("mikrotik device reported no records for %s", menu)
}

// buildList maps each RouterOS reply row to a resource using build.
func buildList(runtime *plugin.Runtime, rows []map[string]string, build func(*plugin.Runtime, map[string]string) (plugin.Resource, error)) ([]any, error) {
	res := make([]any, 0, len(rows))
	for _, row := range rows {
		r, err := build(runtime, row)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// interfaceByName resolves a mikrotik.interface resource by its name.
func interfaceByName(runtime *plugin.Runtime, name string) (*mqlMikrotikInterface, error) {
	res, err := NewResource(runtime, "mikrotik.interface", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikInterface), nil
}

func (r *mqlMikrotik) id() (string, error) {
	return "mikrotik", nil
}

// --- system family ---

func (r *mqlMikrotik) system() (*mqlMikrotikSystem, error) {
	conn := mikrotikConn(r.MqlRuntime)

	identity, err := conn.PrintOne("/system/identity")
	if err != nil {
		return nil, err
	}
	res, err := conn.PrintOne("/system/resource")
	if err != nil {
		return nil, err
	}
	// routerboard is unavailable on CHR / x86 builds; tolerate failures
	rb, _ := conn.PrintOne("/system/routerboard")

	resource, err := CreateResource(r.MqlRuntime, "mikrotik.system", map[string]*llx.RawData{
		"__id":                 llx.StringData("mikrotik.system"),
		"identity":             llx.StringData(identity["name"]),
		"version":              llx.StringData(res["version"]),
		"buildTime":            llx.StringData(res["build-time"]),
		"factorySoftware":      llx.StringData(res["factory-software"]),
		"boardName":            llx.StringData(res["board-name"]),
		"platform":             llx.StringData(res["platform"]),
		"architecture":         llx.StringData(res["architecture-name"]),
		"cpu":                  llx.StringData(res["cpu"]),
		"cpuCount":             intField(res, "cpu-count"),
		"cpuFrequency":         intField(res, "cpu-frequency"),
		"cpuLoad":              intField(res, "cpu-load"),
		"totalMemory":          intField(res, "total-memory"),
		"freeMemory":           intField(res, "free-memory"),
		"totalHddSpace":        intField(res, "total-hdd-space"),
		"freeHddSpace":         intField(res, "free-hdd-space"),
		"badBlocks":            llx.StringData(res["bad-blocks"]),
		"writeSectSinceReboot": intField(res, "write-sect-since-reboot"),
		"writeSectTotal":       intField(res, "write-sect-total"),
		"uptime":               llx.StringData(res["uptime"]),
		"routerboard":          boolField(rb, "routerboard"),
		"model":                llx.StringData(rb["model"]),
		"serialNumber":         llx.StringData(rb["serial-number"]),
		"firmwareType":         llx.StringData(rb["firmware-type"]),
		"factoryFirmware":      llx.StringData(rb["factory-firmware"]),
		"firmwareVersion":      llx.StringData(rb["current-firmware"]),
		"upgradeFirmware":      llx.StringData(rb["upgrade-firmware"]),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMikrotikSystem), nil
}

func newMikrotikPackage(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.system.package", map[string]*llx.RawData{
		"__id":      llx.StringData("mikrotik.system.package/" + row["name"]),
		"name":      llx.StringData(row["name"]),
		"version":   llx.StringData(row["version"]),
		"buildTime": llx.StringData(row["build-time"]),
		"scheduled": llx.StringData(row["scheduled"]),
		"disabled":  boolField(row, "disabled"),
	})
}

func (r *mqlMikrotik) packages() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/system/package")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikPackage)
}

func (r *mqlMikrotik) clock() (*mqlMikrotikSystemClock, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOne("/system/clock")
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.system.clock", map[string]*llx.RawData{
		"__id":               llx.StringData("mikrotik.system.clock"),
		"time":               llx.StringData(row["time"]),
		"date":               llx.StringData(row["date"]),
		"timeZoneName":       llx.StringData(row["time-zone-name"]),
		"gmtOffset":          llx.StringData(row["gmt-offset"]),
		"dstActive":          boolField(row, "dst-active"),
		"timeZoneAutodetect": boolField(row, "time-zone-autodetect"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikSystemClock), nil
}

func (r *mqlMikrotik) ntpClient() (*mqlMikrotikSystemNtpClient, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOne("/system/ntp/client")
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.system.ntp.client", map[string]*llx.RawData{
		"__id":          llx.StringData("mikrotik.system.ntp.client"),
		"enabled":       boolField(row, "enabled"),
		"mode":          llx.StringData(row["mode"]),
		"servers":       listField(row, "servers"),
		"status":        llx.StringData(row["status"]),
		"syncedServer":  llx.StringData(row["synced-server"]),
		"syncedStratum": intField(row, "synced-stratum"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikSystemNtpClient), nil
}

func (r *mqlMikrotik) snmp() (*mqlMikrotikSnmp, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOne("/snmp")
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.snmp", map[string]*llx.RawData{
		"__id":           llx.StringData("mikrotik.snmp"),
		"enabled":        boolField(row, "enabled"),
		"contact":        llx.StringData(row["contact"]),
		"location":       llx.StringData(row["location"]),
		"engineId":       llx.StringData(row["engine-id"]),
		"trapCommunity":  llx.StringData(row["trap-community"]),
		"trapVersion":    intField(row, "trap-version"),
		"trapGenerators": llx.StringData(row["trap-generators"]),
		"srcAddress":     llx.StringData(row["src-address"]),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikSnmp), nil
}

// --- network collections (creators live in interfaces.go / ip.go) ---

func (r *mqlMikrotik) interfaces() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/interface")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikInterface)
}

func (r *mqlMikrotik) bridges() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/interface/bridge")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikBridge)
}

func (r *mqlMikrotik) vlans() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/interface/vlan")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikVlan)
}

func (r *mqlMikrotik) ipAddresses() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/address")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikIpAddress)
}

func (r *mqlMikrotik) ipv6Addresses() ([]any, error) {
	// /ipv6 only exists when the ipv6 package is enabled; PrintOptional turns
	// its absence into an empty list instead of failing the whole query
	rows, err := mikrotikConn(r.MqlRuntime).PrintOptional("/ipv6/address")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikIpv6Address)
}

func (r *mqlMikrotik) routes() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/route")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikRoute)
}

func (r *mqlMikrotik) pools() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/pool")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikIpPool)
}

func (r *mqlMikrotik) dns() (*mqlMikrotikIpDns, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOne("/ip/dns")
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.ip.dns", map[string]*llx.RawData{
		"__id":                llx.StringData("mikrotik.ip.dns"),
		"servers":             llx.StringData(row["servers"]),
		"dynamicServers":      llx.StringData(row["dynamic-servers"]),
		"allowRemoteRequests": boolField(row, "allow-remote-requests"),
		"useDohServer":        llx.StringData(row["use-doh-server"]),
		"verifyDohCert":       boolField(row, "verify-doh-cert"),
		"maxUdpPacketSize":    intField(row, "max-udp-packet-size"),
		"queryServerTimeout":  llx.StringData(row["query-server-timeout"]),
		"queryTotalTimeout":   llx.StringData(row["query-total-timeout"]),
		"cacheSize":           intField(row, "cache-size"),
		"cacheMaxTtl":         llx.StringData(row["cache-max-ttl"]),
		"cacheUsed":           intField(row, "cache-used"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikIpDns), nil
}

func (r *mqlMikrotik) services() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/service")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikService)
}

func (r *mqlMikrotik) firewallRules() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/firewall/filter")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikFirewallFilter)
}

func (r *mqlMikrotik) natRules() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/firewall/nat")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikFirewallNat)
}

func (r *mqlMikrotik) dhcpServers() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/dhcp-server")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikDhcpServer)
}

func (r *mqlMikrotik) dhcpLeases() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/dhcp-server/lease")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikDhcpLease)
}

func (r *mqlMikrotik) neighbors() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/neighbor")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikNeighbor)
}

func (r *mqlMikrotik) users() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/user")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikUser)
}

func (r *mqlMikrotik) userGroups() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/user/group")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikUserGroup)
}
