// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- l2tp server ---

func l2tpServerArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":     llx.StringData("mikrotik.interface.l2tpServer"),
		"enabled":  boolField(row, "enabled"),
		"useIpsec": llx.StringData(row["use-ipsec"]),
		// the pre-shared key itself is never read; only whether one is set
		"hasIpsecSecret":     presenceField(row, "ipsec-secret"),
		"authentication":     listField(row, "authentication"),
		"maxMtu":             intField(row, "max-mtu"),
		"maxMru":             intField(row, "max-mru"),
		"mrru":               llx.StringData(row["mrru"]),
		"keepaliveTimeout":   llx.StringData(row["keepalive-timeout"]),
		"defaultProfile":     llx.StringData(row["default-profile"]),
		"allowFastPath":      boolField(row, "allow-fast-path"),
		"oneSessionPerHost":  boolField(row, "one-session-per-host"),
		"callerIdType":       llx.StringData(row["caller-id-type"]),
		"maxSessions":        intField(row, "max-sessions"),
		"acceptProtoVersion": llx.StringData(row["accept-proto-version"]),
	}
}

func (r *mqlMikrotik) l2tpServer() (*mqlMikrotikInterfaceL2tpServer, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOneOptional("/interface/l2tp-server/server")
	if err != nil {
		return nil, err
	}
	if len(row) == 0 {
		r.L2tpServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.interface.l2tpServer", l2tpServerArgs(row))
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikInterfaceL2tpServer), nil
}

func initMikrotikInterfaceL2tpServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	row, err := mikrotikConn(runtime).PrintOneOptional("/interface/l2tp-server/server")
	if err != nil {
		return nil, nil, err
	}
	if len(row) == 0 {
		return nil, nil, errNoMenu("/interface/l2tp-server/server")
	}
	return l2tpServerArgs(row), nil, nil
}

// --- pptp server ---

func pptpServerArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":             llx.StringData("mikrotik.interface.pptpServer"),
		"enabled":          boolField(row, "enabled"),
		"authentication":   listField(row, "authentication"),
		"maxMtu":           intField(row, "max-mtu"),
		"maxMru":           intField(row, "max-mru"),
		"mrru":             llx.StringData(row["mrru"]),
		"keepaliveTimeout": llx.StringData(row["keepalive-timeout"]),
		"defaultProfile":   llx.StringData(row["default-profile"]),
	}
}

func (r *mqlMikrotik) pptpServer() (*mqlMikrotikInterfacePptpServer, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOneOptional("/interface/pptp-server/server")
	if err != nil {
		return nil, err
	}
	if len(row) == 0 {
		r.PptpServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.interface.pptpServer", pptpServerArgs(row))
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikInterfacePptpServer), nil
}

func initMikrotikInterfacePptpServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	row, err := mikrotikConn(runtime).PrintOneOptional("/interface/pptp-server/server")
	if err != nil {
		return nil, nil, err
	}
	if len(row) == 0 {
		return nil, nil, errNoMenu("/interface/pptp-server/server")
	}
	return pptpServerArgs(row), nil, nil
}

// --- sstp server ---

type mqlMikrotikInterfaceSstpServerInternal struct {
	cacheCertificate string
}

func sstpServerArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                    llx.StringData("mikrotik.interface.sstpServer"),
		"enabled":                 boolField(row, "enabled"),
		"port":                    intField(row, "port"),
		"verifyClientCertificate": llx.StringData(row["verify-client-certificate"]),
		"authentication":          listField(row, "authentication"),
		"tlsVersion":              llx.StringData(row["tls-version"]),
		"forceAes":                boolField(row, "force-aes"),
		"pfs":                     boolField(row, "pfs"),
		"maxMtu":                  intField(row, "max-mtu"),
		"maxMru":                  intField(row, "max-mru"),
		"mrru":                    llx.StringData(row["mrru"]),
		"keepaliveTimeout":        llx.StringData(row["keepalive-timeout"]),
		"defaultProfile":          llx.StringData(row["default-profile"]),
		"vrf":                     llx.StringData(row["vrf"]),
	}
}

func (r *mqlMikrotik) sstpServer() (*mqlMikrotikInterfaceSstpServer, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOneOptional("/interface/sstp-server/server")
	if err != nil {
		return nil, err
	}
	if len(row) == 0 {
		r.SstpServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.interface.sstpServer", sstpServerArgs(row))
	if err != nil {
		return nil, err
	}
	srv := res.(*mqlMikrotikInterfaceSstpServer)
	srv.cacheCertificate = certificateRefName(row["certificate"])
	return srv, nil
}

func initMikrotikInterfaceSstpServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	row, err := mikrotikConn(runtime).PrintOneOptional("/interface/sstp-server/server")
	if err != nil {
		return nil, nil, err
	}
	if len(row) == 0 {
		return nil, nil, errNoMenu("/interface/sstp-server/server")
	}
	res, err := CreateResource(runtime, "mikrotik.interface.sstpServer", sstpServerArgs(row))
	if err != nil {
		return nil, nil, err
	}
	res.(*mqlMikrotikInterfaceSstpServer).cacheCertificate = certificateRefName(row["certificate"])
	return nil, res, nil
}

func (r *mqlMikrotikInterfaceSstpServer) certificate() (*mqlMikrotikCertificate, error) {
	if r.cacheCertificate == "" {
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return certificateByName(r.MqlRuntime, r.cacheCertificate)
}

// --- ovpn server ---

type mqlMikrotikInterfaceOvpnServerInternal struct {
	cacheCertificate string
}

// ovpnServerEnabled reports whether an OpenVPN server accepts connections.
// Releases with a single OpenVPN server report `enabled`. Releases that hold
// several named servers, such as 7.25.1, carry `disabled` on each row
// instead.
func ovpnServerEnabled(row map[string]string) *llx.RawData {
	if _, ok := row["enabled"]; ok {
		return boolField(row, "enabled")
	}
	if v, ok := row["disabled"]; ok {
		return llx.BoolData(!parseBool(v))
	}
	return llx.NilData
}

func ovpnServerArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                     llx.StringData(rowID("mikrotik.interface.ovpnServer/", row, row["name"])),
		"name":                     llx.StringData(row["name"]),
		"enabled":                  ovpnServerEnabled(row),
		"port":                     intField(row, "port"),
		"protocol":                 llx.StringData(row["protocol"]),
		"mode":                     llx.StringData(row["mode"]),
		"requireClientCertificate": boolField(row, "require-client-certificate"),
		"ciphers":                  listField(row, "cipher"),
		"auth":                     listField(row, "auth"),
		"tlsVersion":               llx.StringData(row["tls-version"]),
		"userAuthMethod":           llx.StringData(row["user-auth-method"]),
		"redirectGateway":          llx.StringData(row["redirect-gateway"]),
		"netmask":                  intField(row, "netmask"),
		"macAddress":               llx.StringData(row["mac-address"]),
		"maxMtu":                   intField(row, "max-mtu"),
		"keepaliveTimeout":         llx.StringData(row["keepalive-timeout"]),
		"defaultProfile":           llx.StringData(row["default-profile"]),
		"vrf":                      llx.StringData(row["vrf"]),
	}
}

func newMikrotikOvpnServer(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.interface.ovpnServer", ovpnServerArgs(row))
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikInterfaceOvpnServer).cacheCertificate = certificateRefName(row["certificate"])
	return res, nil
}

// ovpnServer returns the first OpenVPN server. RouterOS releases that hold
// several named servers list them all; ovpnServers returns every one.
func (r *mqlMikrotik) ovpnServer() (*mqlMikrotikInterfaceOvpnServer, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOneOptional("/interface/ovpn-server/server")
	if err != nil {
		return nil, err
	}
	if len(row) == 0 {
		r.OvpnServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := newMikrotikOvpnServer(r.MqlRuntime, row)
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikInterfaceOvpnServer), nil
}

func (r *mqlMikrotik) ovpnServers() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).PrintOptional("/interface/ovpn-server/server")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikOvpnServer)
}

func initMikrotikInterfaceOvpnServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	row, err := mikrotikConn(runtime).PrintOneOptional("/interface/ovpn-server/server")
	if err != nil {
		return nil, nil, err
	}
	if len(row) == 0 {
		return nil, nil, errNoMenu("/interface/ovpn-server/server")
	}
	res, err := newMikrotikOvpnServer(runtime, row)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlMikrotikInterfaceOvpnServer) certificate() (*mqlMikrotikCertificate, error) {
	if r.cacheCertificate == "" {
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return certificateByName(r.MqlRuntime, r.cacheCertificate)
}
