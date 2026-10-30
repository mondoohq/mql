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

func ovpnServerArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                     llx.StringData("mikrotik.interface.ovpnServer"),
		"enabled":                  boolField(row, "enabled"),
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

func (r *mqlMikrotik) ovpnServer() (*mqlMikrotikInterfaceOvpnServer, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOneOptional("/interface/ovpn-server/server")
	if err != nil {
		return nil, err
	}
	if len(row) == 0 {
		r.OvpnServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.interface.ovpnServer", ovpnServerArgs(row))
	if err != nil {
		return nil, err
	}
	srv := res.(*mqlMikrotikInterfaceOvpnServer)
	srv.cacheCertificate = certificateRefName(row["certificate"])
	return srv, nil
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
	res, err := CreateResource(runtime, "mikrotik.interface.ovpnServer", ovpnServerArgs(row))
	if err != nil {
		return nil, nil, err
	}
	res.(*mqlMikrotikInterfaceOvpnServer).cacheCertificate = certificateRefName(row["certificate"])
	return nil, res, nil
}

func (r *mqlMikrotikInterfaceOvpnServer) certificate() (*mqlMikrotikCertificate, error) {
	if r.cacheCertificate == "" {
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return certificateByName(r.MqlRuntime, r.cacheCertificate)
}
