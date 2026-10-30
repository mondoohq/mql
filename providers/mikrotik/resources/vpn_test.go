// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestL2tpServerArgs(t *testing.T) {
	row := map[string]string{
		"enabled":              "yes",
		"use-ipsec":            "no",
		"ipsec-secret":         "",
		"authentication":       "mschap2,mschap1,chap,pap",
		"max-mtu":              "1450",
		"max-mru":              "1450",
		"mrru":                 "disabled",
		"keepalive-timeout":    "30",
		"default-profile":      "default-encryption",
		"one-session-per-host": "no",
		"max-sessions":         "0",
	}
	args := l2tpServerArgs(row)

	assert.Equal(t, "mikrotik.interface.l2tpServer", args["__id"].Value)
	assert.Equal(t, true, args["enabled"].Value)
	// L2TP without IPsec is cleartext tunneling
	assert.Equal(t, "no", args["useIpsec"].Value)
	assert.Equal(t, false, args["hasIpsecSecret"].Value)
	assert.Equal(t, []any{"mschap2", "mschap1", "chap", "pap"}, args["authentication"].Value)
	assert.Equal(t, int64(1450), args["maxMtu"].Value)
	assert.Equal(t, int64(0), args["maxSessions"].Value)
}

func TestL2tpServerArgsWithIpsec(t *testing.T) {
	args := l2tpServerArgs(map[string]string{
		"enabled":      "yes",
		"use-ipsec":    "required",
		"ipsec-secret": "not-a-real-key",
	})

	assert.Equal(t, "required", args["useIpsec"].Value)
	// the key's presence is reported; the key itself never is
	assert.Equal(t, true, args["hasIpsecSecret"].Value)
	assert.NotContains(t, args, "ipsecSecret")
	for _, v := range args {
		assert.NotEqual(t, "not-a-real-key", v.Value)
	}
}

func TestL2tpServerArgsAbsentMenu(t *testing.T) {
	args := l2tpServerArgs(map[string]string{})

	assert.Nil(t, args["enabled"].Value)
	assert.Nil(t, args["hasIpsecSecret"].Value)
	assert.Nil(t, args["authentication"].Value)
	assert.Equal(t, "", args["useIpsec"].Value)
}

func TestPptpServerArgs(t *testing.T) {
	// PPTP is cryptographically broken but still shipped and still enableable,
	// so an enabled server is exactly what needs reporting
	on := pptpServerArgs(map[string]string{
		"enabled":        "yes",
		"authentication": "mschap2,mschap1",
	})
	assert.Equal(t, "mikrotik.interface.pptpServer", on["__id"].Value)
	assert.Equal(t, true, on["enabled"].Value)
	assert.Equal(t, []any{"mschap2", "mschap1"}, on["authentication"].Value)

	off := pptpServerArgs(map[string]string{"enabled": "no", "authentication": ""})
	assert.Equal(t, false, off["enabled"].Value)
	assert.Equal(t, []any{}, off["authentication"].Value)
}

func TestPptpServerArgsAbsentMenu(t *testing.T) {
	// an absent menu must not read as a disabled PPTP server
	args := pptpServerArgs(map[string]string{})

	assert.Nil(t, args["enabled"].Value)
	assert.Nil(t, args["authentication"].Value)
	assert.Nil(t, args["maxMtu"].Value)
}

func TestSstpServerArgs(t *testing.T) {
	row := map[string]string{
		"enabled":                   "yes",
		"port":                      "443",
		"verify-client-certificate": "no",
		"certificate":               "sstp-server",
		"authentication":            "mschap2",
		"tls-version":               "any",
		"force-aes":                 "no",
		"pfs":                       "no",
	}
	args := sstpServerArgs(row)

	assert.Equal(t, true, args["enabled"].Value)
	assert.Equal(t, int64(443), args["port"].Value)
	// with verification off, anyone who passes PPP auth gets a tunnel
	assert.Equal(t, "no", args["verifyClientCertificate"].Value)
	// the certificate name is carried only by certificate, never as a
	// field that duplicates it
	assert.NotContains(t, args, "certificate")
	assert.Equal(t, false, args["pfs"].Value)
}

func TestSstpServerArgsAbsentMenu(t *testing.T) {
	args := sstpServerArgs(map[string]string{})

	assert.Nil(t, args["enabled"].Value)
	assert.Nil(t, args["port"].Value)
	assert.Nil(t, args["forceAes"].Value)
	assert.Nil(t, args["pfs"].Value)
	assert.Equal(t, "", args["verifyClientCertificate"].Value)
}

func TestOvpnServerArgs(t *testing.T) {
	row := map[string]string{
		"enabled":                    "yes",
		"port":                       "1194",
		"protocol":                   "udp",
		"mode":                       "ip",
		"require-client-certificate": "no",
		"certificate":                "ovpn-server",
		"cipher":                     "blowfish128,aes128-cbc",
		"auth":                       "sha1,md5",
		"netmask":                    "24",
		"tls-version":                "any",
	}
	args := ovpnServerArgs(row)

	assert.Equal(t, true, args["enabled"].Value)
	assert.Equal(t, int64(1194), args["port"].Value)
	assert.Equal(t, "udp", args["protocol"].Value)
	// without a client certificate, PPP credentials are the only client auth
	assert.Equal(t, false, args["requireClientCertificate"].Value)
	assert.NotContains(t, args, "certificate")
	// RouterOS names the cipher attribute in the singular
	assert.Equal(t, []any{"blowfish128", "aes128-cbc"}, args["ciphers"].Value)
	assert.Equal(t, []any{"sha1", "md5"}, args["auth"].Value)
	assert.Equal(t, int64(24), args["netmask"].Value)
}

func TestOvpnServerArgsAbsentMenu(t *testing.T) {
	args := ovpnServerArgs(map[string]string{})

	assert.Nil(t, args["enabled"].Value)
	assert.Nil(t, args["requireClientCertificate"].Value)
	assert.Nil(t, args["ciphers"].Value)
	assert.Nil(t, args["auth"].Value)
}
