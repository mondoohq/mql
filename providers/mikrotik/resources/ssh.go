// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func sshArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                     llx.StringData("mikrotik.ssh"),
		"strongCrypto":             boolField(row, "strong-crypto"),
		"allowNoneCrypto":          boolField(row, "allow-none-crypto"),
		"hostKeySize":              intField(row, "host-key-size"),
		"hostKeyType":              llx.StringData(row["host-key-type"]),
		"forwardingEnabled":        llx.StringData(row["forwarding-enabled"]),
		"alwaysAllowPasswordLogin": boolField(row, "always-allow-password-login"),
		"ciphers":                  listField(row, "ciphers"),
	}
}

func (r *mqlMikrotik) ssh() (*mqlMikrotikSsh, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOne("/ip/ssh")
	if err != nil {
		return nil, err
	}
	if len(row) == 0 {
		r.Ssh.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.ssh", sshArgs(row))
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikSsh), nil
}

// initMikrotikSsh populates the resource when it is queried by its own name
// (`mikrotik.ssh.strongCrypto`) rather than reached through the `ssh` accessor
// on the device root.
func initMikrotikSsh(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	row, err := mikrotikConn(runtime).PrintOne("/ip/ssh")
	if err != nil {
		return nil, nil, err
	}
	if len(row) == 0 {
		return nil, nil, errNoMenu("/ip/ssh")
	}
	return sshArgs(row), nil, nil
}
