// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/arista/resources/eos"
	"go.mondoo.com/mql/types"
)

// =====================================================================
// arista.eos.aaa.tacacsServer (list)
// =====================================================================

// id keys a server on VRF, host and port, since the same address can be
// configured more than once across routing instances or ports.
func (a *mqlAristaEosAaaTacacsServer) id() (string, error) {
	if a.Host.Error != nil {
		return "", a.Host.Error
	}
	if a.Vrf.Error != nil {
		return "", a.Vrf.Error
	}
	if a.Port.Error != nil {
		return "", a.Port.Error
	}
	return "arista.eos.aaa.tacacsServer/" + a.Vrf.Data + "/" + a.Host.Data + "/" +
		strconv.FormatInt(a.Port.Data, 10), nil
}

func (a *mqlAristaEosAaa) tacacsServerHosts() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	servers := eos.ParseTacacsServers(rc)

	res := make([]any, 0, len(servers))
	for _, s := range servers {
		mqlServer, err := CreateResource(a.MqlRuntime, "arista.eos.aaa.tacacsServer", map[string]*llx.RawData{
			"host":              llx.StringData(s.Host),
			"vrf":               llx.StringData(s.VRF),
			"port":              llx.IntData(int64(s.Port)),
			"timeout":           llx.IntData(int64(s.Timeout)),
			"singleConnection":  llx.BoolData(s.SingleConnection),
			"keyConfigured":     llx.BoolData(s.KeyConfigured),
			"keyEncryptionType": llx.StringData(s.KeyEncryptionType),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlServer)
	}
	return res, nil
}

// =====================================================================
// arista.eos.aaa.radiusServer (list)
// =====================================================================

func (a *mqlAristaEosAaaRadiusServer) id() (string, error) {
	if a.Host.Error != nil {
		return "", a.Host.Error
	}
	if a.Vrf.Error != nil {
		return "", a.Vrf.Error
	}
	if a.AuthPort.Error != nil {
		return "", a.AuthPort.Error
	}
	if a.AcctPort.Error != nil {
		return "", a.AcctPort.Error
	}
	// RADIUS splits authentication and accounting across two independently
	// configurable ports, so one host can be defined twice differing only in
	// the accounting port. Both belong in the key.
	return "arista.eos.aaa.radiusServer/" + a.Vrf.Data + "/" + a.Host.Data + "/" +
		strconv.FormatInt(a.AuthPort.Data, 10) + "/" +
		strconv.FormatInt(a.AcctPort.Data, 10), nil
}

func (a *mqlAristaEosAaa) radiusServerHosts() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	servers := eos.ParseRadiusServers(rc)

	res := make([]any, 0, len(servers))
	for _, s := range servers {
		mqlServer, err := CreateResource(a.MqlRuntime, "arista.eos.aaa.radiusServer", map[string]*llx.RawData{
			"host":              llx.StringData(s.Host),
			"vrf":               llx.StringData(s.VRF),
			"authPort":          llx.IntData(int64(s.AuthPort)),
			"acctPort":          llx.IntData(int64(s.AcctPort)),
			"timeout":           llx.IntData(int64(s.Timeout)),
			"retransmit":        llx.IntData(int64(s.Retransmit)),
			"keyConfigured":     llx.BoolData(s.KeyConfigured),
			"keyEncryptionType": llx.StringData(s.KeyEncryptionType),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlServer)
	}
	return res, nil
}

// =====================================================================
// arista.eos.aaa.serverGroup (list)
// =====================================================================

// id keys a group on protocol and name: EOS allows a TACACS+ group and a
// RADIUS group to carry the same name.
func (a *mqlAristaEosAaaServerGroup) id() (string, error) {
	if a.Protocol.Error != nil {
		return "", a.Protocol.Error
	}
	if a.Name.Error != nil {
		return "", a.Name.Error
	}
	return "arista.eos.aaa.serverGroup/" + a.Protocol.Data + "/" + a.Name.Data, nil
}

func (a *mqlAristaEosAaa) serverGroups() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	groups := eos.ParseAaaServerGroups(rc)

	res := make([]any, 0, len(groups))
	for _, g := range groups {
		mqlGroup, err := CreateResource(a.MqlRuntime, "arista.eos.aaa.serverGroup", map[string]*llx.RawData{
			"name":     llx.StringData(g.Name),
			"protocol": llx.StringData(g.Protocol),
			"servers":  llx.ArrayData(stringSliceToAny(g.Servers), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}
