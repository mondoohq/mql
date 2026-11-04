// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/frr"
	"go.mondoo.com/mql/types"
)

// This file reads the runtime state of the daemons other than BGP. Each
// accessor asks one daemon, and a daemon that is not running answers with a
// refusal rather than with data, which is reported as an empty result.

// vtyshOptional runs a vtysh command whose daemon may not be running. It
// returns nil data when vtysh refuses the query.
func vtyshOptional(conn shared.Connection, command string) ([]byte, error) {
	out, err := runOutput(conn, vtyshCommand(command))
	if err != nil {
		return nil, err
	}
	if frr.Refused(out) {
		log.Debug().Str("command", command).Msg("vtysh has no answer for this daemon")
		return nil, nil
	}
	return out, nil
}

func (n *mqlFrr) ospfNeighbors() ([]any, error) {
	conn := n.MqlRuntime.Connection.(shared.Connection)

	var neighbors []frr.OSPFNeighbor
	for _, q := range []struct {
		version int64
		command string
	}{
		{2, "show ip ospf neighbor json"},
		{3, "show ipv6 ospf6 neighbor json"},
	} {
		out, err := vtyshOptional(conn, q.command)
		if err != nil {
			return nil, err
		}
		if out == nil {
			continue
		}
		parsed, err := frr.ParseOSPFNeighbors(q.version, out)
		if err != nil {
			// One protocol version that cannot be read must not hide the
			// other one.
			log.Debug().Err(err).Str("command", q.command).Msg("cannot parse ospf neighbors")
			continue
		}
		neighbors = append(neighbors, parsed...)
	}

	res := make([]any, 0, len(neighbors))
	for i := range neighbors {
		nb := &neighbors[i]
		id := fmt.Sprintf("frr.ospf.neighbor/%d/%s/%s", nb.Version, nb.NeighborID, nb.Interface)
		obj, err := CreateResource(n.MqlRuntime, "frr.ospf.neighbor", map[string]*llx.RawData{
			"__id":            llx.StringData(id),
			"version":         llx.IntData(nb.Version),
			"neighborId":      llx.StringData(nb.NeighborID),
			"state":           llx.StringData(nb.State),
			"full":            llx.BoolData(nb.Full),
			"role":            llx.StringData(nb.Role),
			"priority":        llx.IntData(nb.Priority),
			"address":         llx.StringData(nb.Address),
			"localAddress":    llx.StringData(nb.LocalAddress),
			"interface":       llx.StringData(nb.Interface),
			"uptimeMsec":      llx.IntData(nb.UptimeMsec),
			"deadTimeMsec":    llx.IntData(nb.DeadTimeMsec),
			"retransmitCount": llx.IntData(nb.RetransmitCount),
			"details":         llx.DictData(anyMapToDict(nb.Details)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (n *mqlFrr) isisNeighbors() ([]any, error) {
	conn := n.MqlRuntime.Connection.(shared.Connection)

	out, err := vtyshOptional(conn, "show isis neighbor json")
	if err != nil {
		return nil, err
	}
	if out == nil {
		return []any{}, nil
	}
	neighbors, err := frr.ParseISISNeighbors(out)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(neighbors))
	for i := range neighbors {
		nb := &neighbors[i]
		id := "frr.isis.neighbor/" + nb.Area + "/" + nb.SystemID + "/" + nb.Interface
		obj, err := CreateResource(n.MqlRuntime, "frr.isis.neighbor", map[string]*llx.RawData{
			"__id":      llx.StringData(id),
			"area":      llx.StringData(nb.Area),
			"systemId":  llx.StringData(nb.SystemID),
			"interface": llx.StringData(nb.Interface),
			"level":     llx.StringData(nb.Level),
			"state":     llx.StringData(nb.State),
			"up":        llx.BoolData(nb.Up),
			"expiresIn": llx.StringData(nb.ExpiresIn),
			"snpa":      llx.StringData(nb.SNPA),
			"details":   llx.DictData(anyMapToDict(nb.Details)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (n *mqlFrr) bfdSessions() ([]any, error) {
	conn := n.MqlRuntime.Connection.(shared.Connection)

	out, err := vtyshOptional(conn, "show bfd peers json")
	if err != nil {
		return nil, err
	}
	if out == nil {
		return []any{}, nil
	}
	sessions, err := frr.ParseBFDSessions(out)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(sessions))
	for i := range sessions {
		s := &sessions[i]
		id := "frr.bfd.session/" + vrfKey(s.VRF) + "/" + s.Peer + "/" + s.Interface
		obj, err := CreateResource(n.MqlRuntime, "frr.bfd.session", map[string]*llx.RawData{
			"__id":                   llx.StringData(id),
			"peer":                   llx.StringData(s.Peer),
			"local":                  llx.StringData(s.Local),
			"vrf":                    llx.StringData(s.VRF),
			"interface":              llx.StringData(s.Interface),
			"multiHop":               llx.BoolData(s.MultiHop),
			"status":                 llx.StringData(s.Status),
			"up":                     llx.BoolData(s.Up),
			"uptimeSec":              llx.IntData(s.UptimeSec),
			"diagnostic":             llx.StringData(s.Diagnostic),
			"remoteDiagnostic":       llx.StringData(s.RemoteDiag),
			"detectMultiplier":       llx.IntData(s.DetectMulti),
			"receiveInterval":        llx.IntData(s.ReceiveMsec),
			"transmitInterval":       llx.IntData(s.TransmitMsec),
			"echoInterval":           llx.IntData(s.EchoMsec),
			"remoteDetectMultiplier": llx.IntData(s.RemoteDetectMulti),
			"remoteReceiveInterval":  llx.IntData(s.RemoteReceiveMsec),
			"remoteTransmitInterval": llx.IntData(s.RemoteTransmitMsec),
			"details":                llx.DictData(anyMapToDict(s.Details)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (n *mqlFrr) interfaces() ([]any, error) {
	conn := n.MqlRuntime.Connection.(shared.Connection)

	out, err := vtyshOptional(conn, "show interface json")
	if err != nil {
		return nil, err
	}
	if out == nil {
		return []any{}, nil
	}
	ifaces, err := frr.ParseZebraInterfaces(out)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(ifaces))
	for i := range ifaces {
		f := &ifaces[i]
		obj, err := CreateResource(n.MqlRuntime, "frr.interface", map[string]*llx.RawData{
			"__id":            llx.StringData("frr.interface/" + f.Name),
			"name":            llx.StringData(f.Name),
			"adminUp":         llx.BoolData(f.AdminUp),
			"operUp":          llx.BoolData(f.OperUp),
			"vrf":             llx.StringData(f.VRF),
			"ifindex":         llx.IntData(f.IfIndex),
			"mtu":             llx.IntData(f.MTU),
			"speed":           llx.IntData(f.Speed),
			"type":            llx.StringData(f.Type),
			"hardwareAddress": llx.StringData(f.HardwareAddress),
			"addresses":       llx.ArrayData(stringSliceToAny(f.Addresses), types.String),
			"linkDowns":       llx.IntData(f.LinkDowns),
			"linkUps":         llx.IntData(f.LinkUps),
			"protocolDown":    llx.BoolData(f.ProtocolDown),
			"details":         llx.DictData(anyMapToDict(f.Details)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}
