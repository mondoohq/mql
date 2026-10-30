// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/aristanetworks/goeapi/module"
)

// showIPBgpSummary represents the response from "show ip bgp summary"
type showIPBgpSummary struct {
	VRFs map[string]showBgpVrf `json:"vrfs"`
}

func (s *showIPBgpSummary) GetCmd() string {
	return "show ip bgp summary"
}

type showBgpVrf struct {
	RouterID string `json:"routerId"`
	// ASN is the local autonomous system number. EOS has rendered this both
	// as a JSON number and as a string across releases, and goeapi decodes
	// with mapstructure with weak typing off, so any concrete type here
	// fails the whole `show ip bgp summary` command on whichever release
	// disagrees with it, and arista.eos.bgp.vrfs returns no data at all.
	// Read it with ASNString.
	ASN   any                    `json:"asn"`
	Peers map[string]showBgpPeer `json:"peers"`
}

// ASNString renders an autonomous system number that EOS may have sent as
// either a JSON number or a string. An absent value reads as empty rather
// than as AS 0, which is a real reserved AS number and not what a missing
// field means.
func ASNString(v any) string {
	switch n := v.(type) {
	case nil:
		return ""
	case string:
		return n
	case float64:
		return strconv.FormatInt(int64(n), 10)
	case int64:
		return strconv.FormatInt(n, 10)
	case int:
		return strconv.Itoa(n)
	case json.Number:
		return n.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

type showBgpPeer struct {
	PeerState      string  `json:"peerState"`
	InMsgQueue     int64   `json:"inMsgQueue"`
	OutMsgQueue    int64   `json:"outMsgQueue"`
	UpDownTime     float64 `json:"upDownTime"`
	PrefixAccepted int64   `json:"prefixAccepted"`
	PrefixReceived int64   `json:"prefixReceived"`
	// See showBgpVrf.ASN: the same field has varied between a number and a
	// string across releases, so it is read through ASNString too.
	ASN              any  `json:"asn"`
	UnderMaintenance bool `json:"underMaintenance"`
}

// BGPSummary returns BGP summary information for all VRFs
func (eos *Eos) BGPSummary() (*showIPBgpSummary, error) {
	shRsp := &showIPBgpSummary{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	err = handle.AddCommand(shRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}

	return shRsp, nil
}

// BGPConfig returns BGP configuration using the goeapi module
func (eos *Eos) BGPConfig() *module.BgpConfig {
	bgpModule := module.Bgp(eos.node)
	return bgpModule.Get()
}

// showIPBgpNeighbors represents the response from "show ip bgp neighbors"
type showIPBgpNeighbors struct {
	VRFs map[string]showBgpNeighborsVrf `json:"vrfs"`
}

func (s *showIPBgpNeighbors) GetCmd() string {
	return "show ip bgp neighbors"
}

type showBgpNeighborsVrf struct {
	PeerList []showBgpNeighborDetail `json:"peerList"`
}

type showBgpNeighborDetail struct {
	PeerAddress string `json:"peerAddress"`
	Description string `json:"description"`
	// ASN varies between a number and a string across releases exactly as it
	// does on showBgpVrf and showBgpPeer. Nothing reads it today, but an
	// unread field still gates the decode: mapstructure fills the whole
	// struct, so the wrong type here fails all of `show ip bgp neighbors`.
	// That failure is quieter than the summary one, because the caller
	// degrades to nil rather than erroring, and every peer silently loses its
	// description and its inbound and outbound policies. Read via ASNString.
	ASN              any    `json:"asn"`
	InboundRouteMap  string `json:"inboundRouteMap"`
	OutboundRouteMap string `json:"outboundRouteMap"`
}

// BGPNeighbors returns detailed BGP neighbor information
func (eos *Eos) BGPNeighbors() (*showIPBgpNeighbors, error) {
	shRsp := &showIPBgpNeighbors{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	err = handle.AddCommand(shRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}

	return shRsp, nil
}
