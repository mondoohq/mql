// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package sriov reads the SR-IOV state of a Linux host.
//
// Two sources are combined. Sysfs reports the hardware inventory: which
// physical function has virtual functions, how many, their PCI addresses and
// the driver each one is bound to. The link layer reports the administrative
// configuration the physical function enforces on each virtual function: MAC,
// VLAN, spoof checking, trust and rate limits. Neither source is visible to
// the Kubernetes API, which only counts the devices a device plugin
// advertises.
package sriov

import (
	"encoding/json"
	"strconv"
	"strings"
)

// PhysicalFunction is an SR-IOV capable network interface.
type PhysicalFunction struct {
	Interface        string
	PCIAddress       string
	Driver           string
	VendorID         string
	DeviceID         string
	NumVFs           int64
	TotalVFs         int64
	MACAddress       string
	MTU              int64
	OperationalState string
	NUMANode         int64
	VirtualFunctions []VirtualFunction
}

// VirtualFunction is one virtual function of a physical function.
type VirtualFunction struct {
	Index      int64
	PCIAddress string
	Driver     string
	Interface  string
	VendorID   string
	DeviceID   string
	NUMANode   int64

	// Link configuration, present when the link layer reports the virtual
	// function. A virtual function the kernel does not report keeps the zero
	// values and LinkConfigured stays false.
	LinkConfigured bool
	MACAddress     string
	VlanID         int64
	QoS            int64
	SpoofChecking  bool
	Trusted        bool
	LinkState      string
	MinTxRate      int64
	MaxTxRate      int64
}

// passthroughDrivers bind a virtual function for userspace datapaths such as
// DPDK. A device bound to one of them has no kernel network interface, so the
// host stack cannot filter its traffic.
var passthroughDrivers = map[string]struct{}{
	"vfio-pci":        {},
	"uio_pci_generic": {},
	"igb_uio":         {},
	"vfio":            {},
}

// UsesPassthroughDriver reports whether the virtual function is bound to a
// userspace passthrough driver rather than a kernel network driver.
func (v VirtualFunction) UsesPassthroughDriver() bool {
	_, ok := passthroughDrivers[v.Driver]
	return ok
}

// ParseSysfs reads the output of the sysfs walk into physical functions.
//
// The walk emits one "===PF===<interface>" line per physical function, then
// "key=value" lines, then one "===VF===<index>" line per virtual function with
// its own key/value lines. Unknown keys are ignored, so a newer walk can add
// keys without breaking an older reader.
func ParseSysfs(output string) []PhysicalFunction {
	pfs := []PhysicalFunction{}
	var pf *PhysicalFunction
	var vf *VirtualFunction

	flushVF := func() {
		if pf != nil && vf != nil {
			pf.VirtualFunctions = append(pf.VirtualFunctions, *vf)
		}
		vf = nil
	}
	flushPF := func() {
		flushVF()
		if pf != nil {
			pfs = append(pfs, *pf)
		}
		pf = nil
	}

	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, pfMarker):
			flushPF()
			pf = &PhysicalFunction{
				Interface:        strings.TrimPrefix(line, pfMarker),
				NUMANode:         unknownNUMANode,
				VirtualFunctions: []VirtualFunction{},
			}
		case strings.HasPrefix(line, vfMarker):
			flushVF()
			if pf == nil {
				continue
			}
			index, err := strconv.ParseInt(strings.TrimPrefix(line, vfMarker), 10, 64)
			if err != nil {
				continue
			}
			vf = &VirtualFunction{Index: index, NUMANode: unknownNUMANode}
		default:
			key, value, ok := strings.Cut(line, "=")
			if !ok || pf == nil {
				continue
			}
			if vf != nil {
				applyVFField(vf, key, strings.TrimSpace(value))
				continue
			}
			applyPFField(pf, key, strings.TrimSpace(value))
		}
	}
	flushPF()
	return pfs
}

const (
	pfMarker = "===PF==="
	vfMarker = "===VF==="

	// unknownNUMANode is what sysfs reports for a device with no NUMA
	// affinity, and what the parser reports when the file is absent.
	unknownNUMANode = int64(-1)
)

func applyPFField(pf *PhysicalFunction, key, value string) {
	switch key {
	case "pciAddress":
		pf.PCIAddress = value
	case "driver":
		pf.Driver = value
	case "vendor":
		pf.VendorID = normalizeHexID(value)
	case "device":
		pf.DeviceID = normalizeHexID(value)
	case "numa_node":
		pf.NUMANode = parseInt(value, unknownNUMANode)
	case "sriov_numvfs":
		pf.NumVFs = parseInt(value, 0)
	case "sriov_totalvfs":
		pf.TotalVFs = parseInt(value, 0)
	case "net.address":
		pf.MACAddress = value
	case "net.mtu":
		pf.MTU = parseInt(value, 0)
	case "net.operstate":
		pf.OperationalState = value
	}
}

func applyVFField(vf *VirtualFunction, key, value string) {
	switch key {
	case "pciAddress":
		vf.PCIAddress = value
	case "driver":
		vf.Driver = value
	case "vendor":
		vf.VendorID = normalizeHexID(value)
	case "device":
		vf.DeviceID = normalizeHexID(value)
	case "numa_node":
		vf.NUMANode = parseInt(value, unknownNUMANode)
	case "interface":
		vf.Interface = value
	}
}

// normalizeHexID strips the 0x prefix sysfs writes on PCI vendor and device
// IDs, so the value matches what a device-plugin selector lists.
func normalizeHexID(value string) string {
	return strings.TrimPrefix(strings.ToLower(value), "0x")
}

func parseInt(value string, fallback int64) int64 {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

// linkInterface is the subset of `ip -details -json link show` the reader uses.
type linkInterface struct {
	IfName   string   `json:"ifname"`
	VFInfo   []linkVF `json:"vfinfo_list"`
	LinkInfo struct {
		InfoData struct {
			VFInfo []linkVF `json:"vfinfo_list"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

type linkVF struct {
	VF        int64  `json:"vf"`
	Address   string `json:"address"`
	SpoofChk  *bool  `json:"spoofchk"`
	Trust     *bool  `json:"trust"`
	LinkState string `json:"link_state"`
	VlanList  []struct {
		Vlan int64 `json:"vlan"`
		QoS  int64 `json:"qos"`
	} `json:"vlan_list"`
	// Older iproute2 reports a single VLAN inline rather than a list.
	Vlan *int64 `json:"vlan"`
	QoS  *int64 `json:"qos"`
	Rate *struct {
		MaxTxRate int64 `json:"max_tx_rate"`
		MinTxRate int64 `json:"min_tx_rate"`
	} `json:"rate"`
	MaxTxRate *int64 `json:"max_tx_rate"`
	MinTxRate *int64 `json:"min_tx_rate"`
}

// ParseLinkConfig reads `ip -details -json link show` into the per-interface
// virtual function configuration, keyed by physical function interface name
// and then by virtual function index.
func ParseLinkConfig(output string) (map[string]map[int64]VirtualFunction, error) {
	out := map[string]map[int64]VirtualFunction{}
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return out, nil
	}

	var links []linkInterface
	if err := json.Unmarshal([]byte(trimmed), &links); err != nil {
		return nil, err
	}

	for _, link := range links {
		infos := link.VFInfo
		if len(infos) == 0 {
			infos = link.LinkInfo.InfoData.VFInfo
		}
		if len(infos) == 0 || link.IfName == "" {
			continue
		}
		byIndex := make(map[int64]VirtualFunction, len(infos))
		for _, info := range infos {
			byIndex[info.VF] = info.virtualFunction()
		}
		out[link.IfName] = byIndex
	}
	return out, nil
}

func (l linkVF) virtualFunction() VirtualFunction {
	vf := VirtualFunction{
		Index:          l.VF,
		LinkConfigured: true,
		MACAddress:     l.Address,
		LinkState:      l.LinkState,
	}
	if l.SpoofChk != nil {
		vf.SpoofChecking = *l.SpoofChk
	}
	if l.Trust != nil {
		vf.Trusted = *l.Trust
	}
	// A build that reports both shapes writes the same VLAN twice, so the flat
	// field wins and the reading is the same either way.
	if len(l.VlanList) > 0 {
		vf.VlanID = l.VlanList[0].Vlan
		vf.QoS = l.VlanList[0].QoS
	}
	if l.Vlan != nil {
		vf.VlanID = *l.Vlan
	}
	if l.QoS != nil {
		vf.QoS = *l.QoS
	}
	// Same precedence for the rates.
	if l.Rate != nil {
		vf.MaxTxRate = l.Rate.MaxTxRate
		vf.MinTxRate = l.Rate.MinTxRate
	}
	if l.MaxTxRate != nil {
		vf.MaxTxRate = *l.MaxTxRate
	}
	if l.MinTxRate != nil {
		vf.MinTxRate = *l.MinTxRate
	}
	return vf
}

// Merge folds the link configuration into the sysfs inventory.
//
// A virtual function the link layer does not report keeps its sysfs values and
// LinkConfigured stays false, so an unreported device is not reported as one
// with spoof checking off.
func Merge(pfs []PhysicalFunction, linkConfig map[string]map[int64]VirtualFunction) []PhysicalFunction {
	for i := range pfs {
		byIndex, ok := linkConfig[pfs[i].Interface]
		if !ok {
			continue
		}
		for j := range pfs[i].VirtualFunctions {
			config, ok := byIndex[pfs[i].VirtualFunctions[j].Index]
			if !ok {
				continue
			}
			vf := &pfs[i].VirtualFunctions[j]
			vf.LinkConfigured = true
			vf.MACAddress = config.MACAddress
			vf.VlanID = config.VlanID
			vf.QoS = config.QoS
			vf.SpoofChecking = config.SpoofChecking
			vf.Trusted = config.Trusted
			vf.LinkState = config.LinkState
			vf.MinTxRate = config.MinTxRate
			vf.MaxTxRate = config.MaxTxRate
		}
	}
	return pfs
}
