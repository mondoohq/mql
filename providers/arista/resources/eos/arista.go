// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aristanetworks/goeapi"
	"github.com/aristanetworks/goeapi/module"
)

func NewEos(node *goeapi.Node) *Eos {
	return &Eos{node: node}
}

type Eos struct {
	node *goeapi.Node
}

// RunningConfig returns the device's running-config, with every default
// rendered explicitly.
//
// It deliberately does not use the eAPI client's own RunningConfig(), which
// returns a bare string and discards the error: a permission gap or a timeout
// there yields "", and an empty running-config parses cleanly into "no TACACS
// servers, no syslog collectors, no ACL bindings, dot1x disabled" — a
// confident pass for every hardening check, with nothing to attribute it to.
func (eos *Eos) RunningConfig() (string, error) {
	return configText(eos.node, goeapi.RunningConfig, "all")
}

// RunningConfigPlain returns the running-config rendered the way the
// startup-config is, with defaults left implicit.
//
// RunningConfig asks for `all`, which expands every default-valued setting so
// the parsers see the device's effective state. That is the right input for
// parsing and the wrong input for drift comparison: the startup-config never
// carries those defaults, so comparing the two renderings reports drift on a
// device that was just saved.
func (eos *Eos) RunningConfigPlain() (string, error) {
	return configText(eos.node, goeapi.RunningConfig, "")
}

// configText fetches a configuration as text and fails loudly rather than
// returning a partial or empty result. An EOS device never renders an empty
// configuration, so an empty body is a failed read, not a bare device.
func configText(node *goeapi.Node, config, params string) (string, error) {
	res, err := node.GetConfig(config, params, "text")
	if err != nil {
		return "", fmt.Errorf("could not read %s: %w", config, err)
	}
	return configTextFromResponse(res, config)
}

// configTextFromResponse extracts the configuration body from a successful
// response, rejecting the two shapes that would otherwise become an empty
// string: a response carrying no text output, and one carrying an empty body.
func configTextFromResponse(res map[string]any, config string) (string, error) {
	out, ok := res["output"].(string)
	if !ok {
		return "", fmt.Errorf("could not read %s: response carried no text output", config)
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return "", fmt.Errorf("could not read %s: device returned an empty configuration", config)
	}
	return out, nil
}

func (eos *Eos) SystemConfig() map[string]string {
	// get api system module
	sys := module.System(eos.node)
	return sys.Get()
}

func (eos *Eos) ShowInterface() module.ShowInterface {
	show := module.Show(eos.node)
	return show.ShowInterfaces()
}

func (eos *Eos) IPInterfaces() []module.IPInterfaceConfig {
	ifaceModule := module.IPInterface(eos.node)
	interfaces := ifaceModule.GetAll()

	res := []module.IPInterfaceConfig{}
	for i := range interfaces {
		iface := interfaces[i]
		res = append(res, iface)
	}
	return res
}

type showInterfacesStatus struct {
	InterfaceStatuses map[string]InterfaceStatus
}

func (s *showInterfacesStatus) GetCmd() string {
	return "show interfaces status"
}

type InterfaceStatus struct {
	Bandwidth           int64    `json:"bandwidth"`
	InterfaceType       string   `json:"interfaceType"`
	Description         string   `json:"description"`
	AutoNegotiateActive bool     `json:"autoNegotiateActive"`
	Duplex              string   `json:"duplex"`
	LinkStatus          string   `json:"linkStatus"`
	LineProtocolStatus  string   `json:"lineProtocolStatus"`
	VlanInformation     vlanInfo `json:"vlanInformation"`
}

type vlanInfo struct {
	InterfaceMode            string `json:"interfaceMode"`
	VlanID                   int64  `json:"vlanId"`
	InterfaceForwardingModel string `json:"interfaceForwardingModel"`
}

func (eos *Eos) ShowInterfacesStatus() (map[string]InterfaceStatus, error) {
	shIntRsp := &showInterfacesStatus{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	err = handle.AddCommand(shIntRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}

	return shIntRsp.InterfaceStatuses, nil
}

type showSpanningTree struct {
	SpanningTreeInstances map[string]SptMstInstance
}

func (s *showSpanningTree) GetCmd() string {
	return "show spanning-tree"
}

type showSpanningTreeMst struct {
	SpanningTreeMstInstances map[string]SptMstInstance
}

func (s *showSpanningTreeMst) GetCmd() string {
	return "show spanning-tree mst detail"
}

type SptMstInstance struct {
	Protocol           string                     `json:"protocol"` // NOTE: only returned for `show spanning-tree` but not `show spanning-tree mst`
	Bridge             sptMstBridge               `json:"bridge"`
	RootBridge         sptMstBridge               `json:"rootBridge"`
	RegionalRootBridge sptMstBridge               `json:"regionalRootBridge"`
	Interfaces         map[string]sptMstInterface `json:"interfaces"`
}

type sptMstBridge struct {
	Priority          int64   `json:"priority"`
	MacAddress        string  `json:"macAddress"`
	SystemIdExtension float64 `json:"systemIdExtension"`

	// NOTE: only returned for `show spanning-tree` but not `show spanning-tree mst`
	ForwardDelay int64 `json:"forwardDelay,omitempty"`
	HelloTime    int64 `json:"helloTime,omitempty"`
	MaxAge       int64 `json:"maxAge,omitempty"`
}

type sptMstInterface struct {
	Priority             int64  `json:"priority"`
	LinkType             string `json:"linkType"`
	State                string `json:"state"`
	Cost                 int64  `json:"cost"`
	Role                 string `json:"role"`
	InconsistentFeatures struct {
		LoopGuard       bool `json:"loopGuard"`
		RootGuard       bool `json:"rootGuard"`
		MstPvstBorder   bool `json:"mstPvstBorder"`
		BridgeAssurance bool `json:"bridgeAssurance"`
	} `json:"inconsistentFeatures"`
	PortNumber int64 `json:"portNumber"`
	IsEdgePort bool  `json:"isEdgePort"`
	Detail     struct {
		DesignatedBridgePriority int64  `json:"designatedBridgePriority"`
		RegionalRootPriority     int64  `json:"regionalRootPriority"`
		RegionalRootAddress      string `json:"regionalRootAddress"`
		DesignatedRootPriority   int64  `json:"designatedRootPriority"`
		DesignatedPortNumber     int64  `json:"designatedPortNumber"`
		DesignatedBridgeAddress  string `json:"designatedBridgeAddress"`
		DesignatedPortPriority   int64  `json:"designatedPortPriority"`
		DesignatedRootAddress    string `json:"designatedRootAddress"`
	} `json:"detail"`
}

// runs both
// show spanning-tree
// show spanning-tree mst
func (eos *Eos) Stp() (map[string]SptMstInstance, error) {
	shRsp := &showSpanningTree{}
	shMstRsp := &showSpanningTreeMst{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	err = handle.AddCommand(shRsp)
	if err != nil {
		return nil, err
	}
	err = handle.AddCommand(shMstRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}

	handle.Close()

	// merge the information
	merge := shMstRsp.SpanningTreeMstInstances

	for k := range merge {
		entry := merge[k]

		// check if we found the protocol stuff
		tobemerged, ok := shRsp.SpanningTreeInstances[k]
		if ok {
			entry.Protocol = tobemerged.Protocol
			entry.Bridge.HelloTime = tobemerged.Bridge.HelloTime
			entry.Bridge.MaxAge = tobemerged.Bridge.MaxAge
			entry.Bridge.ForwardDelay = tobemerged.Bridge.ForwardDelay
		}
		merge[k] = entry
	}

	return merge, nil
}

type showSpanningTreeMstInstanceDetail struct {
	cmd                      string
	SpanningTreeMstInterface SptMestInterfaceDetail
}

func (s *showSpanningTreeMstInstanceDetail) GetCmd() string {
	return s.cmd
}

var (
	// An MST instance id is a non-negative integer.
	aristaMstInstanceIDRe = regexp.MustCompile(`^[0-9]+$`)
	// EOS interface names are alphanumeric with `/`, `-`, and `.` separators
	// (e.g. Ethernet1, Ethernet1/1, Port-Channel3, Ethernet1.100). Notably
	// they never contain spaces.
	aristaInterfaceNameRe = regexp.MustCompile(`^[A-Za-z0-9/.\-]+$`)
)

// stpInterfaceDetailCmd builds the EOS command for a given MST instance and
// interface. Previously the command was hardcoded to `mst 0 ... Ethernet1`, so
// every call returned details for that one interface regardless of the
// requested instance/interface arguments. Both arguments are validated against
// an allowlist before interpolation so a malformed identifier can't produce a
// corrupt command on the device.
func stpInterfaceDetailCmd(mstInstanceID, iface string) (string, error) {
	if !aristaMstInstanceIDRe.MatchString(mstInstanceID) {
		return "", fmt.Errorf("invalid MST instance id %q", mstInstanceID)
	}
	if !aristaInterfaceNameRe.MatchString(iface) {
		return "", fmt.Errorf("invalid interface name %q", iface)
	}
	return fmt.Sprintf("show spanning-tree mst %s interface %s detail", mstInstanceID, iface), nil
}

type SptMestInterfaceDetail struct {
	IsEdgePort bool `json:"isEdgePort"`
	Features   struct {
		LinkType struct {
			Default bool   `json:"default"`
			Value   string `json:"value"`
		} `json:"linkType"`
		BpduGuard struct {
			Default bool   `json:"default"`
			Value   string `json:"value"`
		} `json:"bpduGuard"`
		BpduFilter struct {
			Default bool   `json:"default"`
			Value   string `json:"value"`
		} `json:"BpduFilter"`
	} `json:"features"`
	InterfaceName string `json:"interfaceName"`
	Counters      struct {
		BpduRateLimitCount int64 `json:"bpduRateLimitCount"`
		BpduOtherError     int64 `json:"bpduOtherError"`
		BpduReceived       int64 `json:"bpduReceived"`
		BpduTaggedError    int64 `json:"bpduTaggedError"`
		BpduSent           int64 `json:"bpduSent"`
	} `json:"counters"`
}

// show spanning-tree mst <instance> interface <iface> detail
func (eos *Eos) StpInterfaceDetails(mstInstanceID string, iface string) (SptMestInterfaceDetail, error) {
	cmd, err := stpInterfaceDetailCmd(mstInstanceID, iface)
	if err != nil {
		return SptMestInterfaceDetail{}, err
	}
	shRsp := &showSpanningTreeMstInstanceDetail{cmd: cmd}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return SptMestInterfaceDetail{}, err
	}
	err = handle.AddCommand(shRsp)
	if err != nil {
		return SptMestInterfaceDetail{}, err
	}

	if err := handle.Call(); err != nil {
		return SptMestInterfaceDetail{}, err
	}

	handle.Close()

	return shRsp.SpanningTreeMstInterface, nil
}

type showHostname struct {
	Fqdn     string `json:"fqdn"`
	Hostname string `json:"hostname"`
}

func (s *showHostname) GetCmd() string {
	return "show hostname"
}

func (eos *Eos) ShowHostname() (*showHostname, error) {
	shIntRsp := &showHostname{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	err = handle.AddCommand(shIntRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}

	return shIntRsp, nil
}

// Vlans returns all configured VLANs using the goeapi module
func (eos *Eos) Vlans() map[string]module.VlanConfig {
	vlanModule := module.Vlan(eos.node)
	return vlanModule.GetAll()
}

// showVlan represents the response from "show vlan"
type showVlan struct {
	SourceDetail string              `json:"sourceDetail"`
	Vlans        map[string]ShowVlan `json:"vlans"`
}

func (s *showVlan) GetCmd() string {
	return "show vlan"
}

// ShowVlan represents a single VLAN from the "show vlan" JSON output
type ShowVlan struct {
	Status     string                   `json:"status"`
	Name       string                   `json:"name"`
	Interfaces map[string]VlanInterface `json:"interfaces"`
	Dynamic    bool                     `json:"dynamic"`
}

// VlanInterface represents an interface associated with a VLAN
type VlanInterface struct {
	Annotation      string `json:"annotation"`
	PrivatePromoted bool   `json:"privatePromoted"`
}

// ShowVlans returns VLAN information from the "show vlan" JSON command
func (eos *Eos) ShowVlans() (map[string]ShowVlan, error) {
	shRsp := &showVlan{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	err = handle.AddCommand(shRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}

	handle.Close()

	return shRsp.Vlans, nil
}

// Switchports returns all switchport configurations using the goeapi module
func (eos *Eos) Switchports() map[string]module.SwitchPortConfig {
	switchportModule := module.SwitchPort(eos.node)
	return switchportModule.GetAll()
}

// showIPRoute represents the response from "show ip route"
type showIPRoute struct {
	VRFs map[string]showIPRouteVRF `json:"vrfs"`
}

func (s *showIPRoute) GetCmd() string {
	return "show ip route"
}

type showIPRouteVRF struct {
	Routes map[string]showIPRouteEntry `json:"routes"`
}

type showIPRouteEntry struct {
	KernelProgrammed   bool             `json:"kernelProgrammed"`
	DirectlyConnected  bool             `json:"directlyConnected"`
	Preference         int              `json:"preference"`
	RouteAction        string           `json:"routeAction"`
	Vias               []showIPRouteVia `json:"vias"`
	Metric             int              `json:"metric"`
	HardwareProgrammed bool             `json:"hardwareProgrammed"`
	RouteType          string           `json:"routeType"`
}

type showIPRouteVia struct {
	Interface   string `json:"interface"`
	NexthopAddr string `json:"nexthopAddr"`
}

// ShowIPRoute returns the IP routing table
func (eos *Eos) ShowIPRoute() (*showIPRoute, error) {
	shRsp := &showIPRoute{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	err = handle.AddCommand(shRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}

	handle.Close()

	return shRsp, nil
}

// MlagConfig returns the MLAG configuration using the goeapi module
func (eos *Eos) MlagConfig() *module.MlagConfig {
	mlagModule := module.Mlag(eos.node)
	return mlagModule.Get()
}

// showEnvironmentPower represents the response from "show system environment power"
type showEnvironmentPower struct {
	PowerSupplies map[string]PowerSupply `json:"powerSupplies"`
}

func (s *showEnvironmentPower) GetCmd() string {
	return "show system environment power"
}

// PowerSupply represents a single power supply unit
type PowerSupply struct {
	OutputPower  float64 `json:"outputPower"`
	State        string  `json:"state"`
	ModelName    string  `json:"modelName"`
	Capacity     int     `json:"capacity"`
	InputCurrent float64 `json:"inputCurrent"`
	TempSensors  map[string]struct {
		Status      string `json:"status"`
		Temperature int    `json:"temperature"`
	} `json:"tempSensors"`
	Fans map[string]struct {
		Status string `json:"status"`
		Speed  int    `json:"speed"`
	} `json:"fans"`
	OutputCurrent float64 `json:"outputCurrent"`
	Uptime        float64 `json:"uptime"`
	Managed       bool    `json:"managed"`
}

// ShowEnvironmentPower returns power supply status
func (eos *Eos) ShowEnvironmentPower() (*showEnvironmentPower, error) {
	shRsp := &showEnvironmentPower{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	err = handle.AddCommand(shRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}

	handle.Close()

	return shRsp, nil
}

// showEnvironmentCooling represents the response from "show system environment cooling"
type showEnvironmentCooling struct {
	SystemStatus     string        `json:"systemStatus"`
	FanTraySlots     []FanTraySlot `json:"fanTraySlots"`
	AirflowDirection string        `json:"airflowDirection"`
	CoolingMode      string        `json:"coolingMode"`
}

func (s *showEnvironmentCooling) GetCmd() string {
	return "show system environment cooling"
}

// FanTraySlot represents a fan tray slot from the cooling response
type FanTraySlot struct {
	Label  string `json:"label"`
	Status string `json:"status"`
	Fans   []Fan  `json:"fans"`
}

// Fan represents an individual fan within a fan tray
type Fan struct {
	Label           string `json:"label"`
	Status          string `json:"status"`
	Speed           int    `json:"speed"`
	ConfiguredSpeed int    `json:"configuredSpeed"`
}

// ShowEnvironmentCooling returns fan/cooling status
func (eos *Eos) ShowEnvironmentCooling() (*showEnvironmentCooling, error) {
	shRsp := &showEnvironmentCooling{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	err = handle.AddCommand(shRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}

	handle.Close()

	return shRsp, nil
}

// showInventory represents the response from "show inventory"
type showInventory struct {
	SystemInformation InventoryEntry            `json:"systemInformation"`
	PowerSupplySlots  map[string]InventoryEntry `json:"powerSupplySlots"`
	FanTraySlots      map[string]InventoryEntry `json:"fanTraySlots"`
	XcvrSlots         map[string]InventoryEntry `json:"xcvrSlots"`
	CardSlots         map[string]InventoryEntry `json:"cardSlots"`
}

func (s *showInventory) GetCmd() string {
	return "show inventory"
}

// InventoryEntry represents a hardware component in the inventory
type InventoryEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	MfgDate     string `json:"mfgDate"`
	HardwareRev string `json:"hardwareRev"`
	SerialNum   string `json:"serialNum"`
}

// ShowInventory returns the hardware inventory
func (eos *Eos) ShowInventory() (*showInventory, error) {
	shRsp := &showInventory{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	err = handle.AddCommand(shRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}

	handle.Close()

	return shRsp, nil
}

// MlagInterface represents a Port-Channel interface with an MLAG ID
type MlagInterface struct {
	Name   string
	MlagID string
}

// ParseMlagInterfaces extracts MLAG interface mappings from running config
// Returns a slice of MlagInterface structs containing Port-Channel name and MLAG ID
func ParseMlagInterfaces(runningConfig string) []MlagInterface {
	// First, find all Port-Channel interface blocks
	// Interface blocks in EOS config end at the next "!" or "interface" line
	portChannelRegex := regexp.MustCompile(`(?m)^interface (Port-Channel\d+)\n`)
	mlagIDRegex := regexp.MustCompile(`(?m)^\s+mlag (\d+)`)
	blockEndRegex := regexp.MustCompile(`(?m)^!`)

	// Find all Port-Channel interface start positions
	matches := portChannelRegex.FindAllStringSubmatchIndex(runningConfig, -1)

	result := []MlagInterface{}
	for i, match := range matches {
		// match[0]:match[1] is the full match
		// match[2]:match[3] is the Port-Channel name
		portChannelName := runningConfig[match[2]:match[3]]
		blockStart := match[1] // Start after the interface line

		// Find the end of this interface block (next "!" or "interface" at start of line)
		var blockEnd int
		if i+1 < len(matches) {
			// End at next interface
			blockEnd = matches[i+1][0]
		} else {
			blockEnd = len(runningConfig)
		}

		// Also check for "!" as block terminator
		if bangMatch := blockEndRegex.FindStringIndex(runningConfig[blockStart:blockEnd]); bangMatch != nil {
			blockEnd = blockStart + bangMatch[0]
		}

		// Extract the interface block content
		blockContent := runningConfig[blockStart:blockEnd]

		// Look for mlag ID within this block
		if mlagMatch := mlagIDRegex.FindStringSubmatch(blockContent); mlagMatch != nil {
			result = append(result, MlagInterface{
				Name:   portChannelName,
				MlagID: mlagMatch[1],
			})
		}
	}

	return result
}
