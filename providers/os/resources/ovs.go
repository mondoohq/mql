// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/resources/ovs"
	"go.mondoo.com/mql/types"
)

// ovsTableDump reads the three tables that make up the switch topology in one
// call, separated by a marker line. Listing only the columns the resource maps
// keeps the output small on a node with hundreds of pod interfaces.
//
// The calls are chained with && so that any one of them failing fails the whole
// script. A partial read would otherwise leave a table empty and report ports
// that belong to no bridge.
const ovsTableDump = `ovs-vsctl --format=json --columns=_uuid,name,datapath_type,fail_mode,protocols,stp_enable,rstp_enable,external_ids,other_config,ports list Bridge &&
echo '===OVSTABLE===' &&
ovs-vsctl --format=json --columns=_uuid,name,vlan_mode,tag,trunks,external_ids,other_config,interfaces list Port &&
echo '===OVSTABLE===' &&
ovs-vsctl --format=json --columns=_uuid,name,type,admin_state,link_state,mac_in_use,mtu,ofport,error,external_ids,options list Interface`

const ovsVersionCmd = `ovs-vsctl --version`

// ovsTableSeparator splits the three documents of the table dump.
const ovsTableSeparator = "===OVSTABLE==="

type mqlOvsInternal struct {
	lock               sync.Mutex
	loaded             bool
	loadErr            error
	bridgeResources    []any
	portResources      []any
	interfaceResources []any
}

type mqlOvsBridgeInternal struct {
	portResources []any
}

type mqlOvsPortInternal struct {
	bridgeResource     *mqlOvsBridge
	interfaceResources []any
}

type mqlOvsInterfaceInternal struct {
	portResource *mqlOvsPort
}

func (o *mqlOvs) id() (string, error) {
	return "ovs", nil
}

func (o *mqlOvs) version() (string, error) {
	stdout, ok, err := runShellCmd(o.MqlRuntime, ovsVersionCmd)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	return ovs.ParseVersion(stdout), nil
}

// runOvsVsctl runs an ovs-vsctl command line and returns its stdout. A
// non-zero exit comes back as failed, carrying the reason ovs-vsctl gave; err
// is for a command that could not be run at all.
func runOvsVsctl(runtime *plugin.Runtime, cmdline string) (stdout string, failed error, err error) {
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData(cmdline),
	})
	if err != nil {
		return "", nil, err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return "", nil, exit.Error
	}
	if exit.Data != 0 {
		return "", ovs.VsctlFailure(exit.Data, cmd.GetStderr().Data), nil
	}
	return cmd.GetStdout().Data, nil, nil
}

func (o *mqlOvs) load() error {
	if o.loaded {
		return o.loadErr
	}
	o.lock.Lock()
	defer o.lock.Unlock()
	if o.loaded {
		return o.loadErr
	}
	o.loadErr = o.doLoad()
	o.loaded = true
	return o.loadErr
}

func (o *mqlOvs) doLoad() error {
	o.bridgeResources = []any{}
	o.portResources = []any{}
	o.interfaceResources = []any{}

	// A host without ovs-vsctl has no switch to report. `--version` does not
	// touch the database, so it runs for any user wherever the tool exists.
	_, installed, err := runShellCmd(o.MqlRuntime, ovsVersionCmd)
	if err != nil {
		return err
	}
	if !installed {
		return nil
	}

	stdout, failed, err := runOvsVsctl(o.MqlRuntime, ovsTableDump)
	if err != nil {
		return err
	}
	if failed != nil {
		if !plugin.StructuredErrors() {
			// v13 reported a database it could not read as a switch without
			// bridges; keep that until structured errors are the default
			return nil
		}
		return failed
	}

	// The script only exits 0 when all three calls ran, so a different number of
	// sections means the output shape changed. Report that rather than an empty
	// switch, which reads as a host with no bridges.
	documents := strings.Split(stdout, ovsTableSeparator)
	if len(documents) != 3 {
		return fmt.Errorf("ovs-vsctl returned %d table sections, expected 3", len(documents))
	}

	topology, err := ovs.ParseTopology(documents[0], documents[1], documents[2])
	if err != nil {
		return err
	}

	bridgesByName := make(map[string]*mqlOvsBridge, len(topology.Bridges))
	for _, bridge := range topology.Bridges {
		resource, err := CreateResource(o.MqlRuntime, "ovs.bridge", map[string]*llx.RawData{
			"__id":         llx.StringData(bridge.UUID),
			"name":         llx.StringData(bridge.Name),
			"uuid":         llx.StringData(bridge.UUID),
			"datapathType": llx.StringData(bridge.DatapathType),
			"failMode":     llx.StringData(bridge.FailMode),
			"protocols":    llx.ArrayData(convert.SliceAnyToInterface(bridge.Protocols), types.String),
			"stpEnabled":   llx.BoolData(bridge.STPEnabled),
			"rstpEnabled":  llx.BoolData(bridge.RSTPEnabled),
			"externalIds":  llx.MapData(convert.MapToInterfaceMap(bridge.ExternalIDs), types.String),
			"otherConfig":  llx.MapData(convert.MapToInterfaceMap(bridge.OtherConfig), types.String),
		})
		if err != nil {
			return err
		}
		mqlBridge := resource.(*mqlOvsBridge)
		mqlBridge.portResources = []any{}
		bridgesByName[bridge.Name] = mqlBridge
		o.bridgeResources = append(o.bridgeResources, mqlBridge)
	}

	portsByName := make(map[string]*mqlOvsPort, len(topology.Ports))
	for _, port := range topology.Ports {
		resource, err := CreateResource(o.MqlRuntime, "ovs.port", map[string]*llx.RawData{
			"__id":        llx.StringData(port.UUID),
			"name":        llx.StringData(port.Name),
			"uuid":        llx.StringData(port.UUID),
			"bridgeName":  llx.StringData(port.BridgeName),
			"vlanMode":    llx.StringData(port.VlanMode),
			"vlanTag":     llx.IntData(port.Tag),
			"tagged":      llx.BoolData(port.Tagged),
			"trunks":      llx.ArrayData(convert.SliceAnyToInterface(port.Trunks), types.Int),
			"externalIds": llx.MapData(convert.MapToInterfaceMap(port.ExternalIDs), types.String),
			"otherConfig": llx.MapData(convert.MapToInterfaceMap(port.OtherConfig), types.String),
		})
		if err != nil {
			return err
		}
		mqlPort := resource.(*mqlOvsPort)
		mqlPort.interfaceResources = []any{}
		mqlPort.bridgeResource = bridgesByName[port.BridgeName]
		portsByName[port.Name] = mqlPort
		o.portResources = append(o.portResources, mqlPort)

		if mqlPort.bridgeResource != nil {
			mqlPort.bridgeResource.portResources = append(mqlPort.bridgeResource.portResources, mqlPort)
		}
	}

	for _, iface := range topology.Interfaces {
		resource, err := CreateResource(o.MqlRuntime, "ovs.interface", map[string]*llx.RawData{
			"__id":        llx.StringData(iface.UUID),
			"name":        llx.StringData(iface.Name),
			"uuid":        llx.StringData(iface.UUID),
			"portName":    llx.StringData(iface.PortName),
			"bridgeName":  llx.StringData(iface.BridgeName),
			"type":        llx.StringData(iface.Type),
			"adminState":  llx.StringData(iface.AdminState),
			"linkState":   llx.StringData(iface.LinkState),
			"macAddress":  llx.StringData(iface.MACInUse),
			"mtu":         llx.IntData(iface.MTU),
			"ofport":      llx.IntData(iface.OFPort),
			"error":       llx.StringData(iface.Error),
			"externalIds": llx.MapData(convert.MapToInterfaceMap(iface.ExternalIDs), types.String),
			"options":     llx.MapData(convert.MapToInterfaceMap(iface.Options), types.String),
		})
		if err != nil {
			return err
		}
		mqlInterface := resource.(*mqlOvsInterface)
		mqlInterface.portResource = portsByName[iface.PortName]
		o.interfaceResources = append(o.interfaceResources, mqlInterface)

		if mqlInterface.portResource != nil {
			mqlInterface.portResource.interfaceResources = append(mqlInterface.portResource.interfaceResources, mqlInterface)
		}
	}

	return nil
}

func (o *mqlOvs) bridges() ([]any, error) {
	if err := o.load(); err != nil {
		return nil, err
	}
	return o.bridgeResources, nil
}

func (o *mqlOvs) ports() ([]any, error) {
	if err := o.load(); err != nil {
		return nil, err
	}
	return o.portResources, nil
}

func (o *mqlOvs) interfaces() ([]any, error) {
	if err := o.load(); err != nil {
		return nil, err
	}
	return o.interfaceResources, nil
}

func (b *mqlOvsBridge) ports() ([]any, error) {
	return b.portResources, nil
}

func (p *mqlOvsPort) bridge() (*mqlOvsBridge, error) {
	// A port the database keeps but no bridge references has no bridge to
	// resolve. That is a real state, not an error.
	if p.bridgeResource == nil {
		p.Bridge.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return p.bridgeResource, nil
}

func (p *mqlOvsPort) interfaces() ([]any, error) {
	return p.interfaceResources, nil
}

func (i *mqlOvsInterface) port() (*mqlOvsPort, error) {
	if i.portResource == nil {
		i.Port.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return i.portResource, nil
}
