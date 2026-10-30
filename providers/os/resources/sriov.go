// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/sriov"
)

// sriovSysfsWalk dumps the SR-IOV inventory in a single shell call.
//
// Every SR-IOV capable interface has a sriov_totalvfs file, including one with
// no virtual functions enabled, so a capable but unused interface is reported
// too. Each device is separated by a "===PF===<interface>" line and each
// virtual function by a "===VF===<index>" line, followed by key=value pairs.
// The readlink calls resolve the PCI address and the bound driver, which sysfs
// only exposes as symlinks.
const sriovSysfsWalk = `for total in /sys/class/net/*/device/sriov_totalvfs; do
  [ -r "$total" ] || continue
  dev="${total%/sriov_totalvfs}"
  net="${dev%/device}"
  echo "===PF===${net##*/}"
  echo "pciAddress=$(readlink -f "$dev" 2>/dev/null | sed 's|.*/||')"
  if [ -e "$dev/driver" ]; then
    echo "driver=$(readlink -f "$dev/driver" 2>/dev/null | sed 's|.*/||')"
  fi
  for n in vendor device numa_node sriov_numvfs sriov_totalvfs; do
    if [ -r "$dev/$n" ]; then printf '%s=' "$n"; cat "$dev/$n" 2>/dev/null; fi
  done
  for n in address mtu operstate; do
    if [ -r "$net/$n" ]; then printf 'net.%s=' "$n"; cat "$net/$n" 2>/dev/null; fi
  done
  for vf in "$dev"/virtfn*; do
    [ -e "$vf" ] || continue
    echo "===VF===${vf##*/virtfn}"
    echo "pciAddress=$(readlink -f "$vf" 2>/dev/null | sed 's|.*/||')"
    if [ -e "$vf/driver" ]; then
      echo "driver=$(readlink -f "$vf/driver" 2>/dev/null | sed 's|.*/||')"
    fi
    for n in vendor device numa_node; do
      if [ -r "$vf/$n" ]; then printf '%s=' "$n"; cat "$vf/$n" 2>/dev/null; fi
    done
    for n in "$vf"/net/*; do
      [ -d "$n" ] && echo "interface=${n##*/}"
    done
  done
done`

// sriovLinkShow reports the per-function configuration the physical function
// enforces. Sysfs does not expose it, so it takes a second call.
const sriovLinkShow = `ip -details -json link show`

type mqlSriovInternal struct {
	lock    sync.Mutex
	loaded  bool
	loadErr error
	pfs     []*mqlSriovPhysicalFunction
	allVFs  []any
}

type mqlSriovPhysicalFunctionInternal struct {
	vfResources []any
}

type mqlSriovVirtualFunctionInternal struct {
	parent *mqlSriovPhysicalFunction
}

func (s *mqlSriov) id() (string, error) {
	return "sriov", nil
}

func (s *mqlSriov) load() error {
	if s.loaded {
		return s.loadErr
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.loaded {
		return s.loadErr
	}
	s.loadErr = s.doLoad()
	s.loaded = true
	return s.loadErr
}

func (s *mqlSriov) doLoad() error {
	s.pfs = []*mqlSriovPhysicalFunction{}
	s.allVFs = []any{}

	stdout, ok, err := runShellCmd(s.MqlRuntime, sriovSysfsWalk)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	inventory := sriov.ParseSysfs(stdout)
	if len(inventory) == 0 {
		return nil
	}

	// A host without iproute2, or one where the driver exposes no per-function
	// settings, still reports the inventory, and linkConfigured stays false for
	// those functions. Output the reader cannot parse is a different case and
	// fails the query, because dropping it would report spoofChecking as off on
	// functions that in fact enforce it.
	linkStdout, ok, err := runShellCmd(s.MqlRuntime, sriovLinkShow)
	if err != nil {
		return err
	}
	if ok {
		linkConfig, err := sriov.ParseLinkConfig(linkStdout)
		if err != nil {
			return err
		}
		inventory = sriov.Merge(inventory, linkConfig)
	}

	for _, pf := range inventory {
		mqlPF, err := s.createPhysicalFunction(pf)
		if err != nil {
			return err
		}
		s.pfs = append(s.pfs, mqlPF)
		s.allVFs = append(s.allVFs, mqlPF.vfResources...)
	}
	return nil
}

func (s *mqlSriov) createPhysicalFunction(pf sriov.PhysicalFunction) (*mqlSriovPhysicalFunction, error) {
	resource, err := CreateResource(s.MqlRuntime, "sriov.physicalFunction", map[string]*llx.RawData{
		"__id":             llx.StringData(pf.PCIAddress),
		"interface":        llx.StringData(pf.Interface),
		"pciAddress":       llx.StringData(pf.PCIAddress),
		"driver":           llx.StringData(pf.Driver),
		"vendorId":         llx.StringData(pf.VendorID),
		"deviceId":         llx.StringData(pf.DeviceID),
		"numVfs":           llx.IntData(pf.NumVFs),
		"totalVfs":         llx.IntData(pf.TotalVFs),
		"macAddress":       llx.StringData(pf.MACAddress),
		"mtu":              llx.IntData(pf.MTU),
		"operationalState": llx.StringData(pf.OperationalState),
		"numaNode":         llx.IntData(pf.NUMANode),
	})
	if err != nil {
		return nil, err
	}
	mqlPF := resource.(*mqlSriovPhysicalFunction)

	mqlPF.vfResources = make([]any, 0, len(pf.VirtualFunctions))
	for _, vf := range pf.VirtualFunctions {
		mqlVF, err := createVirtualFunction(s.MqlRuntime, mqlPF, vf)
		if err != nil {
			return nil, err
		}
		mqlPF.vfResources = append(mqlPF.vfResources, mqlVF)
	}
	return mqlPF, nil
}

func createVirtualFunction(runtime *plugin.Runtime, parent *mqlSriovPhysicalFunction, vf sriov.VirtualFunction) (*mqlSriovVirtualFunction, error) {
	resource, err := CreateResource(runtime, "sriov.virtualFunction", map[string]*llx.RawData{
		"__id":                  llx.StringData(vf.PCIAddress),
		"pciAddress":            llx.StringData(vf.PCIAddress),
		"index":                 llx.IntData(vf.Index),
		"driver":                llx.StringData(vf.Driver),
		"interface":             llx.StringData(vf.Interface),
		"vendorId":              llx.StringData(vf.VendorID),
		"deviceId":              llx.StringData(vf.DeviceID),
		"numaNode":              llx.IntData(vf.NUMANode),
		"usesPassthroughDriver": llx.BoolData(vf.UsesPassthroughDriver()),
		"linkConfigured":        llx.BoolData(vf.LinkConfigured),
		"macAddress":            llx.StringData(vf.MACAddress),
		"vlanId":                llx.IntData(vf.VlanID),
		"qos":                   llx.IntData(vf.QoS),
		"spoofChecking":         llx.BoolData(vf.SpoofChecking),
		"trusted":               llx.BoolData(vf.Trusted),
		"linkState":             llx.StringData(vf.LinkState),
		"minTxRate":             llx.IntData(vf.MinTxRate),
		"maxTxRate":             llx.IntData(vf.MaxTxRate),
	})
	if err != nil {
		return nil, err
	}
	mqlVF := resource.(*mqlSriovVirtualFunction)
	mqlVF.parent = parent
	return mqlVF, nil
}

func (s *mqlSriov) physicalFunctions() ([]any, error) {
	if err := s.load(); err != nil {
		return nil, err
	}
	out := make([]any, 0, len(s.pfs))
	for _, pf := range s.pfs {
		out = append(out, pf)
	}
	return out, nil
}

func (s *mqlSriov) virtualFunctions() ([]any, error) {
	if err := s.load(); err != nil {
		return nil, err
	}
	return s.allVFs, nil
}

func (p *mqlSriovPhysicalFunction) virtualFunctions() ([]any, error) {
	return p.vfResources, nil
}

func (v *mqlSriovVirtualFunction) physicalFunction() (*mqlSriovPhysicalFunction, error) {
	// A virtual function is always created from its physical function, so the
	// parent is only missing on a resource built from a recording.
	if v.parent == nil {
		v.PhysicalFunction.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return v.parent, nil
}
