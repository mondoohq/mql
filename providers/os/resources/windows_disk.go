// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
)

// windowsDisksApplicable reports why windows.disks cannot be answered on this
// connection, or nil when it can. Disks are read by running PowerShell, so a
// target that is not Windows, or a connection that cannot run commands (a
// mounted disk image, a container filesystem), is outside what the question
// applies to: ADR 046 not applicable, never an empty list.
func windowsDisksApplicable(runtime *plugin.Runtime) error {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return llx.NotApplicable(errors.New("windows.disks is not supported on this connection type"))
	}
	if asset := conn.Asset(); asset == nil || asset.Platform == nil || !asset.Platform.IsFamily("windows") {
		return llx.NotApplicable(errors.New("windows.disks is only supported on Windows"))
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return llx.NotApplicable(errors.New("windows.disks needs a connection that can run commands"))
	}
	return nil
}

func (w *mqlWindows) disks() ([]any, error) {
	if err := windowsDisksApplicable(w.MqlRuntime); err != nil {
		return nil, err
	}

	stdout, err := runWindowsPowerShell(w.MqlRuntime, windows.PSGetDisks, "retrieve disks")
	if err != nil {
		return nil, err
	}
	disks, err := windows.ParseDisks(stdout)
	if err != nil {
		// No output at all means the script never ran, which says nothing
		// about the shape of the target's answer, so it stays unclassified.
		if errors.Is(err, windows.ErrNoDiskOutput) {
			return nil, err
		}
		return nil, llx.MalformedData(err)
	}

	res := make([]any, 0, len(disks))
	for i, d := range disks {
		r, err := CreateResource(w.MqlRuntime, "windows.disk", diskResourceArgs(i, d))
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// diskResourceID builds the internal cache key. The disk number is unique on a
// running system, which UniqueId is not guaranteed to be (cloned virtual disks
// and some USB bridges repeat it), so the number carries uniqueness and the
// UniqueId keeps a renumbered disk from reusing another disk's entry. A record
// without a number falls back to its position in the listing.
func diskResourceID(i int, d windows.Disk) string {
	num := "idx" + strconv.Itoa(i)
	if d.Number != nil {
		num = strconv.FormatInt(*d.Number, 10)
	}
	uid := ""
	if d.UniqueId != nil {
		uid = *d.UniqueId
	}
	return "windows.disk/" + num + "/" + uid
}

func diskResourceArgs(i int, d windows.Disk) map[string]*llx.RawData {
	var opStatus *llx.RawData
	if names := d.OperationalStatusNames(); names != nil {
		list := make([]any, len(names))
		for j, n := range names {
			list[j] = n
		}
		opStatus = llx.ArrayData(list, types.String)
	} else {
		opStatus = llx.NilData
	}

	return map[string]*llx.RawData{
		"__id":              llx.StringData(diskResourceID(i, d)),
		"number":            llx.IntDataPtr(d.Number),
		"friendlyName":      llx.StringDataPtr(d.FriendlyName),
		"serialNumber":      llx.StringDataPtr(d.TrimmedSerialNumber()),
		"uniqueId":          llx.StringDataPtr(d.UniqueId),
		"size":              llx.IntDataPtr(d.Size),
		"busType":           llx.StringDataPtr(d.BusTypeName()),
		"partitionStyle":    llx.StringDataPtr(d.PartitionStyleName()),
		"isBoot":            llx.BoolDataPtr(d.IsBoot),
		"isSystem":          llx.BoolDataPtr(d.IsSystem),
		"isOffline":         llx.BoolDataPtr(d.IsOffline),
		"isReadOnly":        llx.BoolDataPtr(d.IsReadOnly),
		"operationalStatus": opStatus,
		"healthStatus":      llx.StringDataPtr(d.HealthStatusName()),
	}
}
