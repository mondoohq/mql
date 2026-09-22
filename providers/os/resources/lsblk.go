// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"slices"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func (l *mqlLsblk) id() (string, error) {
	return "lsblk", nil
}

func (l *mqlLsblk) list() ([]any, error) {
	o, err := CreateResource(l.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("lsblk --json --fs"),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	stdout, err := commandOutput(cmd, "lsblk")
	if err != nil {
		return nil, err
	}

	blockEntries, err := parseBlockEntries([]byte(stdout))
	if err != nil {
		return nil, err
	}

	mqlBlockEntries := []any{}
	for _, entry := range filesystemDevices(blockEntries.Blockdevices) {
		mqlLsblkEntry, err := CreateResource(l.MqlRuntime, "lsblk.entry", map[string]*llx.RawData{
			"name":        llx.StringData(entry.Name),
			"fstype":      llx.StringData(entry.Fstype),
			"label":       llx.StringData(entry.Label),
			"uuid":        llx.StringData(entry.Uuid),
			"mountpoints": llx.ArrayData(entry.Mountpoints, types.String),
		})
		if err != nil {
			return nil, err
		}
		mqlBlockEntries = append(mqlBlockEntries, mqlLsblkEntry)
	}
	return mqlBlockEntries, nil
}

// carriesFilesystem reports whether a block device holds a filesystem of its
// own rather than only acting as a container for the devices stacked on top of
// it. A disk that merely carries a partition table reports no fstype, no
// mountpoint and a list of children, and is skipped in favor of its partitions.
// A disk whose filesystem sits directly on it has no children at all, and a
// stacking member (LVM2_member, crypto_LUKS, linux_raid_member) reports its own
// fstype next to its children.
func (d blockdevice) carriesFilesystem() bool {
	return len(d.Children) == 0 || d.Fstype != "" || len(d.Mountpoints) > 0
}

// filesystemDevices walks the block device tree depth-first and returns every
// device that carries a filesystem of its own. Walking the whole tree keeps
// devices that sit more than one level deep (disk -> partition -> crypt -> lvm)
// reachable.
func filesystemDevices(devices []blockdevice) []blockdevice {
	res := []blockdevice{}
	var walk func(devices []blockdevice)
	walk = func(devices []blockdevice) {
		for i := range devices {
			if devices[i].carriesFilesystem() {
				res = append(res, devices[i])
			}
			walk(devices[i].Children)
		}
	}
	walk(devices)
	return res
}

func parseBlockEntries(data []byte) (blockdevices, error) {
	blockEntries := blockdevices{}
	if err := json.Unmarshal(data, &blockEntries); err != nil {
		return blockEntries, err
	}

	normalizeMountpoints(blockEntries.Blockdevices)

	return blockEntries, nil
}

// normalizeMountpoints reconciles the mountpoint shapes across lsblk versions
// for every device in the tree.
func normalizeMountpoints(devices []blockdevice) {
	for i := range devices {
		entry := devices[i]
		// Some versions of the lsblk return [null] instead of empty array
		entry.Mountpoints = slices.Collect(func(yield func(any) bool) {
			for _, m := range entry.Mountpoints {
				if m != nil && !yield(m) {
					return
				}
			}
		})
		// Some versions of the lsblk return the mountpoint instead of the mountpoints array
		if len(entry.Mountpoints) == 0 && entry.Mountpoint != "" {
			entry.Mountpoints = append(entry.Mountpoints, entry.Mountpoint)
		}
		devices[i] = entry

		normalizeMountpoints(devices[i].Children)
	}
}

func (l *mqlLsblkEntry) id() (string, error) {
	return l.Name.Data + "-" + l.Fstype.Data, nil
}

type blockdevices struct {
	Blockdevices []blockdevice `json:"blockdevices,omitempty"`
}

type blockdevice struct {
	Name        string        `json:"name,omitempty"`
	Fstype      string        `json:"fstype,omitempty"`
	Label       string        `json:"label,omitempty"`
	Uuid        string        `json:"uuid,omitempty"`
	Mountpoints []any         `json:"mountpoints,omitempty"`
	Mountpoint  string        `json:"mountpoint,omitempty"`
	Children    []blockdevice `json:"children,omitempty"`
}
