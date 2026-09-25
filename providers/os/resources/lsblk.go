// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// lsblkCommand appends TYPE and KNAME to the --fs columns. Both columns and
// the "+" form of --output predate --json (util-linux 2.27), so every lsblk
// that can answer in JSON accepts them.
const lsblkCommand = "lsblk --json --fs --output +TYPE,KNAME"

type mqlLsblkInternal struct {
	lock     sync.Mutex
	fetched  bool
	topo     *blockTopology
	fetchErr error
}

type mqlLsblkEntryInternal struct {
	node *blockNode
	// lsblk is the resource that built this entry, used to turn related
	// nodes into entries of the same runtime.
	lsblk *mqlLsblk
}

func (l *mqlLsblk) id() (string, error) {
	return "lsblk", nil
}

// topology runs lsblk once per runtime and returns the device graph every
// lsblk.entry, mount.point.blockDevice, and luks.volume.blockDevice lookup
// is answered from.
func (l *mqlLsblk) topology() (*blockTopology, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.fetched {
		return l.topo, l.fetchErr
	}

	topo, err := l.fetchTopology()
	if errors.Is(err, plugin.NotReady) {
		return nil, err
	}
	l.topo, l.fetchErr, l.fetched = topo, err, true
	return topo, err
}

func (l *mqlLsblk) fetchTopology() (*blockTopology, error) {
	conn, ok := l.MqlRuntime.Connection.(shared.Connection)
	if ok {
		if pf := conn.Asset().GetPlatform(); pf != nil && !pf.IsFamily("linux") {
			return nil, llx.NotApplicable(errors.New("lsblk block devices are only available on Linux"))
		}
		if !conn.Capabilities().Has(shared.Capability_RunCommand) {
			return nil, llx.NotApplicable(errors.New("lsblk block devices need a running system, and this connection cannot run commands"))
		}
	}

	o, err := CreateResource(l.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(lsblkCommand),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return nil, exit.Error
	}
	switch exit.Data {
	case 0:
	case 127:
		return nil, llx.NotFound(errors.New("could not retrieve lsblk: lsblk is not installed"))
	default:
		return nil, errors.New("could not retrieve lsblk: " + cmd.GetStderr().Data)
	}

	blockEntries, err := parseBlockEntries([]byte(cmd.GetStdout().Data))
	if err != nil {
		return nil, llx.MalformedData(errors.New("could not parse lsblk output: " + err.Error()))
	}
	return buildBlockTopology(blockEntries.Blockdevices), nil
}

func (l *mqlLsblk) list() ([]any, error) {
	topo, err := l.topology()
	if err != nil {
		return nil, err
	}

	return l.entries(topo.filesystemNodes())
}

// entry returns the lsblk.entry for a node of the topology. The resource
// cache keys it by kernel name, so a device reached through the list, a
// parent, a child, or a mount resolves to the same entry.
func (l *mqlLsblk) entry(node *blockNode) (*mqlLsblkEntry, error) {
	res, err := CreateResource(l.MqlRuntime, "lsblk.entry", map[string]*llx.RawData{
		"__id":        llx.StringData(node.key),
		"name":        llx.StringData(node.dev.Name),
		"fstype":      llx.StringData(node.dev.Fstype),
		"label":       llx.StringData(node.dev.Label),
		"uuid":        llx.StringData(node.dev.Uuid),
		"mountpoints": llx.ArrayData(node.dev.Mountpoints, types.String),
		"type":        llx.StringData(node.dev.Type),
	})
	if err != nil {
		return nil, err
	}
	entry := res.(*mqlLsblkEntry)
	entry.node = node
	entry.lsblk = l
	return entry, nil
}

// entries turns nodes into lsblk.entry resources, keeping their order.
func (l *mqlLsblk) entries(nodes []*blockNode) ([]any, error) {
	res := make([]any, 0, len(nodes))
	for _, node := range nodes {
		entry, err := l.entry(node)
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

// lookupBlockDevice resolves a device path, such as a mount source or a LUKS
// volume path, to its lsblk.entry through the one lsblk call of this runtime.
// It returns nil when no block device matches.
func lookupBlockDevice(runtime *plugin.Runtime, device string, mountPath string) (*mqlLsblkEntry, error) {
	o, err := CreateResource(runtime, "lsblk", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	lb := o.(*mqlLsblk)
	topo, err := lb.topology()
	if err != nil {
		return nil, err
	}
	node := topo.resolve(device, mountPath)
	if node == nil {
		return nil, nil
	}
	return lb.entry(node)
}

func (l *mqlLsblkEntry) id() (string, error) {
	return l.Name.Data + "-" + l.Fstype.Data, nil
}

func (l *mqlLsblkEntry) parents() ([]any, error) {
	if l.node == nil || l.lsblk == nil {
		return nil, errors.New("lsblk.entry: device topology is not available")
	}
	return l.lsblk.entries(l.node.parents)
}

func (l *mqlLsblkEntry) children() ([]any, error) {
	if l.node == nil || l.lsblk == nil {
		return nil, errors.New("lsblk.entry: device topology is not available")
	}
	return l.lsblk.entries(l.node.children)
}

func (l *mqlLsblkEntry) encrypted() (bool, error) {
	if l.node == nil {
		return false, errors.New("lsblk.entry: device topology is not available")
	}
	encrypted, known := l.node.encryption()
	if !known {
		l.Encrypted.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return encrypted, nil
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

// blockNode is one device of the lsblk tree. lsblk prints a device that is
// built on several others (a RAID array, an LVM volume spanning physical
// volumes) once under each of them; the topology folds those copies into one
// node with several parents.
type blockNode struct {
	key      string
	dev      blockdevice
	parents  []*blockNode
	children []*blockNode
}

type blockTopology struct {
	// nodes in the order lsblk first prints them
	nodes   []*blockNode
	byKname map[string]*blockNode
	byName  map[string]*blockNode
}

func buildBlockTopology(devices []blockdevice) *blockTopology {
	t := &blockTopology{
		byKname: map[string]*blockNode{},
		byName:  map[string]*blockNode{},
	}

	var walk func(devices []blockdevice, parent *blockNode)
	walk = func(devices []blockdevice, parent *blockNode) {
		for i := range devices {
			dev := devices[i]
			key := dev.Kname
			if key == "" {
				key = dev.Name
			}

			node, seen := t.byKname[key]
			if !seen {
				node = &blockNode{key: key, dev: dev}
				t.nodes = append(t.nodes, node)
				t.byKname[key] = node
				if _, ok := t.byName[dev.Name]; !ok {
					t.byName[dev.Name] = node
				}
			}
			if parent != nil && !slices.Contains(node.parents, parent) {
				node.parents = append(node.parents, parent)
				parent.children = append(parent.children, node)
			}
			// A device printed once more under a second parent repeats its
			// whole subtree; the first walk already recorded it.
			if !seen {
				walk(dev.Children, node)
			}
		}
	}
	walk(devices, nil)
	return t
}

// filesystemNodes returns every device that carries a filesystem of its own,
// once each, in the order lsblk first prints them. These are the devices the
// lsblk list reports.
func (t *blockTopology) filesystemNodes() []*blockNode {
	res := []*blockNode{}
	for _, node := range t.nodes {
		if node.dev.carriesFilesystem() {
			res = append(res, node)
		}
	}
	return res
}

// encryption reports whether the data on a node passes through a dm-crypt
// mapping on every path down to physical storage. known is false when a
// device on the way reports no type, since nothing can be said about it.
func (n *blockNode) encryption() (encrypted bool, known bool) {
	visiting := map[*blockNode]bool{}
	var walk func(n *blockNode) (bool, bool)
	walk = func(n *blockNode) (bool, bool) {
		if n.dev.Type == "" {
			return false, false
		}
		if n.dev.Type == "crypt" {
			return true, true
		}
		if len(n.parents) == 0 {
			return false, true
		}
		if visiting[n] {
			return false, false
		}
		visiting[n] = true
		defer delete(visiting, n)

		known := true
		for _, p := range n.parents {
			e, k := walk(p)
			if !k {
				known = false
				continue
			}
			if !e {
				// one unencrypted leg decides it, whatever the others say
				return false, true
			}
		}
		return known, known
	}
	return walk(n)
}

// resolve finds the node for a device path as a mount table or cryptsetup
// reports it. It understands the kernel name (/dev/sda1, /dev/dm-0), the
// device-mapper name (/dev/mapper/vg-root), the LVM path (/dev/vg/root), and
// the udev by-uuid and by-label links. When the path names no device lsblk
// knows, such as /dev/root, the device lsblk reports as mounted at mountPath
// is used, provided it is the only one. Sources that are not device paths
// (tmpfs, proc, overlay, server:/export) resolve to nil.
func (t *blockTopology) resolve(device string, mountPath string) *blockNode {
	if t == nil {
		return nil
	}
	rest, ok := strings.CutPrefix(device, "/dev/")
	if !ok || rest == "" {
		return nil
	}

	var node *blockNode
	switch {
	case strings.HasPrefix(rest, "mapper/"):
		node = t.byName[strings.TrimPrefix(rest, "mapper/")]
	case strings.HasPrefix(rest, "disk/by-uuid/"):
		node = t.unique(func(n *blockNode) bool {
			return n.dev.Uuid != "" && n.dev.Uuid == unescapeUdev(strings.TrimPrefix(rest, "disk/by-uuid/"))
		})
	case strings.HasPrefix(rest, "disk/by-label/"):
		node = t.unique(func(n *blockNode) bool {
			return n.dev.Label != "" && n.dev.Label == unescapeUdev(strings.TrimPrefix(rest, "disk/by-label/"))
		})
	case !strings.Contains(rest, "/"):
		if n, ok := t.byKname[rest]; ok {
			node = n
		} else {
			node = t.byName[rest]
		}
	default:
		// /dev/<vg>/<lv> is a link to the mapping /dev/mapper/<vg>-<lv>, with
		// every dash inside the names doubled.
		if vg, lv, ok := strings.Cut(rest, "/"); ok && !strings.Contains(lv, "/") {
			node = t.byName[dmEscape(vg)+"-"+dmEscape(lv)]
		}
	}
	if node != nil {
		return node
	}

	if mountPath == "" {
		return nil
	}
	return t.unique(func(n *blockNode) bool {
		return slices.Contains(n.dev.Mountpoints, any(mountPath))
	})
}

// unique returns the one node that matches, or nil when none or several do.
// Several filesystems can share a UUID or label (a btrfs volume spanning
// disks, a cloned disk), and picking one of them would be a guess.
func (t *blockTopology) unique(match func(n *blockNode) bool) *blockNode {
	var found *blockNode
	for _, n := range t.nodes {
		if !match(n) {
			continue
		}
		if found != nil {
			return nil
		}
		found = n
	}
	return found
}

func dmEscape(s string) string {
	return strings.ReplaceAll(s, "-", "--")
}

// unescapeUdev decodes the \xHH escapes udev writes into by-label and by-uuid
// link names, for example a space as \x20.
func unescapeUdev(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
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

type blockdevices struct {
	Blockdevices []blockdevice `json:"blockdevices,omitempty"`
}

type blockdevice struct {
	Name        string        `json:"name,omitempty"`
	Kname       string        `json:"kname,omitempty"`
	Type        string        `json:"type,omitempty"`
	Fstype      string        `json:"fstype,omitempty"`
	Label       string        `json:"label,omitempty"`
	Uuid        string        `json:"uuid,omitempty"`
	Mountpoints []any         `json:"mountpoints,omitempty"`
	Mountpoint  string        `json:"mountpoint,omitempty"`
	Children    []blockdevice `json:"children,omitempty"`
}
