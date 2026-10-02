// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

const (
	cgroupRoot = "/sys/fs/cgroup"

	// cgroupControllersFile marks a directory as a cgroup v2 node. Its
	// presence at the mount point also identifies the unified hierarchy.
	cgroupControllersFile = "cgroup.controllers"

	// cgroupV1MemoryDir is the per-controller hierarchy that only exists
	// under cgroup v1.
	cgroupV1MemoryDir = "memory"

	// procCgroupsPath lists the controllers the kernel knows and the v1
	// hierarchy each one is attached to.
	procCgroupsPath = "/proc/cgroups"

	// cgroupWalkMaxDepth bounds how far below the cgroup root the walk
	// descends. Busy hosts (e.g. K8s nodes with thousands of pod
	// cgroups) would otherwise cost one directory listing per pod
	// container; the typical layout is `slice/sub-slice/unit`, which
	// fits comfortably within three levels below the root.
	cgroupWalkMaxDepth = 3
)

// cgroupAttrFiles are the v2 attribute files read for every cgroup, in
// addition to cgroupControllersFile. Files that are absent (the
// controller is not enabled on that cgroup) are skipped, and the
// builder falls back to the documented default for the field.
var cgroupAttrFiles = []string{
	"cgroup.type",
	"memory.max",
	"memory.current",
	"memory.high",
	"memory.swap.max",
	"cpu.max",
	"cpu.weight",
	"pids.max",
	"pids.current",
	"cgroup.procs",
}

type mqlCgroupsInternal struct {
	lock     sync.Mutex
	probed   atomic.Bool
	detected *cgroupDetection
	probeErr error
}

type mqlCgroupInternal struct {
	childResources []any
}

type cgroupDetection struct {
	version     int64
	controllers []string
	// controllersErr is why controllers could not be read, when they could
	// not; it fails only that field, not the version.
	controllersErr error
	root           *mqlCgroup
	flat           []*mqlCgroup
}

func (c *mqlCgroups) id() (string, error) {
	return "cgroups", nil
}

func (c *mqlCgroups) probe() (*cgroupDetection, error) {
	if c.probed.Load() {
		return c.detected, c.probeErr
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.probed.Load() {
		return c.detected, c.probeErr
	}
	c.detected, c.probeErr = c.doProbe()
	c.probed.Store(true)
	return c.detected, c.probeErr
}

func (c *mqlCgroups) doProbe() (*cgroupDetection, error) {
	det := &cgroupDetection{controllers: []string{}, flat: []*mqlCgroup{}}

	conn, ok := c.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return det, fmt.Errorf("cgroups requires a filesystem connection, got %T", c.MqlRuntime.Connection)
	}
	fs := conn.FileSystem()

	det.version = detectCgroupVersion(fs)
	if det.version == 1 {
		// v1 has no cgroup.controllers file; the kernel lists its
		// controllers in /proc/cgroups instead. The per-controller
		// hierarchies themselves are not modeled, so root and list stay
		// null rather than reading as a host with no cgroups.
		content, err := afero.ReadFile(fs, procCgroupsPath)
		if err != nil {
			det.controllersErr = fmt.Errorf("cannot read the cgroup v1 controllers from %s: %w", procCgroupsPath, err)
			return det, nil
		}
		det.controllers = parseProcCgroups(string(content))
		return det, nil
	}
	if det.version != 2 {
		// version 0 means there is no cgroup mount to walk
		return det, nil
	}

	parsed, err := walkCgroupFS(fs)
	if err != nil {
		return det, err
	}

	byPath := make(map[string]*mqlCgroup, len(parsed))
	for _, p := range parsed {
		relPath := normalizeCgroupPath(p.rawPath)
		cg, err := buildCgroupResource(c.MqlRuntime, relPath, p)
		if err != nil {
			return det, err
		}
		byPath[relPath] = cg
		det.flat = append(det.flat, cg)
	}

	// Link parents -> children. Root's parent is itself; skip self-links.
	for cgPath, cg := range byPath {
		parent := parentCgroupPath(cgPath)
		if parent == cgPath {
			continue
		}
		if p, ok := byPath[parent]; ok {
			p.childResources = append(p.childResources, cg)
		}
	}

	det.root = byPath["/"]
	if det.root != nil {
		// Copy out controllers as []string so we don't share the backing
		// array with the resource's RawData (mutating one would mutate
		// the other).
		raw := det.root.Controllers.Data
		det.controllers = make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				det.controllers = append(det.controllers, s)
			}
		}
	}
	// If the v2 probe matched but the root has no controllers, the
	// unified hierarchy is effectively unusable from a query
	// standpoint. Report version=0 so callers don't see a confusing
	// "v2 with no controllers" state.
	if det.root != nil && len(det.controllers) == 0 {
		det.version = 0
	}
	return det, nil
}

// parseProcCgroups returns the controllers /proc/cgroups lists as enabled
// and attached to a v1 hierarchy, in the kernel's order. A controller with
// hierarchy 0 is not mounted on any v1 hierarchy (on a hybrid host it may
// sit on the unified one), so it is not available to v1 cgroups.
//
//	#subsys_name	hierarchy	num_cgroups	enabled
//	cpuset	3	1	1
func parseProcCgroups(content string) []string {
	controllers := []string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[1] == "0" || fields[3] != "1" {
			continue
		}
		controllers = append(controllers, fields[0])
	}
	return controllers
}

// detectCgroupVersion reports what cgroup mode the target is running in
// by looking for the v2 unified-hierarchy marker file and falling back
// to v1's per-controller directories. It returns 2, 1, or 0.
func detectCgroupVersion(fs afero.Fs) int64 {
	// Open rather than Stat: an unreadable marker file is not a usable
	// unified hierarchy, and the v1 fallback may still apply.
	if f, err := fs.Open(path.Join(cgroupRoot, cgroupControllersFile)); err == nil {
		f.Close()
		return 2
	}
	if fi, err := fs.Stat(path.Join(cgroupRoot, cgroupV1MemoryDir)); err == nil && fi.IsDir() {
		return 1
	}
	return 0
}

// walkCgroupFS collects every cgroup v2 node under the cgroup root,
// depth-first and in directory order, starting with the root itself.
// A root that cannot be read is an error rather than an empty result:
// reporting "v2 with no controllers" would assert something false about
// the target.
func walkCgroupFS(fs afero.Fs) ([]parsedCgroup, error) {
	root, ok := readCgroupDir(fs, cgroupRoot)
	if !ok {
		return nil, fmt.Errorf("cannot read the cgroup v2 root at %s", cgroupRoot)
	}
	out := []parsedCgroup{root}

	entries, err := afero.ReadDir(fs, cgroupRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot list the cgroup v2 root at %s: %w", cgroupRoot, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			walkCgroupDir(fs, path.Join(cgroupRoot, entry.Name()), 1, &out)
		}
	}
	return out, nil
}

// walkCgroupDir appends dir (when it is a cgroup) and recurses into its
// subdirectories up to cgroupWalkMaxDepth. Unreadable subtrees are
// skipped: a single delegated cgroup the scanner cannot enter must not
// discard the rest of the tree.
func walkCgroupDir(fs afero.Fs, dir string, depth int, out *[]parsedCgroup) {
	cg, ok := readCgroupDir(fs, dir)
	if ok {
		*out = append(*out, cg)
	}
	if depth >= cgroupWalkMaxDepth {
		return
	}
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			walkCgroupDir(fs, path.Join(dir, entry.Name()), depth+1, out)
		}
	}
}

// readCgroupDir reads one cgroup directory's attribute files. A
// directory without a readable cgroup.controllers is not a cgroup node
// and reports false.
func readCgroupDir(fs afero.Fs, dir string) (parsedCgroup, bool) {
	controllers, err := afero.ReadFile(fs, path.Join(dir, cgroupControllersFile))
	if err != nil {
		return parsedCgroup{}, false
	}

	cg := parsedCgroup{
		rawPath: dir,
		attrs:   map[string]string{cgroupControllersFile: flattenCgroupAttr(controllers)},
	}
	for _, name := range cgroupAttrFiles {
		data, err := afero.ReadFile(fs, path.Join(dir, name))
		if err != nil {
			continue
		}
		cg.attrs[name] = flattenCgroupAttr(data)
	}
	return cg, true
}

// flattenCgroupAttr collapses a cgroup attribute file into the
// single-line form the resource builder expects. cgroup.procs is one
// PID per line and callers split it on whitespace, so newlines become
// spaces and the surrounding whitespace is trimmed.
func flattenCgroupAttr(data []byte) string {
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\n", " "))
}

func (c *mqlCgroups) version() (int64, error) {
	d, err := c.probe()
	if err != nil {
		return 0, err
	}
	return d.version, nil
}

func (c *mqlCgroups) controllers() ([]any, error) {
	d, err := c.probe()
	if err != nil {
		return nil, err
	}
	if d.controllersErr != nil {
		return nil, classifyFsError(d.controllersErr)
	}
	out := make([]any, len(d.controllers))
	for i, s := range d.controllers {
		out[i] = s
	}
	return out, nil
}

func (c *mqlCgroups) root() (*mqlCgroup, error) {
	d, err := c.probe()
	if err != nil {
		return nil, err
	}
	if d.root == nil {
		c.Root.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return d.root, nil
}

func (c *mqlCgroups) list() ([]any, error) {
	d, err := c.probe()
	if err != nil {
		return nil, err
	}
	if d.version == 1 {
		// the v1 hierarchies are not walked, so the list is unknown, not empty
		c.List.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	out := make([]any, len(d.flat))
	for i, cg := range d.flat {
		out[i] = cg
	}
	return out, nil
}

func (cg *mqlCgroup) id() (string, error) {
	return "cgroup:" + cg.Path.Data, nil
}

func (cg *mqlCgroup) children() ([]any, error) {
	if cg.childResources == nil {
		return []any{}, nil
	}
	return cg.childResources, nil
}

// parsedCgroup is the raw key/value capture from one cgroup directory.
// Conversion to numeric fields happens in buildCgroupResource so the
// walk stays a flat string-to-string map.
type parsedCgroup struct {
	rawPath string
	attrs   map[string]string
}

func buildCgroupResource(runtime *plugin.Runtime, relPath string, p parsedCgroup) (*mqlCgroup, error) {
	controllers := stringsAsAny(strings.Fields(p.attrs["cgroup.controllers"]))
	pids := pidsAsAny(strings.Fields(p.attrs["cgroup.procs"]))

	cpuQuota, cpuPeriod := parseCpuMax(p.attrs["cpu.max"])

	resource, err := CreateResource(runtime, "cgroup", map[string]*llx.RawData{
		"path":             llx.StringData(relPath),
		"type":             llx.StringData(strings.TrimSpace(p.attrs["cgroup.type"])),
		"unitType":         llx.StringData(cgroupUnitTypeFromPath(relPath)),
		"controllers":      llx.ArrayData(controllers, types.String),
		"memoryMax":        llx.IntData(parseCgroupMax(p.attrs["memory.max"])),
		"memoryHigh":       llx.IntData(parseCgroupMax(p.attrs["memory.high"])),
		"memoryCurrent":    llx.IntData(parseCgroupInt(p.attrs["memory.current"], 0)),
		"memorySwapMax":    llx.IntData(parseCgroupMax(p.attrs["memory.swap.max"])),
		"cpuMaxQuotaUSec":  llx.IntData(cpuQuota),
		"cpuMaxPeriodUSec": llx.IntData(cpuPeriod),
		"cpuWeight":        llx.IntData(parseCgroupInt(p.attrs["cpu.weight"], 100)),
		"pidsMax":          llx.IntData(parseCgroupMax(p.attrs["pids.max"])),
		"pidsCurrent":      llx.IntData(parseCgroupInt(p.attrs["pids.current"], 0)),
		"pids":             llx.ArrayData(pids, types.Int),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlCgroup), nil
}

// normalizeCgroupPath converts an absolute filesystem path under
// /sys/fs/cgroup into a path relative to the cgroup root. The root
// itself becomes "/".
func normalizeCgroupPath(absPath string) string {
	rel := strings.TrimPrefix(absPath, cgroupRoot)
	if rel == "" {
		return "/"
	}
	return rel
}

// parentCgroupPath returns the path of the cgroup that contains this
// one. The root cgroup ("/") has no parent and returns itself, which
// callers use to skip the self-link.
func parentCgroupPath(path string) string {
	if path == "/" {
		return "/"
	}
	idx := strings.LastIndexByte(path, '/')
	if idx <= 0 {
		return "/"
	}
	return path[:idx]
}

// cgroupUnitTypeFromPath infers the systemd unit kind from the leaf
// name. This is distinct from the kernel's `cgroup.type` (which
// reports domain/threaded/etc.). We don't model arbitrary cgroup
// directories created outside systemd (e.g. Docker without
// systemd-cgroup) as a distinct kind — they get `other`.
func cgroupUnitTypeFromPath(path string) string {
	if path == "/" {
		return "root"
	}
	leaf := path
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		leaf = path[idx+1:]
	}
	switch {
	case strings.HasSuffix(leaf, ".slice"):
		return "slice"
	case strings.HasSuffix(leaf, ".scope"):
		return "scope"
	case strings.HasSuffix(leaf, ".service"):
		return "service"
	default:
		return "other"
	}
}

// parseCgroupMax parses a cgroup limit file. `max` (the kernel's
// literal for "no limit") becomes -1; anything else parses as an
// int64. Empty / missing / unparseable input becomes -1 too, so a
// cgroup that doesn't have the relevant controller enabled reads as
// "no limit" — semantically the same outcome as "max".
func parseCgroupMax(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return -1
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1
	}
	return v
}

// parseCgroupInt parses a cgroup counter file (memory.current,
// pids.current, cpu.weight, etc.). On missing/invalid input it returns
// fallback so callers can distinguish "no value" from a real 0.
func parseCgroupInt(s string, fallback int64) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fallback
	}
	return v
}

// parseCpuMax parses the two-value `cpu.max` file (`<quota> <period>`).
// quota may be the literal `max` meaning unlimited (-1). period
// defaults to the kernel default of 100000 microseconds when absent.
func parseCpuMax(s string) (quota, period int64) {
	quota = -1
	period = 100000
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return
	}
	if fields[0] != "max" {
		if v, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			quota = v
		}
	}
	if len(fields) >= 2 {
		if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			period = v
		}
	}
	return
}

func stringsAsAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func pidsAsAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// runShellCmd executes a command via the command resource. Returns
// (stdout, true, nil) on success and (empty, false, nil) when the
// command exits non-zero (e.g. shell unavailable, /sys/fs/cgroup
// inaccessible). This matches the pattern used by lvm.go and the
// systemd resources.
func runShellCmd(runtime *plugin.Runtime, cmdline string) (string, bool, error) {
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData(cmdline),
	})
	if err != nil {
		return "", false, err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		return "", false, nil
	}
	return cmd.Stdout.Data, true, nil
}
