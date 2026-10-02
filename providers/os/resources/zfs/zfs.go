// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package zfs

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Pool represents a parsed ZFS storage pool.
type Pool struct {
	Name      string
	GUID      string
	Size      int64
	Allocated int64
	Free      int64
	// Fragmentation is nil when the pool does not report it: Oracle Solaris
	// has no such property, and OpenZFS writes "-" without the
	// spacemap_histogram feature.
	Fragmentation *int64
	PercentUsed   int64
	Dedupratio    float64
	Health        string
	Readonly      bool
	Autoexpand    bool
	Autoreplace   bool
	Autotrim      bool
}

// Vdev represents a virtual device in a ZFS pool's topology.
type Vdev struct {
	Name           string
	Type           string
	State          string
	Path           string
	ReadErrors     int64
	WriteErrors    int64
	ChecksumErrors int64
	SlowIOs        int64
	Devices        []Vdev
}

// Dataset represents a parsed ZFS dataset.
type Dataset struct {
	Name          string
	Type          string
	Used          int64
	Available     int64
	Referenced    int64
	Mountpoint    string
	Compression   string
	Compressratio float64
	Mounted       bool
	Recordsize    int64
	Quota         int64
	Reservation   int64
	Origin        string
	Creation      *time.Time
	Encryption    string
}

// JSON output structure shared by zpool get and zfs get commands.
// Both produce: {"pools"|"datasets": {"name": {"properties": {"key": {"value": "..."}}}}}
type propertyValue struct {
	Value string `json:"value"`
}

// JSON output structure for zpool status -jp (vdev topology).
type zpoolStatusOutput struct {
	Pools map[string]zpoolStatusPool `json:"pools"`
}

type zpoolStatusPool struct {
	Vdevs map[string]zpoolStatusVdev `json:"vdevs"`
}

type zpoolStatusVdev struct {
	Name           string                     `json:"name"`
	VdevType       string                     `json:"vdev_type"`
	State          string                     `json:"state"`
	Path           string                     `json:"path"`
	ReadErrors     string                     `json:"read_errors"`
	WriteErrors    string                     `json:"write_errors"`
	ChecksumErrors string                     `json:"checksum_errors"`
	SlowIOs        string                     `json:"slow_ios"`
	Vdevs          map[string]zpoolStatusVdev `json:"vdevs"`
}

// ParsePools parses the JSON output of `zpool get -jp all`.
// All pool properties (health, guid, size, etc.) come from this single command.
func ParsePools(jsonOutput string) ([]Pool, error) {
	byName, err := parseGetJSON(jsonOutput, "zpool get")
	if err != nil {
		return nil, err
	}
	return poolsFromProperties(byName)
}

// ParsePoolsText parses the scriptable output of `zpool get -Hp all`, used on
// OpenZFS releases older than 2.3 that have no JSON output.
func ParsePoolsText(output string) ([]Pool, error) {
	byName, err := parseGetText(output)
	if err != nil {
		return nil, fmt.Errorf("parsing zpool get output: %w", err)
	}
	return poolsFromProperties(byName)
}

func poolsFromProperties(byName map[string]map[string]string) ([]Pool, error) {
	if len(byName) == 0 {
		return nil, nil
	}

	pools := make([]Pool, 0, len(byName))
	for name, props := range byName {
		pool := Pool{
			Name:   name,
			GUID:   props["guid"],
			Health: props["health"],
		}

		var err error
		pool.Size, err = parseInt(props["size"])
		if err != nil {
			return nil, fmt.Errorf("parsing pool %q size: %w", name, err)
		}
		pool.Allocated, err = parseInt(props["allocated"])
		if err != nil {
			return nil, fmt.Errorf("parsing pool %q allocated: %w", name, err)
		}
		pool.Free, err = parseInt(props["free"])
		if err != nil {
			return nil, fmt.Errorf("parsing pool %q free: %w", name, err)
		}
		if frag, ok := props["fragmentation"]; ok && frag != "-" && frag != "" {
			n, err := parsePercent(frag)
			if err != nil {
				return nil, fmt.Errorf("parsing pool %q fragmentation: %w", name, err)
			}
			pool.Fragmentation = &n
		}
		pool.PercentUsed, err = parsePercent(props["capacity"])
		if err != nil {
			return nil, fmt.Errorf("parsing pool %q capacity: %w", name, err)
		}
		pool.Dedupratio, err = parseRatio(props["dedupratio"])
		if err != nil {
			return nil, fmt.Errorf("parsing pool %q dedupratio: %w", name, err)
		}
		pool.Readonly = parseBool(props["readonly"])
		pool.Autoexpand = parseBool(props["autoexpand"])
		pool.Autoreplace = parseBool(props["autoreplace"])
		pool.Autotrim = parseBool(props["autotrim"])

		pools = append(pools, pool)
	}

	return pools, nil
}

// ParseDatasets parses the JSON output of `zfs get -jp all`.
// All dataset properties come from this single command.
func ParseDatasets(jsonOutput string) ([]Dataset, error) {
	byName, err := parseGetJSON(jsonOutput, "zfs get")
	if err != nil {
		return nil, err
	}
	return datasetsFromProperties(byName)
}

// ParseDatasetsText parses the scriptable output of `zfs get -Hp all`, used on
// OpenZFS releases older than 2.3 that have no JSON output.
func ParseDatasetsText(output string) ([]Dataset, error) {
	byName, err := parseGetText(output)
	if err != nil {
		return nil, fmt.Errorf("parsing zfs get output: %w", err)
	}
	return datasetsFromProperties(byName)
}

func datasetsFromProperties(byName map[string]map[string]string) ([]Dataset, error) {
	if len(byName) == 0 {
		return nil, nil
	}

	datasets := make([]Dataset, 0, len(byName))
	for name, props := range byName {
		ds := Dataset{
			Name:        name,
			Type:        strings.ToLower(props["type"]),
			Mountpoint:  dashToEmpty(props["mountpoint"]),
			Compression: dashToEmpty(props["compression"]),
			Origin:      dashToEmpty(props["origin"]),
			Encryption:  dashToEmpty(props["encryption"]),
		}

		var err error
		ds.Used, err = parseInt(props["used"])
		if err != nil {
			return nil, fmt.Errorf("parsing dataset %q used: %w", name, err)
		}
		ds.Available, err = parseInt(props["available"])
		if err != nil {
			return nil, fmt.Errorf("parsing dataset %q available: %w", name, err)
		}
		ds.Referenced, err = parseInt(props["referenced"])
		if err != nil {
			return nil, fmt.Errorf("parsing dataset %q referenced: %w", name, err)
		}
		ds.Compressratio, err = parseRatio(props["compressratio"])
		if err != nil {
			return nil, fmt.Errorf("parsing dataset %q compressratio: %w", name, err)
		}
		ds.Mounted = parseBool(props["mounted"])
		ds.Recordsize, err = parseInt(props["recordsize"])
		if err != nil {
			return nil, fmt.Errorf("parsing dataset %q recordsize: %w", name, err)
		}
		ds.Quota, err = parseInt(props["quota"])
		if err != nil {
			return nil, fmt.Errorf("parsing dataset %q quota: %w", name, err)
		}
		ds.Reservation, err = parseInt(props["reservation"])
		if err != nil {
			return nil, fmt.Errorf("parsing dataset %q reservation: %w", name, err)
		}

		creationStr := props["creation"]
		if creationStr != "" && creationStr != "-" {
			epoch, err := strconv.ParseInt(creationStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parsing dataset %q creation: %w", name, err)
			}
			t := time.Unix(epoch, 0)
			ds.Creation = &t
		}

		datasets = append(datasets, ds)
	}

	return datasets, nil
}

// ParseProperties parses the JSON output of `zpool get -jp all '<name>'`
// or `zfs get -jp all '<name>'` into a flat key-value map.
// Works for both pool and dataset properties since the JSON structure
// is the same (just keyed under "pools" vs "datasets").
func ParseProperties(jsonOutput string) (map[string]string, error) {
	props := make(map[string]string)
	if strings.TrimSpace(jsonOutput) == "" {
		return props, nil
	}

	// Try parsing as pool properties first, then dataset properties.
	// The JSON has either "pools" or "datasets" as the top-level key.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonOutput), &raw); err != nil {
		return nil, fmt.Errorf("parsing properties JSON: %w", err)
	}

	// Generic structure: {"pools"|"datasets": {"name": {"properties": {"k": {"value": "v"}}}}}
	type propsContainer struct {
		Properties map[string]propertyValue `json:"properties"`
	}

	for key, data := range raw {
		if key == "output_version" {
			continue
		}
		var items map[string]propsContainer
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, fmt.Errorf("parsing properties for key %q: %w", key, err)
		}
		for _, item := range items {
			for k, v := range item.Properties {
				props[k] = v.Value
			}
		}
	}

	return props, nil
}

// ParsePropertiesText parses the scriptable output of `zpool get -Hp all '<name>'`
// or `zfs get -Hp all '<name>'` into a flat key-value map.
func ParsePropertiesText(output string) (map[string]string, error) {
	byName, err := parseGetText(output)
	if err != nil {
		return nil, fmt.Errorf("parsing properties: %w", err)
	}
	props := make(map[string]string)
	for _, item := range byName {
		for k, v := range item {
			props[k] = v
		}
	}
	return props, nil
}

// parseGetJSON parses `zpool get -jp` / `zfs get -jp` output into
// name -> property -> value.
func parseGetJSON(jsonOutput string, command string) (map[string]map[string]string, error) {
	if strings.TrimSpace(jsonOutput) == "" {
		return nil, nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonOutput), &raw); err != nil {
		return nil, fmt.Errorf("parsing %s JSON: %w", command, err)
	}

	key := "datasets"
	if command == "zpool get" {
		key = "pools"
	}
	data, ok := raw[key]
	if !ok {
		return nil, nil
	}

	var items map[string]struct {
		Properties map[string]propertyValue `json:"properties"`
	}
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("parsing %s JSON: %w", command, err)
	}

	byName := make(map[string]map[string]string, len(items))
	for name, item := range items {
		props := make(map[string]string, len(item.Properties))
		for k, v := range item.Properties {
			props[k] = v.Value
		}
		byName[name] = props
	}
	return byName, nil
}

// parseGetText parses `zpool get -Hp` / `zfs get -Hp` output into
// name -> property -> value. Each line holds four tab-separated columns:
// name, property, value, source. A value may itself contain tabs (user
// properties), so the value is everything between the second and the last
// column.
//
// A value may also contain a newline, which splits its row across lines:
// Oracle Solaris images carry a `com.oracle.diskimage:original_guid` user
// property whose value ends in one. A line with fewer than four columns is
// therefore joined with the lines after it until the row is complete.
func parseGetText(output string) (map[string]map[string]string, error) {
	byName := map[string]map[string]string{}
	pending := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if pending != "" {
			line = pending + "\n" + line
			pending = ""
		} else if line == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 4 {
			pending = line
			continue
		}
		name := cols[0]
		props, ok := byName[name]
		if !ok {
			props = map[string]string{}
			byName[name] = props
		}
		props[cols[1]] = strings.Join(cols[2:len(cols)-1], "\t")
	}
	if strings.TrimSpace(pending) != "" {
		return nil, fmt.Errorf("unexpected line %q", pending)
	}
	return byName, nil
}

// ParseVdevs parses the JSON output of `zpool status -jp '<pool>'` and returns
// the top-level vdev groups (skipping the root vdev). Each vdev has nested devices.
func ParseVdevs(statusJSON string) ([]Vdev, error) {
	if strings.TrimSpace(statusJSON) == "" {
		return nil, nil
	}

	var status zpoolStatusOutput
	if err := json.Unmarshal([]byte(statusJSON), &status); err != nil {
		return nil, fmt.Errorf("parsing zpool status JSON: %w", err)
	}

	// There should be exactly one pool in the output.
	for _, pool := range status.Pools {
		// The top-level vdevs map contains one root vdev (named after the pool).
		// Its children are the actual vdev groups (raidz, mirror, etc.).
		for _, rootVdev := range pool.Vdevs {
			if rootVdev.VdevType != "root" {
				continue
			}
			return convertVdevs(rootVdev.Vdevs)
		}
	}

	return nil, nil
}

func convertVdevs(vdevMap map[string]zpoolStatusVdev) ([]Vdev, error) {
	if len(vdevMap) == 0 {
		return nil, nil
	}

	vdevs := make([]Vdev, 0, len(vdevMap))
	for _, sv := range vdevMap {
		v, err := convertVdev(sv)
		if err != nil {
			return nil, err
		}
		vdevs = append(vdevs, v)
	}
	return vdevs, nil
}

func convertVdev(sv zpoolStatusVdev) (Vdev, error) {
	var v Vdev
	v.Name = sv.Name
	v.Type = sv.VdevType
	v.State = sv.State
	v.Path = sv.Path

	var err error
	v.ReadErrors, err = parseInt(sv.ReadErrors)
	if err != nil {
		return v, fmt.Errorf("parsing vdev %q read_errors: %w", sv.Name, err)
	}
	v.WriteErrors, err = parseInt(sv.WriteErrors)
	if err != nil {
		return v, fmt.Errorf("parsing vdev %q write_errors: %w", sv.Name, err)
	}
	v.ChecksumErrors, err = parseInt(sv.ChecksumErrors)
	if err != nil {
		return v, fmt.Errorf("parsing vdev %q checksum_errors: %w", sv.Name, err)
	}
	v.SlowIOs, err = parseInt(sv.SlowIOs)
	if err != nil {
		return v, fmt.Errorf("parsing vdev %q slow_ios: %w", sv.Name, err)
	}

	v.Devices, err = convertVdevs(sv.Vdevs)
	if err != nil {
		return v, err
	}

	return v, nil
}

// IsJSONUnsupported reports whether a zfs or zpool command failed because it
// does not know the -j (JSON output) flag. JSON output exists since OpenZFS
// 2.3; older releases print "invalid option 'j'" and exit 2.
func IsJSONUnsupported(stderr string) bool {
	return strings.Contains(stderr, "invalid option 'j'")
}

// ParseVdevsTextPlain parses `zpool status '<pool>'` and
// `zpool status -P '<pool>'` from releases whose zpool status has neither -p
// nor -s: ZFS on Linux before 0.8, and Oracle Solaris. ZFS on Linux has -P and
// lists disks by their /dev path there. Oracle Solaris has no -P, so
// fullPathOutput is empty and disks resolve under /dev/dsk.
func ParseVdevsTextPlain(statusOutput string, fullPathOutput string) ([]Vdev, error) {
	if fullPathOutput == "" {
		return ParseVdevsTextSolaris(statusOutput)
	}
	return ParseVdevsText(statusOutput, fullPathOutput)
}

// ParseVdevsTextSolaris parses the output of a plain `zpool status '<pool>'`
// on Oracle Solaris, whose zpool status has neither -p, -s nor -P. It lists
// disks by their bare device name (c0t5000CCA0D0E1F2A3d0), which Solaris
// resolves under /dev/dsk, and file vdevs by their absolute path.
func ParseVdevsTextSolaris(statusOutput string) ([]Vdev, error) {
	vdevs, err := ParseVdevsText(statusOutput, statusOutput)
	if err != nil {
		return nil, err
	}
	solarisDiskPaths(vdevs)
	return vdevs, nil
}

func solarisDiskPaths(vdevs []Vdev) {
	for i := range vdevs {
		v := &vdevs[i]
		if len(v.Devices) > 0 {
			solarisDiskPaths(v.Devices)
			continue
		}
		if v.Path != "" && !strings.HasPrefix(v.Path, "/") {
			v.Path = "/dev/dsk/" + v.Path
			v.Type = leafVdevType(v.Path)
		}
	}
}

var solarisPoolVersion = regexp.MustCompile(`running ZFS pool version (\d+)`)

// ParseSolarisPoolVersion reads the pool version from `zpool upgrade -v`
// ("This system is currently running ZFS pool version 53."). Oracle Solaris
// has no `zfs version`; the pool version is how it names its ZFS release.
func ParseSolarisPoolVersion(output string) (string, bool) {
	m := solarisPoolVersion.FindStringSubmatch(output)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ParseVdevsText parses the text output of `zpool status -ps '<pool>'` and
// `zpool status -Pps '<pool>'` and returns the top-level vdev groups (skipping
// the root vdev), like ParseVdevs does for JSON. It is used on OpenZFS releases
// older than 2.3 that have no JSON output.
//
// The first output provides the vdev names as the JSON output reports them
// (disks without their /dev/ prefix), the second the full device paths. Both
// list the same vdevs line by line.
//
// Only the pool's regular vdevs are returned. The special, dedup, logs, cache,
// and spares sections are left out, since the JSON output reports those outside
// the root vdev too.
func ParseVdevsText(statusOutput string, fullPathOutput string) ([]Vdev, error) {
	short, counters := statusConfigLines(statusOutput)
	full, _ := statusConfigLines(fullPathOutput)
	if len(short) == 0 {
		return nil, nil
	}
	if len(short) != len(full) {
		return nil, fmt.Errorf("parsing zpool status: %d vdev lines with names, %d with paths", len(short), len(full))
	}

	type node struct {
		vdev     Vdev
		depth    int
		children []*node
	}

	var root *node
	stack := []*node{}
	for i, line := range short {
		depth, fields := statusFields(line)
		_, fullFields := statusFields(full[i])
		if len(fields) == 0 {
			continue
		}

		if depth == 0 {
			if root != nil {
				// A section after the root vdev (special, dedup, logs, cache, spares).
				break
			}
			root = &node{depth: 0}
			stack = []*node{root}
			continue
		}
		if root == nil {
			return nil, fmt.Errorf("parsing zpool status: vdev %q before the pool", fields[0])
		}

		v, err := statusVdev(fields, fullFields, counters)
		if err != nil {
			return nil, err
		}
		n := &node{vdev: v, depth: depth}

		for len(stack) > 1 && stack[len(stack)-1].depth >= depth {
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1]
		parent.children = append(parent.children, n)
		stack = append(stack, n)
	}

	if root == nil {
		return nil, nil
	}

	var convert func(nodes []*node) []Vdev
	convert = func(nodes []*node) []Vdev {
		if len(nodes) == 0 {
			return nil
		}
		res := make([]Vdev, 0, len(nodes))
		for _, n := range nodes {
			v := n.vdev
			v.Devices = convert(n.children)
			if len(n.children) > 0 {
				// Groups carry no path and no slow I/O count in the JSON output.
				v.Type = groupVdevType(v.Name)
				v.Path = ""
				v.SlowIOs = 0
			} else {
				v.Type = leafVdevType(v.Path)
			}
			res = append(res, v)
		}
		return res
	}
	return convert(root.children), nil
}

// statusConfigLines returns the vdev lines of the config section of
// `zpool status`, from the line after the NAME header up to the first blank
// line, and the number of error counter columns the header names: READ,
// WRITE, CKSUM, and SLOW with -s. Releases without -s (ZFS on Linux before
// 0.8, Oracle Solaris) have no SLOW column, so a note such as "was /dev/sdb"
// follows CKSUM directly.
func statusConfigLines(output string) ([]string, int) {
	var lines []string
	counters := 0
	inConfig := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !inConfig {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "NAME" && fields[1] == "STATE" {
				inConfig = true
				counters = len(fields) - 2
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		lines = append(lines, line)
	}
	return lines, counters
}

// statusFields returns the nesting depth of a zpool status config line and its
// whitespace-separated fields. Lines start with a tab, then two spaces per
// nesting level.
func statusFields(line string) (int, []string) {
	line = strings.TrimPrefix(line, "\t")
	trimmed := strings.TrimLeft(line, " ")
	depth := (len(line) - len(trimmed)) / 2
	return depth, strings.Fields(trimmed)
}

// statusVdev builds a vdev from a config line (NAME STATE READ WRITE CKSUM
// [SLOW] [note]) with the given number of counter columns, and the same line
// printed with full paths.
func statusVdev(fields []string, fullFields []string, counters int) (Vdev, error) {
	v := Vdev{Name: fields[0]}
	if len(fullFields) > 0 {
		v.Path = fullFields[0]
	}
	if len(fields) > 1 {
		v.State = fields[1]
	}

	dsts := []*int64{&v.ReadErrors, &v.WriteErrors, &v.ChecksumErrors, &v.SlowIOs}
	names := []string{"read errors", "write errors", "checksum errors", "slow I/Os"}
	for i, dst := range dsts {
		if i >= counters || len(fields) <= 2+i {
			break
		}
		n, err := parseCount(fields[2+i])
		if err != nil {
			return v, fmt.Errorf("parsing vdev %q %s: %w", v.Name, names[i], err)
		}
		*dst = n
	}

	// A missing device is listed by its GUID with a note "was /dev/ada1".
	for i := 2; i < len(fullFields)-1; i++ {
		if fullFields[i] == "was" {
			v.Path = fullFields[i+1]
			break
		}
	}
	return v, nil
}

// groupVdevType derives the vdev type from a group vdev name such as
// "mirror-0", "raidz2-1", "draid1:2d:4c:0s-0", "spare-3", or "replacing-0".
func groupVdevType(name string) string {
	t := name
	if i := strings.LastIndexByte(t, '-'); i > 0 {
		t = t[:i]
	}
	if i := strings.IndexByte(t, ':'); i > 0 {
		t = t[:i]
	}
	switch {
	case strings.HasPrefix(t, "raidz"):
		return "raidz"
	case strings.HasPrefix(t, "draid"):
		return "draid"
	}
	return t
}

// leafVdevType derives the vdev type of a leaf vdev from its path: devices
// under /dev are disks, anything else is a file vdev.
func leafVdevType(path string) string {
	if strings.HasPrefix(path, "/dev/") {
		return "disk"
	}
	return "file"
}

// parseInt parses a string to int64, treating "-" and "" as 0.
func parseInt(s string) (int64, error) {
	if s == "-" || s == "" {
		return 0, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

// parsePercent parses a ZFS percentage such as capacity or fragmentation.
// With -p, OpenZFS 0.7 and later print a bare number ("37"); ZFS on Linux
// 0.6.5 keeps the percent sign ("37%").
func parsePercent(s string) (int64, error) {
	return parseInt(strings.TrimSuffix(s, "%"))
}

// parseCount parses a vdev error counter from `zpool status`. With -p it is
// always a plain integer. Releases without -p (ZFS on Linux before 0.8, Oracle
// Solaris) print counters from 1000 on in their short form ("1.2K", "3M"),
// which is read back to the nearest value, in powers of 1024 like zfs_nicenum.
func parseCount(s string) (int64, error) {
	n, err := parseInt(s)
	if err == nil || len(s) < 2 {
		return n, err
	}
	exp := strings.IndexByte("KMGTPE", s[len(s)-1])
	if exp < 0 {
		return 0, err
	}
	f, ferr := strconv.ParseFloat(s[:len(s)-1], 64)
	if ferr != nil || f < 0 {
		return 0, err
	}
	return int64(math.Round(f * math.Pow(1024, float64(exp+1)))), nil
}

// parseRatio parses a ZFS ratio like "1.50x" or "1.50" to float64. Oracle
// Solaris `zpool get -p` writes dedupratio in hundredths without a decimal
// point ("300" for 3.00x); OpenZFS always writes the point, so a bare integer
// is read as hundredths.
func parseRatio(s string) (float64, error) {
	if s == "-" || s == "" {
		return 0, nil
	}
	s = strings.TrimSuffix(s, "x")
	if !strings.Contains(s, ".") {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, err
		}
		return float64(n) / 100, nil
	}
	return strconv.ParseFloat(s, 64)
}

// parseBool parses ZFS boolean values ("on"/"off", "yes"/"no").
func parseBool(s string) bool {
	return s == "on" || s == "yes"
}

// dashToEmpty converts "-" to an empty string.
func dashToEmpty(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
