// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// windowsMemoryScript reads the memory snapshot in one round trip.
// TotalVisibleMemorySize is in KiB; the three perf counters are in bytes.
// Raw counters, not the formatted class, so the values are the exact byte
// counts Task Manager shows as Available and Committed.
const windowsMemoryScript = `$ErrorActionPreference = 'Stop'
$os = Get-CimInstance -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize
$pm = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Memory -Property AvailableBytes,CommittedBytes,CommitLimit
[PSCustomObject]@{
  TotalVisibleMemorySize = $os.TotalVisibleMemorySize
  AvailableBytes = $pm.AvailableBytes
  CommittedBytes = $pm.CommittedBytes
  CommitLimit = $pm.CommitLimit
} | ConvertTo-Json -Compress`

// memoryInfo holds one snapshot, in bytes. A nil pointer is a value the
// target did not report, which the fields surface as null rather than 0.
type memoryInfo struct {
	Total       *int64
	Available   *int64
	Committed   *int64
	CommitLimit *int64
}

type mqlMemoryInternal struct {
	once     sync.Once
	info     *memoryInfo
	fetchErr error
}

func (m *mqlMemory) id() (string, error) {
	return "memory", nil
}

// fetch reads the snapshot once, so every field comes from the same moment
// and the target runs one command however many fields a query reads.
func (m *mqlMemory) fetch() (*memoryInfo, error) {
	m.once.Do(func() {
		conn := m.MqlRuntime.Connection.(shared.Connection)
		m.info, m.fetchErr = readMemoryInfo(conn)
	})
	return m.info, m.fetchErr
}

func readMemoryInfo(conn shared.Connection) (*memoryInfo, error) {
	// Memory usage is a property of a running system. An image, a snapshot or
	// a mounted disk has none, whatever platform it holds.
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, llx.NotApplicable(errors.New("memory requires a running system; this asset cannot run commands"))
	}

	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return nil, errors.New("memory: platform is unknown")
	}
	pf := asset.Platform

	// Solaris comes first: 11.4 ships an os-release and is detected into the
	// linux family, but has no /proc/meminfo.
	switch {
	case pf.Name == "solaris":
		out, err := runMemoryCommand(conn, solarisMemoryCommand)
		if err != nil {
			return nil, err
		}
		return parseSolarisMemory(out)
	case pf.IsFamily("windows"):
		out, err := runMemoryCommand(conn, powershell.Encode(windowsMemoryScript))
		if err != nil {
			return nil, err
		}
		return parseWindowsMemory(out)
	case pf.IsFamily("darwin"):
		out, err := runMemoryCommand(conn, macosMemoryCommand)
		if err != nil {
			return nil, err
		}
		return parseMacosMemory(out)
	case pf.Name == "freebsd":
		out, err := runMemoryCommand(conn, freebsdMemoryCommand)
		if err != nil {
			return nil, err
		}
		return parseFreebsdMemory(out)
	case pf.Name == "netbsd":
		out, err := runMemoryCommand(conn, netbsdMemoryCommand)
		if err != nil {
			return nil, err
		}
		return parseNetbsdMemory(out)
	case pf.IsFamily("linux"):
		data, err := afero.ReadFile(conn.FileSystem(), "/proc/meminfo")
		if err != nil {
			return nil, fmt.Errorf("memory: failed to read /proc/meminfo: %w", err)
		}
		return parseLinuxMeminfo(data)
	default:
		// Not classified: the target has memory, this provider does not read it yet.
		return nil, fmt.Errorf("memory is not yet supported on %s", pf.Name)
	}
}

func runMemoryCommand(conn shared.Connection, command string) ([]byte, error) {
	cmd, err := conn.RunCommand(command)
	if err != nil {
		return nil, err
	}
	stdout, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("failed to read memory counters (exit %d): %s", cmd.ExitStatus, strings.TrimSpace(string(stderr)))
	}
	return stdout, nil
}

// int64Ptr returns a pointer to v, for building a snapshot field.
func int64Ptr(v int64) *int64 {
	return &v
}

// scaled multiplies a reported count by its unit, keeping an unreported
// count unreported.
func scaled(v *int64, unit int64) *int64 {
	if v == nil {
		return nil
	}
	return int64Ptr(*v * unit)
}

// parseLinuxMeminfo reads /proc/meminfo. The kernel reports these values in
// kB (KiB). MemAvailable exists since Linux 3.14; an older kernel leaves
// available null. CommitLimit is always reported but only enforced with
// vm.overcommit_memory=2.
func parseLinuxMeminfo(data []byte) (*memoryInfo, error) {
	values := map[string]*int64{}
	for _, line := range strings.Split(string(data), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "MemTotal", "MemAvailable", "Committed_AS", "CommitLimit":
		default:
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return nil, fmt.Errorf("memory: /proc/meminfo has no value for %s", key)
		}
		n, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("memory: failed to parse %s in /proc/meminfo: %w", key, err)
		}
		unit := int64(1)
		if len(fields) > 1 {
			if fields[1] != "kB" {
				return nil, fmt.Errorf("memory: unexpected unit %q for %s in /proc/meminfo", fields[1], key)
			}
			unit = 1024
		}
		values[key] = int64Ptr(n * unit)
	}
	if values["MemTotal"] == nil {
		return nil, errors.New("memory: /proc/meminfo has no MemTotal")
	}
	return &memoryInfo{
		Total:       values["MemTotal"],
		Available:   values["MemAvailable"],
		Committed:   values["Committed_AS"],
		CommitLimit: values["CommitLimit"],
	}, nil
}

// macosMemoryCommand prints the installed memory and the page counts.
// sysctl without -n, so every value arrives with its name.
const macosMemoryCommand = "sysctl hw.memsize && vm_stat"

// parseMacosMemory reads sysctl and vm_stat output. Available is free plus
// file-backed plus purgeable pages: the memory the kernel can hand out by
// dropping clean file cache and volatile purgeable memory, without compressing
// or swapping anything. vm_stat already excludes speculative pages from
// "Pages free", and they are part of "File-backed pages", so each page is
// counted once. macOS keeps no commit accounting, so committed and
// commitLimit stay null.
func parseMacosMemory(data []byte) (*memoryInfo, error) {
	values := map[string]int64{}
	var pageSize int64
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "Mach Virtual Memory Statistics: (page size of "); ok {
			size, _, _ := strings.Cut(rest, " ")
			n, err := strconv.ParseInt(size, 10, 64)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("memory: failed to parse vm_stat page size %q", line)
			}
			pageSize = n
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSuffix(strings.TrimSpace(val), ".")
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			continue
		}
		values[strings.TrimSpace(key)] = n
	}

	memsize, ok := values["hw.memsize"]
	if !ok {
		return nil, errors.New("memory: sysctl did not report hw.memsize")
	}
	info := &memoryInfo{Total: int64Ptr(memsize)}

	free, okFree := values["Pages free"]
	fileBacked, okFile := values["File-backed pages"]
	purgeable, okPurge := values["Pages purgeable"]
	if pageSize > 0 && okFree && okFile && okPurge {
		info.Available = int64Ptr((free + fileBacked + purgeable) * pageSize)
	}
	return info, nil
}

// freebsdMemoryCommand reads the physical memory and page counts. -i skips an
// unknown name instead of failing the whole call.
const freebsdMemoryCommand = "sysctl -i hw.physmem hw.pagesize vm.stats.vm.v_free_count vm.stats.vm.v_inactive_count vm.swap_reserved"

// parseFreebsdMemory reads sysctl output. Available is free plus inactive
// pages, which the page daemon reclaims without writing them out; laundry
// pages are excluded, since they need a write to swap first. Committed is
// vm.swap_reserved, the anonymous memory the kernel has reserved backing for.
// FreeBSD reports no commit limit, so commitLimit stays null.
func parseFreebsdMemory(data []byte) (*memoryInfo, error) {
	values := map[string]*int64{}
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("memory: failed to parse sysctl %s: %w", strings.TrimSpace(key), err)
		}
		values[strings.TrimSpace(key)] = int64Ptr(n)
	}

	if values["hw.physmem"] == nil {
		return nil, errors.New("memory: sysctl did not report hw.physmem")
	}
	info := &memoryInfo{
		Total:     values["hw.physmem"],
		Committed: values["vm.swap_reserved"],
	}
	pageSize, free, inactive := values["hw.pagesize"], values["vm.stats.vm.v_free_count"], values["vm.stats.vm.v_inactive_count"]
	if pageSize != nil && free != nil && inactive != nil {
		info.Available = int64Ptr((*free + *inactive) * *pageSize)
	}
	return info, nil
}

// netbsdMemoryCommand prints the physical memory and the UVM page counts.
// sysctl lives in /sbin, which is not on an unprivileged user's PATH.
const netbsdMemoryCommand = "/sbin/sysctl hw.physmem64 && vmstat -s"

// parseNetbsdMemory reads sysctl and vmstat -s output. Available is free plus
// cached file pages, the Free and File totals top shows: a file page returns
// to the free list by being dropped or written to its file, never to swap.
// Inactive pages are excluded, since NetBSD keeps dirty anonymous pages on the
// same queue. hw.physmem64 rather than hw.physmem, which is 32-bit on 32-bit
// ports. NetBSD keeps no commit accounting, so committed and commitLimit stay
// null.
func parseNetbsdMemory(data []byte) (*memoryInfo, error) {
	var total *int64
	counts := map[string]int64{}
	for _, line := range strings.Split(string(data), "\n") {
		if key, val, ok := strings.Cut(line, "="); ok {
			if strings.TrimSpace(key) != "hw.physmem64" {
				continue
			}
			n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("memory: failed to parse sysctl hw.physmem64: %w", err)
			}
			total = int64Ptr(n)
			continue
		}
		// vmstat -s prints a count, then what it counts. Lines that do not
		// start with a count, such as the name cache summary, are skipped.
		count, label, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(count, 10, 64)
		if err != nil {
			continue
		}
		counts[strings.TrimSpace(label)] = n
	}

	if total == nil {
		return nil, errors.New("memory: sysctl did not report hw.physmem64")
	}
	info := &memoryInfo{Total: total}
	pageSize, okSize := counts["bytes per page"]
	free, okFree := counts["pages free"]
	file, okFile := counts["cached file pages"]
	if okSize && pageSize > 0 && okFree && okFile {
		info.Available = int64Ptr((free + file) * pageSize)
	}
	return info, nil
}

// solarisMemoryCommand prints the page size, the physical and free page
// counts, and the virtual swap summary.
const solarisMemoryCommand = "pagesize && kstat -p unix:0:system_pages:physmem unix:0:system_pages:freemem && swap -s"

// parseSolarisMemory reads pagesize, kstat -p and swap -s output. Solaris
// reserves swap for every anonymous allocation, so the swap -s "used" total
// (allocated plus reserved) is the committed memory and used plus
// "available" is the hard commit limit. swap -s reports in KiB.
func parseSolarisMemory(data []byte) (*memoryInfo, error) {
	var pageSize, physmem, freemem, used, avail *int64
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "unix:0:system_pages:"):
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return nil, fmt.Errorf("memory: unexpected kstat line %q", line)
			}
			n, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("memory: failed to parse kstat line %q: %w", line, err)
			}
			switch strings.TrimPrefix(fields[0], "unix:0:system_pages:") {
			case "physmem":
				physmem = int64Ptr(n)
			case "freemem":
				freemem = int64Ptr(n)
			}
		case strings.HasPrefix(line, "total:"):
			var err error
			used, avail, err = parseSolarisSwapSummary(line)
			if err != nil {
				return nil, err
			}
		default:
			if pageSize != nil {
				return nil, fmt.Errorf("memory: unexpected output line %q", line)
			}
			n, err := strconv.ParseInt(line, 10, 64)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("memory: failed to parse page size %q", line)
			}
			pageSize = int64Ptr(n)
		}
	}
	if pageSize == nil || physmem == nil {
		return nil, errors.New("memory: pagesize or kstat reported no physical memory")
	}

	info := &memoryInfo{
		Total:     scaled(physmem, *pageSize),
		Available: scaled(freemem, *pageSize),
		Committed: scaled(used, 1024),
	}
	if used != nil && avail != nil {
		info.CommitLimit = int64Ptr((*used + *avail) * 1024)
	}
	return info, nil
}

// parseSolarisSwapSummary reads the used and available KiB out of
//
//	total: 290048k bytes allocated + 105728k reserved = 395776k used, 14362368k available
func parseSolarisSwapSummary(line string) (used, avail *int64, err error) {
	_, rest, ok := strings.Cut(line, "=")
	if !ok {
		return nil, nil, fmt.Errorf("memory: unexpected swap -s output %q", line)
	}
	usedPart, availPart, ok := strings.Cut(rest, ",")
	if !ok {
		return nil, nil, fmt.Errorf("memory: unexpected swap -s output %q", line)
	}
	parse := func(part, label string) (*int64, error) {
		fields := strings.Fields(part)
		if len(fields) != 2 || fields[1] != label || !strings.HasSuffix(fields[0], "k") {
			return nil, fmt.Errorf("memory: unexpected swap -s output %q", line)
		}
		n, err := strconv.ParseInt(strings.TrimSuffix(fields[0], "k"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("memory: failed to parse swap -s output %q: %w", line, err)
		}
		return int64Ptr(n), nil
	}
	if used, err = parse(usedPart, "used"); err != nil {
		return nil, nil, err
	}
	if avail, err = parse(availPart, "available"); err != nil {
		return nil, nil, err
	}
	return used, avail, nil
}

// windowsMemoryRecord is the JSON the script emits. Pointers keep a missing
// or null counter distinguishable from a zero one.
type windowsMemoryRecord struct {
	TotalVisibleMemorySize *int64 `json:"TotalVisibleMemorySize"`
	AvailableBytes         *int64 `json:"AvailableBytes"`
	CommittedBytes         *int64 `json:"CommittedBytes"`
	CommitLimit            *int64 `json:"CommitLimit"`
}

func parseWindowsMemory(data []byte) (*memoryInfo, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("memory: the memory script returned no output")
	}
	var rec windowsMemoryRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("memory: failed to parse memory counters: %w", err)
	}

	info := &memoryInfo{
		Available:   rec.AvailableBytes,
		Committed:   rec.CommittedBytes,
		CommitLimit: rec.CommitLimit,
	}
	if rec.TotalVisibleMemorySize != nil {
		total := *rec.TotalVisibleMemorySize * 1024
		info.Total = &total
	}
	return info, nil
}

// memoryField resolves one value of the snapshot, marking the field null when
// the target did not report it.
func (m *mqlMemory) memoryField(field *plugin.TValue[int64], pick func(*memoryInfo) *int64) (int64, error) {
	info, err := m.fetch()
	if err != nil {
		return 0, err
	}
	v := pick(info)
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *v, nil
}

func (m *mqlMemory) total() (int64, error) {
	return m.memoryField(&m.Total, func(i *memoryInfo) *int64 { return i.Total })
}

func (m *mqlMemory) available() (int64, error) {
	return m.memoryField(&m.Available, func(i *memoryInfo) *int64 { return i.Available })
}

func (m *mqlMemory) committed() (int64, error) {
	return m.memoryField(&m.Committed, func(i *memoryInfo) *int64 { return i.Committed })
}

func (m *mqlMemory) commitLimit() (int64, error) {
	return m.memoryField(&m.CommitLimit, func(i *memoryInfo) *int64 { return i.CommitLimit })
}
