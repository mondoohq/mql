// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/procfs"
)

type cpuInfo struct {
	Cores          int64
	Manufacturer   string
	Model          string
	ProcessorCount int64
	// MaxClockSpeed is in MHz; 0 means unknown.
	MaxClockSpeed int64
}

func initMachineCpu(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(shared.Connection)
	pf := conn.Asset().Platform

	var info *cpuInfo
	var err error

	switch {
	case pf.IsFamily("darwin"):
		info, err = getCpuInfoMacos(conn)
	case pf.IsFamily("windows"):
		info, err = getCpuInfoWindows(conn)
	case pf.Name == "freebsd":
		info, err = getCpuInfoFreeBSD(conn)
	case pf.Name == "aix":
		info, err = getCpuInfoAIX(conn)
	case pf.Name == "solaris":
		info, err = getCpuInfoSolaris(conn)
	case pf.IsFamily(inventory.FAMILY_UNIX):
		info, err = getCpuInfoLinux(conn)
	default:
		return nil, nil, fmt.Errorf("unsupported platform for cpu info: %s", pf.Name)
	}
	if err != nil {
		return nil, nil, err
	}

	maxClockSpeed := llx.NilData
	if info.MaxClockSpeed > 0 {
		maxClockSpeed = llx.IntData(info.MaxClockSpeed)
	}

	return map[string]*llx.RawData{
		"coreCount":      llx.IntData(info.Cores),
		"manufacturer":   llx.StringData(info.Manufacturer),
		"model":          llx.StringData(info.Model),
		"processorCount": llx.IntData(info.ProcessorCount),
		"maxClockSpeed":  maxClockSpeed,
	}, nil, nil
}

func getCpuInfoLinux(conn shared.Connection) (*cpuInfo, error) {
	f, err := conn.FileSystem().Open("/proc/cpuinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	parsed, err := procfs.ParseCpuInfo(f)
	if err != nil {
		return nil, err
	}

	if len(parsed.Processors) == 0 {
		return nil, errors.New("no processors found in /proc/cpuinfo")
	}

	// Count physical CPU packages (sockets) by unique physical_id values.
	// Count physical cores by deduplicating (physical_id, core_id) pairs.
	// On ARM or in containers where these fields aren't populated,
	// fall back to 1 socket and using processor count as core count.
	type coreKey struct {
		physicalID uint
		coreID     uint
	}
	seenCores := map[coreKey]struct{}{}
	seenSockets := map[uint]struct{}{}
	hasCoreInfo := false
	for _, p := range parsed.Processors {
		if p.CPUCores > 0 || p.Siblings > 0 {
			hasCoreInfo = true
		}
		seenCores[coreKey{p.PhysicalID, p.CoreID}] = struct{}{}
		seenSockets[p.PhysicalID] = struct{}{}
	}

	info := &cpuInfo{
		Manufacturer: normalizeManufacturer(parsed.Processors[0].VendorID),
		Model:        parsed.Processors[0].ModelName,
	}

	if hasCoreInfo {
		info.Cores = int64(len(seenCores))
		info.ProcessorCount = int64(len(seenSockets))
	} else {
		// ARM or minimal /proc/cpuinfo: each processor entry is a core, assume 1 socket
		info.Cores = int64(len(parsed.Processors))
		info.ProcessorCount = 1
	}

	info.MaxClockSpeed = linuxCpuMaxClockSpeed(conn)

	// On some ARM systems (e.g. Raspberry Pi), /proc/cpuinfo doesn't include
	// vendor or model name. Fall back to lscpu which typically has this info.
	if (info.Manufacturer == "" || info.Model == "") && conn.Capabilities().Has(shared.Capability_RunCommand) {
		if lscpuInfo, err := parseLscpuOutput(conn); err == nil {
			if info.Manufacturer == "" && lscpuInfo.Manufacturer != "" {
				info.Manufacturer = lscpuInfo.Manufacturer
			}
			if info.Model == "" && lscpuInfo.Model != "" {
				info.Model = lscpuInfo.Model
			}
		}
	}

	return info, nil
}

// linuxCpuMaxClockSpeed reads the cpufreq maximum, which most VMs and
// containers do not expose. /proc/cpuinfo only has the current frequency.
func linuxCpuMaxClockSpeed(conn shared.Connection) int64 {
	data, err := afero.ReadFile(conn.FileSystem(), "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
	if err != nil {
		return 0
	}
	khz, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return khz / 1000
}

func getCpuInfoMacos(conn shared.Connection) (*cpuInfo, error) {
	cmd, err := conn.RunCommand("sysctl -n machdep.cpu.brand_string hw.physicalcpu")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("sysctl failed: %s", string(stderr))
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("unexpected sysctl output: %s", string(data))
	}

	brandString := strings.TrimSpace(lines[0])
	physicalCPU, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hw.physicalcpu: %w", err)
	}

	info := &cpuInfo{
		Model:          brandString,
		Cores:          physicalCPU,
		ProcessorCount: 1, // Macs always have a single CPU package
	}

	// Extract manufacturer from brand string
	if strings.Contains(brandString, "Intel") {
		info.Manufacturer = "Intel"
	} else if strings.Contains(brandString, "Apple") {
		info.Manufacturer = "Apple"
	} else if strings.Contains(brandString, "AMD") {
		info.Manufacturer = "AMD"
	}

	return info, nil
}

const cpuWindowsScript = `
$cpu = @(Get-CimInstance -ClassName Win32_Processor)
$result = @{
    Name = $cpu[0].Name
    Manufacturer = $cpu[0].Manufacturer
    MaxClockSpeed = $cpu[0].MaxClockSpeed
    NumberOfCores = ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum
    ProcessorCount = $cpu.Count
}
$result | ConvertTo-Json
`

func getCpuInfoWindows(conn shared.Connection) (*cpuInfo, error) {
	cmd, err := conn.RunCommand(powershell.Encode(cpuWindowsScript))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("failed to retrieve cpu info: %s", string(stderr))
	}

	var result struct {
		Name           string `json:"Name"`
		Manufacturer   string `json:"Manufacturer"`
		NumberOfCores  int64  `json:"NumberOfCores"`
		ProcessorCount int64  `json:"ProcessorCount"`
		MaxClockSpeed  int64  `json:"MaxClockSpeed"`
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse cpu info: %w", err)
	}

	return &cpuInfo{
		Model:          strings.TrimSpace(result.Name),
		Manufacturer:   normalizeManufacturer(strings.TrimSpace(result.Manufacturer)),
		Cores:          result.NumberOfCores,
		ProcessorCount: result.ProcessorCount,
		MaxClockSpeed:  result.MaxClockSpeed,
	}, nil
}

func getCpuInfoFreeBSD(conn shared.Connection) (*cpuInfo, error) {
	cmd, err := conn.RunCommand("sysctl -n hw.model kern.smp.cores")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("sysctl failed: %s", string(stderr))
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("unexpected sysctl output: %s", string(data))
	}

	model := strings.TrimSpace(lines[0])
	cores, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kern.smp.cores: %w", err)
	}

	// FreeBSD doesn't expose socket/package count directly; default to 1
	info := &cpuInfo{
		Model:          model,
		Cores:          cores,
		ProcessorCount: 1,
	}

	// Extract manufacturer from model string
	if strings.Contains(model, "Intel") {
		info.Manufacturer = "Intel"
	} else if strings.Contains(model, "AMD") {
		info.Manufacturer = "AMD"
	}

	return info, nil
}

func getCpuInfoAIX(conn shared.Connection) (*cpuInfo, error) {
	// Use prtconf for processor type
	cmd, err := conn.RunCommand("prtconf")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("prtconf failed: %s", string(stderr))
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	info := &cpuInfo{
		Manufacturer:   "IBM",
		ProcessorCount: 1,
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, ":"); ok {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			switch k {
			case "Processor Type":
				info.Model = v
			}
		}
	}

	// Use lsdev to count physical processor devices (proc0, proc1, ...).
	// prtconf's "Number Of Processors" can report virtual/logical processors
	// on SMT-enabled POWER systems, so lsdev is more reliable for core count.
	cmd, err = conn.RunCommand("lsdev -Cc processor")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("lsdev failed: %s", string(stderr))
	}

	lsdevData, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	var cores int64
	for _, line := range strings.Split(strings.TrimSpace(string(lsdevData)), "\n") {
		if strings.HasPrefix(line, "proc") {
			cores++
		}
	}
	if cores > 0 {
		info.Cores = cores
	}

	return info, nil
}

// psrinfo reports the core count only when the socket has more than one, and
// uses the singular "core" for exactly one. A socket line without a core count
// therefore describes a single-core package.
//
//	The physical processor has 4 cores and 8 virtual processors (0-7)
//	The physical processor has 1 core and 2 virtual processors (0 1)
//	The physical processor has 1 virtual processor (0)
var solarisCoreCountRegex = regexp.MustCompile(`\bhas (\d+) cores?\b`)

// solarisSocketCores returns the number of physical cores described by a single
// "The physical processor has ..." line from psrinfo -pv.
func solarisSocketCores(line string) int64 {
	m := solarisCoreCountRegex.FindStringSubmatch(line)
	if m == nil {
		// no core count printed => the socket has a single core
		return 1
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 1
	}
	return n
}

func getCpuInfoSolaris(conn shared.Connection) (*cpuInfo, error) {
	// psrinfo -pv gives per-physical-processor details including model.
	// Example output:
	//   The physical processor has 4 cores and 8 virtual processors (0-7)
	//     x86 (GenuineIntel 206D7 family 6 model 45 step 7 clock 2600 MHz)
	//       Intel(r) Xeon(r) CPU E5-2670 0 @ 2.60GHz
	cmd, err := conn.RunCommand("psrinfo -pv")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("psrinfo failed: %s", string(stderr))
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	info := &cpuInfo{}
	var totalCores int64
	var sockets int64

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)

		// "The physical processor has N cores and M virtual processors (...)"
		if strings.HasPrefix(trimmed, "The physical processor has") {
			sockets++
			totalCores += solarisSocketCores(trimmed)
		}

		// The indented model line (deepest indent, no parens) e.g.:
		//       Intel(r) Xeon(r) CPU E5-2670 0 @ 2.60GHz
		if info.Model == "" && !strings.HasPrefix(trimmed, "The ") &&
			!strings.HasPrefix(trimmed, "x86 ") && !strings.HasPrefix(trimmed, "sparc ") &&
			trimmed != "" && !strings.HasPrefix(trimmed, "(") {
			info.Model = trimmed
		}
	}

	if sockets > 0 {
		info.ProcessorCount = sockets
	} else {
		info.ProcessorCount = 1
	}
	info.Cores = totalCores

	// Extract manufacturer from model string
	if strings.Contains(info.Model, "Intel") {
		info.Manufacturer = "Intel"
	} else if strings.Contains(info.Model, "AMD") {
		info.Manufacturer = "AMD"
	} else if strings.Contains(info.Model, "SPARC") || strings.Contains(info.Model, "sparc") {
		info.Manufacturer = "Oracle"
	}

	return info, nil
}

// parseLscpuOutput runs lscpu and extracts manufacturer and model name.
// This is used as a fallback when /proc/cpuinfo lacks these fields (common on ARM).
func parseLscpuOutput(conn shared.Connection) (*cpuInfo, error) {
	cmd, err := conn.RunCommand("lscpu")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("lscpu failed: %s", string(stderr))
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	info := &cpuInfo{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			switch k {
			case "Vendor ID":
				info.Manufacturer = normalizeManufacturer(v)
			case "Model name":
				info.Model = v
			}
		}
	}

	return info, nil
}

// normalizeManufacturer maps CPUID vendor strings to human-readable names.
func normalizeManufacturer(vendor string) string {
	switch vendor {
	case "GenuineIntel":
		return "Intel"
	case "AuthenticAMD":
		return "AMD"
	default:
		return vendor
	}
}
