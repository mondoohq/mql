// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// SolarisSmbiosManager reads the SMBIOS tables of an x86 Solaris or illumos
// system with smbios(8), which needs no privileges. SPARC systems have no
// SMBIOS and no smbios command.
type SolarisSmbiosManager struct {
	provider shared.Connection
}

func (s *SolarisSmbiosManager) Name() string {
	return "Solaris Smbios Manager"
}

// Info reads SMBIOS on x86. SPARC has no SMBIOS, so when smbios fails or
// names no system, the platform identity comes from the firmware device tree
// and prtdiag instead (see sparcInfo).
func (s *SolarisSmbiosManager) Info() (*SmBiosInfo, error) {
	info, smbiosErr := s.smbiosInfo()
	if smbiosErr == nil && (info.SysInfo.Vendor != "" || info.SysInfo.Model != "") {
		return info, nil
	}

	fallback := s.sparcInfo()
	if fallback == nil {
		if smbiosErr != nil {
			return nil, smbiosErr
		}
		return info, nil
	}
	if info == nil {
		return fallback, nil
	}
	// keep whatever smbios did report (an empty system structure can still
	// come with BIOS or chassis data)
	info.SysInfo = fallback.SysInfo
	if info.BIOS.Version == "" {
		info.BIOS = fallback.BIOS
	}
	if info.ChassisInfo.SerialNumber == "" {
		info.ChassisInfo.SerialNumber = fallback.ChassisInfo.SerialNumber
	}
	return info, nil
}

func (s *SolarisSmbiosManager) smbiosInfo() (*SmBiosInfo, error) {
	cmd, err := s.provider.RunCommand("/usr/sbin/smbios")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, errors.New("failed to run smbios: " + strings.TrimSpace(string(stderr)))
	}
	return ParseSolarisSmbios(cmd.Stdout)
}

// sneepPaths are where Oracle's sneep tool is installed: /usr/sbin on
// Solaris 11, /opt/SUNWsneep/bin on Solaris 10.
var sneepPaths = []string{"/usr/sbin/sneep", "/opt/SUNWsneep/bin/sneep"}

// sparcInfo reads the platform identity of a system without SMBIOS. All of
// it is available without privileges:
//
//   - `prtconf -vb` prints the root node of the firmware device tree: the
//     platform name (ORCL,SPARC-T4-2), its marketing name (banner-name), the
//     architecture (compatible), and the OpenBoot PROM version.
//   - prtdiag's first line names the manufacturer:
//     "System Configuration:  Oracle Corporation  sun4v SPARC T4-2".
//   - sneep prints the chassis serial number, when it is installed and a
//     serial was stored. SPARC firmware exposes no serial otherwise, so the
//     serial stays empty without it.
//
// It returns nil when neither command names the system.
func (s *SolarisSmbiosManager) sparcInfo() *SmBiosInfo {
	var root SolarisPrtconfRoot
	if out, ok := s.run("/usr/sbin/prtconf -vb"); ok {
		root = ParseSolarisPrtconfRoot(out)
	}
	// x86 firmware reports i86pc, which names no system
	if root.Name == "i86pc" {
		root = SolarisPrtconfRoot{}
	}

	var diag SolarisPrtdiagConfig
	// prtdiag exits non-zero when it finds a failed component but still
	// prints the configuration, so its output counts regardless of status
	if cmd, err := s.provider.RunCommand("/usr/sbin/prtdiag"); err == nil {
		out, _ := io.ReadAll(cmd.Stdout)
		diag = ParseSolarisPrtdiagConfig(string(out))
	}

	info := &SmBiosInfo{}
	info.SysInfo.Vendor = diag.Manufacturer
	if info.SysInfo.Vendor == "" {
		info.SysInfo.Vendor = solarisVendorFromName(root.Name)
	}
	info.SysInfo.Model = firstNonEmpty(root.BannerName, diag.Product, root.Model, root.Name)
	info.SysInfo.SKU = root.Name
	info.SysInfo.Family = firstNonEmpty(root.Compatible, diag.Architecture)
	info.BIOS.Version = root.FirmwareVersion
	if info.BIOS.Version != "" {
		info.BIOS.Vendor = info.SysInfo.Vendor
	}
	if info.SysInfo.Vendor == "" && info.SysInfo.Model == "" {
		return nil
	}

	serial := s.sneepSerial()
	info.SysInfo.SerialNumber = serial
	info.ChassisInfo.SerialNumber = serial
	return info
}

// sneepSerial returns the chassis serial number sneep stored, or "" when
// sneep is not installed or knows none.
func (s *SolarisSmbiosManager) sneepSerial() string {
	if !s.provider.Capabilities().Has(shared.Capability_File) {
		return ""
	}
	fs := s.provider.FileSystem()
	for _, path := range sneepPaths {
		if _, err := fs.Stat(path); err != nil {
			continue
		}
		out, ok := s.run(path)
		if !ok {
			return ""
		}
		return ParseSneepSerial(out)
	}
	return ""
}

// run returns the output of a command that succeeded.
func (s *SolarisSmbiosManager) run(command string) (string, bool) {
	cmd, err := s.provider.RunCommand(command)
	if err != nil || cmd.ExitStatus != 0 {
		return "", false
	}
	out, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", false
	}
	return string(out), true
}

// SolarisPrtconfRoot holds the root node properties `prtconf -vb` prints.
type SolarisPrtconfRoot struct {
	// Name is the platform name, for example ORCL,SPARC-T4-2
	Name string
	// BannerName is the marketing name, for example SPARC T4-2
	BannerName string
	// Model is the model property, which not every platform sets
	Model string
	// Compatible is the platform architecture, for example sun4v
	Compatible string
	// FirmwareVersion is the OpenBoot PROM version, for example
	// OBP 4.33.0.b 2011/05/16 16:26
	FirmwareVersion string
}

// ParseSolarisPrtconfRoot reads `prtconf -b` or `prtconf -vb` output:
//
//	name:  ORCL,SPARC-T3-4
//	banner-name:  SPARC T3-4
//	compatible: 'sun4v'
//	openprom version: 'OBP 4.33.0.b 2011/05/16 16:26'
func ParseSolarisPrtconfRoot(out string) SolarisPrtconfRoot {
	var root SolarisPrtconfRoot
	fields := map[string]*string{
		"name":             &root.Name,
		"banner-name":      &root.BannerName,
		"model":            &root.Model,
		"compatible":       &root.Compatible,
		"openprom version": &root.FirmwareVersion,
	}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		dst, ok := fields[strings.TrimSpace(key)]
		if !ok || *dst != "" {
			continue
		}
		value = strings.TrimSpace(value)
		// compatible can list several values: 'sun4v' + 'SUNW,sun4v'
		if strings.HasPrefix(value, "'") {
			if end := strings.Index(value[1:], "'"); end >= 0 {
				value = value[1 : end+1]
			}
		}
		*dst = value
	}
	return root
}

// SolarisPrtdiagConfig holds what prtdiag's "System Configuration" line names.
type SolarisPrtdiagConfig struct {
	Manufacturer string
	Architecture string
	Product      string
}

// ParseSolarisPrtdiagConfig reads the first line of prtdiag on SPARC, where
// the manufacturer is followed by the platform architecture and the product:
//
//	System Configuration:  Oracle Corporation  sun4v Sun Fire T200
//
// x86 systems print no architecture there, which leaves the manufacturer
// and product indistinguishable, so such a line yields nothing.
func ParseSolarisPrtdiagConfig(out string) SolarisPrtdiagConfig {
	var cfg SolarisPrtdiagConfig
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "System Configuration:")
		if !ok {
			continue
		}
		fs := strings.Fields(rest)
		for i, f := range fs {
			if !strings.HasPrefix(f, "sun4") {
				continue
			}
			cfg.Manufacturer = strings.Join(fs[:i], " ")
			cfg.Architecture = f
			cfg.Product = strings.Join(fs[i+1:], " ")
			break
		}
		break
	}
	return cfg
}

// ParseSneepSerial reads sneep's output, a single serial number, or
// "unknown" when none was stored.
func ParseSneepSerial(out string) string {
	serial := strings.TrimSpace(out)
	if serial == "" || strings.EqualFold(serial, "unknown") || strings.ContainsAny(serial, " \t\n") {
		return ""
	}
	return serial
}

// solarisVendorFromName names the manufacturer from the stock-ticker prefix
// of a SPARC platform name, for when prtdiag is unavailable.
func solarisVendorFromName(name string) string {
	prefix, _, ok := strings.Cut(name, ",")
	if !ok {
		return ""
	}
	switch prefix {
	case "ORCL":
		return "Oracle Corporation"
	case "SUNW":
		return "Sun Microsystems"
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ParseSolarisSmbios reads smbios(8) output. Each structure starts with an
// `ID SIZE TYPE` header followed by a line naming its type
// (`256   73   SMB_TYPE_SYSTEM (system information)`) and indented
// `Key: value` lines. Only the first structure of each type is used, which is
// what /sys/class/dmi/id reports on Linux too.
func ParseSolarisSmbios(r io.Reader) (*SmBiosInfo, error) {
	smInfo := &SmBiosInfo{}
	fields := map[string]map[string]*string{
		"SMB_TYPE_BIOS": {
			"Vendor":         &smInfo.BIOS.Vendor,
			"Version String": &smInfo.BIOS.Version,
			"Release Date":   &smInfo.BIOS.ReleaseDate,
		},
		"SMB_TYPE_SYSTEM": {
			"Manufacturer":  &smInfo.SysInfo.Vendor,
			"Product":       &smInfo.SysInfo.Model,
			"Version":       &smInfo.SysInfo.Version,
			"Serial Number": &smInfo.SysInfo.SerialNumber,
			"UUID":          &smInfo.SysInfo.UUID,
			"Family":        &smInfo.SysInfo.Family,
			"SKU Number":    &smInfo.SysInfo.SKU,
		},
		"SMB_TYPE_BASEBOARD": {
			"Manufacturer":  &smInfo.BaseBoardInfo.Vendor,
			"Product":       &smInfo.BaseBoardInfo.Model,
			"Version":       &smInfo.BaseBoardInfo.Version,
			"Serial Number": &smInfo.BaseBoardInfo.SerialNumber,
			"Asset Tag":     &smInfo.BaseBoardInfo.AssetTag,
		},
		"SMB_TYPE_CHASSIS": {
			"Manufacturer":  &smInfo.ChassisInfo.Vendor,
			"Version":       &smInfo.ChassisInfo.Version,
			"Serial Number": &smInfo.ChassisInfo.SerialNumber,
			"Asset Tag":     &smInfo.ChassisInfo.AssetTag,
			"Chassis Type":  &smInfo.ChassisInfo.Type,
		},
	}

	var current map[string]*string
	seen := map[string]bool{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		fs := strings.Fields(line)

		// structure header: "<id> <size> SMB_TYPE_... (description)"
		if len(fs) >= 3 && strings.HasPrefix(fs[2], "SMB_TYPE_") {
			current = nil
			if f, ok := fields[fs[2]]; ok && !seen[fs[2]] {
				seen[fs[2]] = true
				current = f
			}
			continue
		}
		if current == nil {
			continue
		}

		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		dst, ok := current[key]
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if key == "Chassis Type" {
			value = solarisChassisType(value)
		}
		*dst = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return smInfo, nil
}

// solarisChassisType turns "0x1 (other)" into the decimal SMBIOS code "1",
// which is how Linux reports chassis_type.
func solarisChassisType(value string) string {
	code, _, _ := strings.Cut(value, " ")
	n, err := strconv.ParseInt(strings.TrimPrefix(code, "0x"), 16, 64)
	if err != nil {
		return value
	}
	return strconv.FormatInt(n, 10)
}
