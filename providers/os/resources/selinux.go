// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type mqlSelinuxInternal struct {
	configParsed    bool
	cfgMode         string
	cfgType         string
	getenforced     bool
	getenforceMode  string
	getenforceAvail bool
	lock            sync.Mutex
}

func (s *mqlSelinux) id() (string, error) {
	return "selinux", nil
}

func (s *mqlSelinuxBoolean) id() (string, error) {
	return "selinux.boolean:" + s.Name.Data, nil
}

func (s *mqlSelinuxModule) id() (string, error) {
	return "selinux.module:" + s.Name.Data, nil
}

// getenforceCmd runs getenforce from /usr/sbin, where libselinux installs it
// on every distribution, before searching PATH. A non-root PATH on Debian has
// no sbin directory, and getenforce needs no privileges.
const getenforceCmd = "/usr/sbin/getenforce 2>/dev/null || getenforce"

// selinuxfsPath is where the kernel exposes SELinux while it is enabled.
const selinuxfsPath = "/sys/fs/selinux"

// fetchGetenforce runs getenforce once and caches the result.
// Uses double-checked locking (same pattern as apparmor.fetchStatus):
// the first unlocked check is the fast path for already-cached results,
// the second check inside the lock guards against concurrent first calls.
func (s *mqlSelinux) fetchGetenforce() (available bool, mode string, err error) {
	if s.getenforced {
		return s.getenforceAvail, s.getenforceMode, nil
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.getenforced {
		return s.getenforceAvail, s.getenforceMode, nil
	}

	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		s.getenforced = true
		return false, "", nil
	}

	o, err := CreateResource(s.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(getenforceCmd),
	})
	if err != nil {
		s.getenforced = true
		return false, "", err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		s.getenforced = true
		s.getenforceAvail = false
		return false, "", nil
	}

	s.getenforceAvail = true
	s.getenforceMode = strings.ToLower(strings.TrimSpace(cmd.Stdout.Data))
	s.getenforced = true
	return s.getenforceAvail, s.getenforceMode, nil
}

func (s *mqlSelinux) installed() (bool, error) {
	// Try command-based detection first (gives us runtime mode too)
	avail, _, err := s.fetchGetenforce()
	if err != nil {
		return false, err
	}
	if avail {
		return true, nil
	}
	// Fall back to checking /etc/selinux/config for disk scan scenarios
	// where command execution is not available
	if err := s.parseConfig(); err != nil {
		return false, err
	}
	return s.cfgMode != "", nil
}

func (s *mqlSelinux) mode() (string, error) {
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		// A disk or image scan has no running kernel, so the configured
		// mode is the only answer.
		if err := s.parseConfig(); err != nil {
			return "", err
		}
		return s.cfgMode, nil
	}

	avail, mode, err := s.fetchGetenforce()
	if err != nil {
		return "", err
	}
	if avail {
		return mode, nil
	}

	// Without getenforce, the kernel's selinuxfs answers. The configured mode
	// does not: SELINUX=permissive in /etc/selinux/config on a host booted
	// with SELinux disabled is not what the kernel enforces.
	fs := conn.FileSystem()
	present, err := afero.DirExists(fs, selinuxfsPath)
	if err != nil {
		return "", err
	}
	var enforce []byte
	if present {
		enforce, err = afero.ReadFile(fs, selinuxfsPath+"/enforce")
		if err != nil {
			return "", fmt.Errorf("could not read SELinux mode from %s/enforce: %w", selinuxfsPath, err)
		}
	}
	if err := s.parseConfig(); err != nil {
		return "", err
	}
	return selinuxRuntimeMode(present, enforce, s.cfgMode)
}

// selinuxRuntimeMode reports the mode a live kernel enforces from selinuxfs:
// its enforce file holds "1" for enforcing and "0" for permissive, and the
// file system is not there while SELinux is disabled. A host that does not
// have SELinux at all (no configured mode) keeps an empty mode.
func selinuxRuntimeMode(selinuxfsPresent bool, enforce []byte, configMode string) (string, error) {
	if !selinuxfsPresent {
		if configMode == "" {
			return "", nil
		}
		return "disabled", nil
	}
	switch strings.TrimSpace(string(enforce)) {
	case "1":
		return "enforcing", nil
	case "0":
		return "permissive", nil
	}
	return "", fmt.Errorf("unexpected SELinux enforce value %q", strings.TrimSpace(string(enforce)))
}

// parseConfig reads /etc/selinux/config and extracts SELINUX= and SELINUXTYPE= values.
// Uses double-checked locking (same pattern as fetchGetenforce above).
func (s *mqlSelinux) parseConfig() error {
	if s.configParsed {
		return nil
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.configParsed {
		return nil
	}

	fileRes, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData("/etc/selinux/config"),
	})
	if err != nil {
		s.configParsed = true
		return err
	}
	f := fileRes.(*mqlFile)
	exists := f.GetExists()
	if exists.Error != nil || !exists.Data {
		s.configParsed = true
		return nil
	}

	content := f.GetContent()
	if content.Error != nil {
		s.configParsed = true
		return content.Error
	}

	mode, policyType := ParseSelinuxConfig(content.Data)
	s.cfgMode = mode
	s.cfgType = policyType
	s.configParsed = true
	return nil
}

// ParseSelinuxConfig extracts SELINUX and SELINUXTYPE from /etc/selinux/config content.
func ParseSelinuxConfig(content string) (mode string, policyType string) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "SELINUX":
			mode = value
		case "SELINUXTYPE":
			policyType = value
		}
	}
	return mode, policyType
}

func (s *mqlSelinux) configMode() (string, error) {
	if err := s.parseConfig(); err != nil {
		return "", err
	}
	return s.cfgMode, nil
}

func (s *mqlSelinux) policyType() (string, error) {
	if err := s.parseConfig(); err != nil {
		return "", err
	}
	return s.cfgType, nil
}

// SELinuxBool represents a parsed getsebool entry.
type SELinuxBool struct {
	Name  string
	Value bool
}

// ParseGetsebool parses the output of "getsebool -a" (format: "name --> on/off").
func ParseGetsebool(output string) []SELinuxBool {
	var bools []SELinuxBool
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: "name --> on" or "name --> off"
		parts := strings.SplitN(line, "-->", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		bools = append(bools, SELinuxBool{
			Name:  name,
			Value: val == "on",
		})
	}
	return bools
}

func (s *mqlSelinux) booleans() ([]any, error) {
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, nil
	}

	var parsed []SELinuxBool
	if conn.Capabilities().Has(shared.Capability_RunCommand) {
		o, err := CreateResource(s.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData("getsebool -a"),
		})
		if err == nil {
			cmd := o.(*mqlCommand)
			if exit := cmd.GetExitcode(); exit.Data == 0 {
				parsed = ParseGetsebool(cmd.Stdout.Data)
			}
		}
	}

	// Fall back to /sys/fs/selinux/booleans/ directory (each file contains
	// "1" or "0" for the boolean's current value)
	if parsed == nil {
		parsed = readSelinuxBooleansFromFS(conn.FileSystem())
	}

	if parsed == nil {
		return nil, nil
	}

	res := make([]any, 0, len(parsed))
	for _, b := range parsed {
		r, err := CreateResource(s.MqlRuntime, "selinux.boolean", map[string]*llx.RawData{
			"name":  llx.StringData(b.Name),
			"value": llx.BoolData(b.Value),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// readSelinuxBooleansFromFS reads boolean values from /sys/fs/selinux/booleans/.
// Each file in that directory contains "1" (on) or "0" (off).
func readSelinuxBooleansFromFS(fs afero.Fs) []SELinuxBool {
	const dir = "/sys/fs/selinux/booleans"
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		return nil
	}
	var bools []SELinuxBool
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := afero.ReadFile(fs, filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		bools = append(bools, SELinuxBool{
			Name:  entry.Name(),
			Value: selinuxBooleanFileValue(data),
		})
	}
	return bools
}

// selinuxBooleanFileValue reads a /sys/fs/selinux/booleans/<name> file, which
// holds the current and the pending value ("1 1", "0 0", or "0 1" while a
// change is pending). The first is what the kernel enforces.
func selinuxBooleanFileValue(data []byte) bool {
	current, _, _ := strings.Cut(strings.TrimSpace(string(data)), " ")
	return current == "1"
}

// SELinuxModule represents a parsed semodule entry.
type SELinuxModule struct {
	Name   string
	Status string
	// Priority is nil when the listing does not show it (semodule -l).
	Priority *int
}

// semoduleListCmd lists every module with its priority and whether it is
// disabled. semodule -l omits disabled modules and priorities since
// policycoreutils 2.4 (RHEL 7 prints the module version instead), so it is
// only the fallback for a semodule that predates --list-modules=full.
const semoduleListCmd = "semodule --list-modules=full 2>/dev/null || semodule -l"

// ParseSemodule parses semodule module listings:
//
//	400 sweeppol          pp
//	100 zosremote         pp  disabled
//
// from `semodule --list-modules=full` (priority, name, language, and
// "disabled" for a disabled module), and from `semodule -l` either the bare
// name, or the name and version followed by "Disabled" on older releases.
func ParseSemodule(output string) []SELinuxModule {
	var modules []SELinuxModule
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}

		var m SELinuxModule
		rest := fields[1:]
		if priority, err := strconv.Atoi(fields[0]); err == nil && len(fields) >= 2 {
			m.Priority = &priority
			m.Name = fields[1]
			rest = fields[2:]
		} else {
			m.Name = fields[0]
		}

		m.Status = "enabled"
		for _, f := range rest {
			if strings.EqualFold(f, "disabled") {
				m.Status = "disabled"
			}
		}
		modules = append(modules, m)
	}
	return modules
}

func (s *mqlSelinux) modules() ([]any, error) {
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, nil
	}

	o, err := CreateResource(s.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(semoduleListCmd),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		return nil, nil
	}

	parsed := ParseSemodule(cmd.Stdout.Data)
	res := make([]any, 0, len(parsed))
	for _, m := range parsed {
		r, err := CreateResource(s.MqlRuntime, "selinux.module", map[string]*llx.RawData{
			"name":     llx.StringData(m.Name),
			"status":   llx.StringData(m.Status),
			"priority": llx.IntDataPtr(m.Priority),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}
