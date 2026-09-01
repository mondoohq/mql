// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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
		"command": llx.StringData("getenforce"),
	})
	if err != nil {
		s.getenforced = true
		return false, "", err
	}
	cmd := o.(*mqlCommand)
	run, cmdErr := commandResult(cmd)
	if cmdErr != nil || run.exitcode != 0 {
		// Either getenforce is absent or the command never ran. Both mean we
		// have no runtime mode to report, so fall through to the
		// /etc/selinux/config read rather than claiming one we never measured.
		s.getenforced = true
		s.getenforceAvail = false
		return false, "", nil
	}

	s.getenforceAvail = true
	s.getenforceMode = strings.ToLower(strings.TrimSpace(run.stdout))
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
	avail, mode, err := s.fetchGetenforce()
	if err != nil {
		return "", err
	}
	if avail {
		return mode, nil
	}
	// Fall back to /sys/fs/selinux/enforce (available on live systems without
	// getenforce in $PATH): contains "1" for enforcing, "0" for permissive.
	if conn, ok := s.MqlRuntime.Connection.(shared.Connection); ok {
		data, err := afero.ReadFile(conn.FileSystem(), "/sys/fs/selinux/enforce")
		if err == nil {
			switch strings.TrimSpace(string(data)) {
			case "1":
				return "enforcing", nil
			case "0":
				return "permissive", nil
			}
		}
	}
	// Fall back to configured mode from /etc/selinux/config (disk scans)
	if err := s.parseConfig(); err != nil {
		return "", err
	}
	return s.cfgMode, nil
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
		// Nothing was read. An empty list would be worse than no list at all:
		// `booleans.none(...)` and `booleans.all(...)` are vacuously true over
		// an empty list, so an unreadable host would pass every assertion. A
		// null list fails them instead.
		s.Booleans.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// read records whether a source answered at all, which is not the same as
	// whether it answered with entries.
	read := false
	var parsed []SELinuxBool
	if conn.Capabilities().Has(shared.Capability_RunCommand) {
		o, err := CreateResource(s.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData("getsebool -a"),
		})
		if err == nil {
			cmd := o.(*mqlCommand)
			// exitcode reads as 0 on a command that never ran, so an errored
			// result must not be parsed as an empty boolean list -- that would
			// also skip the /sys/fs/selinux fallback below.
			if run, cmdErr := commandResult(cmd); cmdErr == nil && run.exitcode == 0 {
				parsed = ParseGetsebool(run.stdout)
				read = true
			}
		}
	}

	// Fall back to /sys/fs/selinux/booleans/ directory (each file contains
	// "1" or "0" for the boolean's current value)
	if len(parsed) == 0 {
		if fsBools, fsRead := readSelinuxBooleansFromFS(conn.FileSystem()); fsRead {
			parsed = fsBools
			read = true
		}
	}

	if !read {
		// Neither getsebool nor selinuxfs answered, so the boolean set is
		// unknown rather than empty.
		s.Booleans.State = plugin.StateIsSet | plugin.StateIsNull
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
//
// The second return value reports whether the directory could be read at all.
// It separates "selinuxfs is not mounted, so we know nothing" from "selinuxfs
// is mounted and exposes no booleans", which the slice alone cannot express.
func readSelinuxBooleansFromFS(fs afero.Fs) ([]SELinuxBool, bool) {
	const dir = "/sys/fs/selinux/booleans"
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		return nil, false
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
		val := strings.TrimSpace(string(data))
		bools = append(bools, SELinuxBool{
			Name:  entry.Name(),
			Value: val == "1",
		})
	}
	return bools, true
}

// SELinuxModule represents a parsed semodule entry.
type SELinuxModule struct {
	Name     string
	Status   string
	Priority int
}

// ParseSemodule parses the output of "semodule -l" (format: "name" or "priority name status").
func ParseSemodule(output string) []SELinuxModule {
	var modules []SELinuxModule
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		switch len(fields) {
		case 1:
			// Simple format: just module name (older semodule versions)
			modules = append(modules, SELinuxModule{
				Name:   fields[0],
				Status: "enabled",
			})
		case 2:
			// "priority name" or "name status"
			if priority, err := strconv.Atoi(fields[0]); err == nil {
				modules = append(modules, SELinuxModule{
					Name:     fields[1],
					Priority: priority,
					Status:   "enabled",
				})
			} else {
				modules = append(modules, SELinuxModule{
					Name:   fields[0],
					Status: fields[1],
				})
			}
		default:
			// "priority name status" or more fields
			if len(fields) >= 3 {
				priority, _ := strconv.Atoi(fields[0])
				modules = append(modules, SELinuxModule{
					Name:     fields[1],
					Priority: priority,
					Status:   fields[2],
				})
			}
		}
	}
	return modules
}

func (s *mqlSelinux) modules() ([]any, error) {
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		// Without command execution the module list was never read. An empty
		// list is vacuously true for `modules.none(...)` and `modules.all(...)`,
		// so report nothing rather than a measurement we never made.
		s.Modules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	o, err := CreateResource(s.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("semodule -l"),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	run, err := commandResult(cmd)
	if err != nil {
		return nil, err
	}
	if run.exitcode != 0 {
		// semodule is absent or refused to answer, so the loaded modules are
		// unknown. Only an exit code of 0 licenses an empty list.
		s.Modules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	parsed := ParseSemodule(run.stdout)
	res := make([]any, 0, len(parsed))
	for _, m := range parsed {
		r, err := CreateResource(s.MqlRuntime, "selinux.module", map[string]*llx.RawData{
			"name":     llx.StringData(m.Name),
			"status":   llx.StringData(m.Status),
			"priority": llx.IntData(int64(m.Priority)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}
