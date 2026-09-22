// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

// This file reads each Sharing panel toggle from the setting that backs it.
// It is the fallback for macOS 26 and later, where `system_profiler
// SPSharingDataType` exits 0 and prints nothing. Every source here is readable
// without root, and each one is the setting the corresponding System Settings
// toggle writes.
//
// The per-user toggles (Bluetooth Sharing, Media Sharing, AirPlay Receiver)
// are read with `defaults` as the user running the scan, which is the same
// view system_profiler gave on the releases that still have it.

// launchdOverridesCmd lists the enabled/disabled overrides launchd holds for
// system services. Sharing toggles that start a daemon (Screen Sharing, File
// Sharing, DVD or CD Sharing) are recorded here.
const launchdOverridesCmd = "launchctl print-disabled system"

// launchDaemonsDir is where the system daemons behind the Sharing toggles are
// defined. A daemon's plist carries its default Disabled state, which applies
// when launchd holds no override for it.
const launchDaemonsDir = "/System/Library/LaunchDaemons"

// remoteManagementStateFile is written by the Remote Management (ARD)
// service: it contains "enabled" while the service is on. The file does not
// exist on a Mac where Remote Management was never turned on.
const remoteManagementStateFile = "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd"

// natPlist holds the Internet Sharing configuration. NAT.Enabled is 1 while
// Internet Sharing is on. The file does not exist until Internet Sharing is
// configured for the first time.
const natPlist = "/Library/Preferences/SystemConfiguration/com.apple.nat.plist"

// assetCachePlist holds the Content Caching configuration. Activated is true
// while Content Caching is on.
const assetCachePlist = "/Library/Preferences/com.apple.AssetCache.plist"

// launchdOverrideRegex matches one entry of `launchctl print-disabled`:
//
//	"com.apple.screensharing" => disabled
//
// macOS 11 and later print enabled/disabled; earlier releases printed
// false/true, where true meant disabled.
var launchdOverrideRegex = regexp.MustCompile(`^\s*"([^"]+)"\s*=>\s*(enabled|disabled|true|false)\s*$`)

// parseLaunchdOverrides maps each service label to whether its override
// enables it.
func parseLaunchdOverrides(stdout string) map[string]bool {
	out := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		m := launchdOverrideRegex.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		out[m[1]] = m[2] == "enabled" || m[2] == "false"
	}
	return out
}

// errDefaultsKeyMissing reports that `defaults read` found no value for the
// key. For the Sharing toggles that means the user never changed the setting,
// so the caller substitutes the macOS default.
var errDefaultsKeyMissing = errors.New("defaults key not set")

// sharingSources reads individual Sharing panel toggles. One instance serves
// all fields of a macos.sharing resource, so `launchctl print-disabled` runs
// at most once per scan.
type sharingSources struct {
	conn shared.Connection

	lock      sync.Mutex
	overrides map[string]bool
}

// flag returns the state of one Sharing panel toggle, keyed by the name the
// Sharing panel shows for it.
func (s *sharingSources) flag(name string) (bool, error) {
	switch name {
	case "Screen Sharing":
		return s.launchdService("com.apple.screensharing")
	case "File Sharing":
		return s.launchdService("com.apple.smbd")
	case "DVD or CD Sharing":
		return s.launchdService("com.apple.ODSAgent")
	case "Remote Management":
		return s.remoteManagement()
	case "Printer Sharing":
		return s.printerSharing()
	case "Internet Sharing":
		return s.plistFlag(natPlist, "NAT", "Enabled")
	case "Content Caching":
		return s.plistFlag(assetCachePlist, "Activated")
	case "Bluetooth Sharing":
		// Off unless the user turned it on.
		return s.defaultsFlag(false, "-currentHost", "com.apple.Bluetooth", "PrefKeyServicesEnabled")
	case "Media Sharing":
		// Media Sharing is on when either home sharing or sharing with guests
		// is on. Both are off unless the user turned them on.
		home, err := s.defaultsFlag(false, "", "com.apple.amp.mediasharingd", "home-sharing-enabled")
		if err != nil {
			return false, err
		}
		public, err := s.defaultsFlag(false, "", "com.apple.amp.mediasharingd", "public-sharing-enabled")
		if err != nil {
			return false, err
		}
		return home || public, nil
	case "AirPlay Receiver":
		// AirPlay Receiver is on by default; the key is written only once the
		// user changes it. (The key name's spelling is Apple's.)
		return s.defaultsFlag(true, "-currentHost", "com.apple.controlcenter", "AirplayRecieverEnabled")
	}
	return false, fmt.Errorf("no source for Sharing panel entry %q", name)
}

// launchdService reports whether launchd will run the named system service:
// its override if launchd holds one, otherwise the Disabled key in the
// daemon's own plist. A daemon that is not installed is not running.
func (s *sharingSources) launchdService(label string) (bool, error) {
	overrides, err := s.launchdOverrides()
	if err != nil {
		return false, err
	}
	if enabled, ok := overrides[label]; ok {
		return enabled, nil
	}

	data, err := s.readPlist(path.Join(launchDaemonsDir, label+".plist"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	disabled, _ := data["Disabled"].(bool)
	return !disabled, nil
}

func (s *sharingSources) launchdOverrides() (map[string]bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.overrides != nil {
		return s.overrides, nil
	}

	stdout, err := s.run(launchdOverridesCmd)
	if err != nil {
		return nil, err
	}
	s.overrides = parseLaunchdOverrides(stdout)
	return s.overrides, nil
}

func (s *sharingSources) remoteManagement() (bool, error) {
	f, err := s.conn.FileSystem().Open(remoteManagementStateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	content, err := io.ReadAll(f)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(content)) == "enabled", nil
}

// printerSharing reads the CUPS server setting that the Printer Sharing
// toggle writes.
func (s *sharingSources) printerSharing() (bool, error) {
	stdout, err := s.run("cupsctl")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(stdout, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key == "_share_printers" {
			return value == "1", nil
		}
	}
	return false, errors.New("cupsctl did not report _share_printers")
}

// plistFlag reads a boolean or 0/1 value from a preferences plist. A missing
// file or key means the setting was never turned on.
func (s *sharingSources) plistFlag(file string, keyPath ...string) (bool, error) {
	data, err := s.readPlist(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	var cur any = map[string]any(data)
	for _, k := range keyPath {
		m, ok := cur.(map[string]any)
		if !ok {
			return false, nil
		}
		cur, ok = m[k]
		if !ok {
			return false, nil
		}
	}
	switch v := cur.(type) {
	case bool:
		return v, nil
	case float64:
		return v != 0, nil
	}
	return false, fmt.Errorf("%s: %s is neither a boolean nor a number", file, strings.Join(keyPath, "."))
}

// defaultsFlag reads a 0/1 preference with `defaults read`, as the user
// running the scan. A key that was never written yields def.
func (s *sharingSources) defaultsFlag(def bool, hostFlag string, domain string, key string) (bool, error) {
	cmd := "defaults "
	if hostFlag != "" {
		cmd += hostFlag + " "
	}
	cmd += "read " + domain + " " + key

	stdout, err := s.run(cmd)
	if errors.Is(err, errDefaultsKeyMissing) {
		return def, nil
	}
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(stdout) {
	case "1", "true", "YES":
		return true, nil
	case "0", "false", "NO":
		return false, nil
	}
	return false, fmt.Errorf("%s: unexpected value %q", cmd, strings.TrimSpace(stdout))
}

func (s *sharingSources) readPlist(file string) (plist.Data, error) {
	f, err := s.conn.FileSystem().Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return plist.Decode(f)
}

// run executes a command and returns its stdout. `defaults read` reports an
// unset key with exit 1 and "does not exist" on stderr; that case comes back
// as errDefaultsKeyMissing so callers can apply the default.
func (s *sharingSources) run(command string) (string, error) {
	cmd, err := s.conn.RunCommand(command)
	if err != nil {
		return "", err
	}
	stdout, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		if strings.HasPrefix(command, "defaults ") && strings.Contains(string(stderr), "does not exist") {
			return "", errDefaultsKeyMissing
		}
		return "", fmt.Errorf("%s failed (exit %d): %s", command, cmd.ExitStatus, strings.TrimSpace(string(stderr)))
	}
	return string(stdout), nil
}
