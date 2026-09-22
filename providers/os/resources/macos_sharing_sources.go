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

	"github.com/spf13/afero"
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
// are read from every real user's preference files, and a toggle is on when
// any user has it on. Reading only the scanning user's settings would let a
// root scan -- the usual agent deployment -- report root's untouched defaults
// and pass a Mac where the logged-in user turned the sharing on. Where another
// user's settings are not readable, the toggle is a permission error, never a
// guess.

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

// hardwareUUIDCmd prints the IOPlatformUUID, which names the ByHost
// preference files of the current Mac.
const hardwareUUIDCmd = "ioreg -rd1 -c IOPlatformExpertDevice"

var hardwareUUIDRegex = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

// userPref is one per-user Sharing setting.
type userPref struct {
	// domain is the preferences domain, e.g. com.apple.Bluetooth.
	domain string
	// byHost settings live in ByHost/<domain>.<hardware UUID>.plist.
	byHost bool
	// keys: the setting is on when any of them is on.
	keys []string
	// def is the macOS default, in effect while the user never changed it.
	def bool
}

var (
	bluetoothSharingPref = userPref{domain: "com.apple.Bluetooth", byHost: true, keys: []string{"PrefKeyServicesEnabled"}}
	// Media Sharing is on when home sharing or sharing with guests is on.
	mediaSharingPref = userPref{domain: "com.apple.amp.mediasharingd", keys: []string{"home-sharing-enabled", "public-sharing-enabled"}}
	// AirPlay Receiver is on by default. (The key name's spelling is Apple's.)
	airplayReceiverPref = userPref{domain: "com.apple.controlcenter", byHost: true, keys: []string{"AirplayRecieverEnabled"}, def: true}
)

// sharingSources reads individual Sharing panel toggles. One instance serves
// all fields of a macos.sharing resource, so `launchctl print-disabled` runs
// at most once per scan.
type sharingSources struct {
	conn shared.Connection
	// listUsers enumerates the users whose per-user settings count.
	listUsers func() ([]targetUser, error)
	// fs overrides conn.FileSystem() in tests.
	fs afero.Fs

	lock        sync.Mutex
	overrides   map[string]bool
	overrideErr error
	fetchedOvr  bool
	uuid        string
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
		return s.anyUser(bluetoothSharingPref)
	case "Media Sharing":
		return s.anyUser(mediaSharingPref)
	case "AirPlay Receiver":
		return s.anyUser(airplayReceiverPref)
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
	// A failure is cached too: three fields read the overrides, and a
	// command that failed once is not retried for each of them.
	if s.fetchedOvr {
		return s.overrides, s.overrideErr
	}
	s.fetchedOvr = true

	stdout, err := s.run(launchdOverridesCmd)
	if err != nil {
		s.overrideErr = err
		return nil, err
	}
	s.overrides = parseLaunchdOverrides(stdout)
	return s.overrides, nil
}

func (s *sharingSources) remoteManagement() (bool, error) {
	f, err := s.open(remoteManagementStateFile)
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
	return dataFlag(data, file, keyPath...)
}

// anyUser reports whether any real user has the setting on. A user who never
// changed it has the macOS default. A Mac with no real users has the default.
func (s *sharingSources) anyUser(p userPref) (bool, error) {
	users, err := s.listUsers()
	if err != nil {
		return false, err
	}
	for _, u := range users {
		on, err := s.userFlag(u, p)
		if err != nil {
			return false, err
		}
		if on {
			return true, nil
		}
	}
	if len(users) == 0 {
		return p.def, nil
	}
	return false, nil
}

// userFlag reads one user's setting from their preference file.
func (s *sharingSources) userFlag(u targetUser, p userPref) (bool, error) {
	file := path.Join(u.home, "Library/Preferences", p.domain+".plist")
	if p.byHost {
		uuid, err := s.hardwareUUID()
		if err != nil {
			return false, err
		}
		file = path.Join(u.home, "Library/Preferences/ByHost", p.domain+"."+uuid+".plist")
	}

	data, err := s.readPlist(file)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return p.def, nil
	case errors.Is(err, os.ErrPermission):
		// Wrapped, not flattened, so the error stays recognisable as a
		// permission failure to anything that classifies errors.
		return false, fmt.Errorf("cannot read the Sharing settings of user %s: %w; reading every user's Sharing settings requires root", u.name, err)
	case err != nil:
		return false, err
	}

	set := false
	for _, key := range p.keys {
		if _, ok := data[key]; !ok {
			continue
		}
		set = true
		on, err := dataFlag(data, file, key)
		if err != nil {
			return false, err
		}
		if on {
			return true, nil
		}
	}
	if !set {
		return p.def, nil
	}
	return false, nil
}

// hardwareUUID returns the IOPlatformUUID, read once.
func (s *sharingSources) hardwareUUID() (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.uuid != "" {
		return s.uuid, nil
	}
	stdout, err := s.run(hardwareUUIDCmd)
	if err != nil {
		return "", err
	}
	m := hardwareUUIDRegex.FindStringSubmatch(stdout)
	if m == nil {
		return "", errors.New("ioreg did not report an IOPlatformUUID")
	}
	s.uuid = m[1]
	return s.uuid, nil
}

// dataFlag reads a boolean or 0/1 value at keyPath. A missing key means the
// setting was never turned on. source names the plist in the error.
func dataFlag(data plist.Data, source string, keyPath ...string) (bool, error) {
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
	return false, fmt.Errorf("%s: %s is neither a boolean nor a number", source, strings.Join(keyPath, "."))
}

// open opens a file on the target, through the test override when set.
func (s *sharingSources) open(file string) (afero.File, error) {
	if s.fs != nil {
		return s.fs.Open(file)
	}
	return s.conn.FileSystem().Open(file)
}

func (s *sharingSources) readPlist(file string) (plist.Data, error) {
	f, err := s.open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return plist.Decode(f)
}

// run executes a command and returns its stdout.
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
		return "", fmt.Errorf("%s failed (exit %d): %s", command, cmd.ExitStatus, strings.TrimSpace(string(stderr)))
	}
	return string(stdout), nil
}
