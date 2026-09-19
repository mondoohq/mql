// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
)

// socketfilterfw is Apple's command line front end for the application
// firewall. Its read-only getters work without root, and unlike the
// preference plist it reports the state the firewall is actually running
// with rather than what was last written to disk.
const socketfilterfwPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// globalStateRegex pulls the numeric state out of `socketfilterfw
// --getglobalstate`, which prints e.g. "Firewall is enabled. (State = 1)".
// The number is the same value the plist stores under "globalstate": 0 off,
// 1 on, 2 blocking all incoming connections.
var globalStateRegex = regexp.MustCompile(`\(State\s*=\s*(\d+)\)`)

// errFirewallStateUnavailable reports that neither source could answer. It is
// deliberately an error rather than a false: "the firewall is off" and "we
// could not read the firewall" are different findings, and reporting the
// second as the first is how a disabled firewall passes an audit.
var errFirewallStateUnavailable = errors.New(
	"cannot determine application firewall state: no ALF preferences file and socketfilterfw did not return a readable answer")

// runSocketfilterfw runs one socketfilterfw getter and returns its stdout.
func (m *mqlMacosFirewall) runSocketfilterfw(flag string) (string, error) {
	res, err := NewResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(socketfilterfwPath + " " + flag),
	})
	if err != nil {
		return "", err
	}
	cmd := res.(*mqlCommand)
	return commandOutput(cmd, "socketfilterfw "+flag)
}

// parseGlobalState reads the numeric state out of --getglobalstate output.
func parseGlobalState(stdout string) (int64, bool) {
	if m := globalStateRegex.FindStringSubmatch(stdout); m != nil {
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err == nil {
			return v, true
		}
	}
	// Older releases print the sentence without the "(State = N)" suffix.
	switch {
	case strings.Contains(stdout, "Firewall is enabled"):
		return 1, true
	case strings.Contains(stdout, "Firewall is disabled"):
		return 0, true
	}
	return 0, false
}

// toggleOnRegex and toggleOffRegex anchor on the two sentence shapes
// socketfilterfw uses for a toggle:
//
//	"Firewall stealth mode is on"                     (--getstealthmode)
//	"Log mode is off"                                 (--getloggingmode)
//	"Firewall has block all state set to disabled."   (--getblockall)
//
// They deliberately do not match a bare "enabled."/"disabled." anywhere in the
// line. That suffix appears in replies that are not toggles at all -- the
// --getallowsigned lines end in "signed software ENABLED." -- so accepting it
// would let one getter's answer be read as another's.
var (
	toggleOnRegex  = regexp.MustCompile(`\bis on\b|\bset to enabled\b`)
	toggleOffRegex = regexp.MustCompile(`\bis off\b|\bset to disabled\b`)
)

// parseOnOff reads a socketfilterfw toggle sentence. It returns ok=false for
// anything it does not recognise -- notably the "settings cannot be modified
// from command line on managed Mac computers" reply -- so an unreadable
// setting surfaces as an error and never as a confident false.
func parseOnOff(stdout string) (bool, bool) {
	s := strings.ToLower(stdout)
	if strings.Contains(s, "cannot be modified") {
		return false, false
	}
	switch {
	case toggleOnRegex.MatchString(s):
		return true, true
	case toggleOffRegex.MatchString(s):
		return false, true
	}
	return false, false
}

// parseAllowSigned reads the two-line --getallowsigned reply:
//
//	Automatically allow built-in signed software ENABLED.
//	Automatically allow downloaded signed software ENABLED.
//
// It returns the built-in and downloaded flags separately.
func parseAllowSigned(stdout string) (builtin bool, downloaded bool, ok bool) {
	var haveBuiltin, haveDownloaded bool
	for _, line := range strings.Split(stdout, "\n") {
		l := strings.ToLower(line)
		if !strings.Contains(l, "signed software") {
			continue
		}
		enabled := strings.Contains(l, "enabled")
		if strings.Contains(l, "downloaded") {
			downloaded, haveDownloaded = enabled, true
		} else if strings.Contains(l, "built-in") {
			builtin, haveBuiltin = enabled, true
		}
	}
	return builtin, downloaded, haveBuiltin && haveDownloaded
}
