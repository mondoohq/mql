// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (t *mqlSystemdTimesyncd) id() (string, error) {
	return "systemd.timesyncd", nil
}

func (t *mqlSystemdTimesyncd) active() (bool, error) {
	return isSystemdUnitActive(t.MqlRuntime, "systemd-timesyncd")
}

// parseTimedatectlStatusSynchronized extracts the synchronization state from
// the human-readable `timedatectl status` output, used as a fallback on
// systemd versions that lack the `timedatectl show` verb (< 239). The
// relevant line looks like:
//
//	System clock synchronized: yes
//
// systemd 232 and older (Debian 9, Ubuntu 16.04) label the same line
// "NTP synchronized". Both are backed by the org.freedesktop.timedate1
// NTPSynchronized property that `timedatectl show` exposes on newer systemd.
func parseTimedatectlStatusSynchronized(stdout string) bool {
	for _, line := range strings.Split(stdout, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "System clock synchronized", "NTP synchronized":
			return strings.EqualFold(strings.TrimSpace(value), "yes")
		}
	}
	return false
}

// timesyncProperties holds what systemd-timesyncd reports about itself over
// org.freedesktop.timesync1. A nil scalar is a property the daemon did not
// report, such as the server before it has picked one.
type timesyncProperties struct {
	servers          []string
	fallbackServers  []string
	serverName       *string
	serverAddress    *string
	pollIntervalUSec *int64
	leapStatus       *string
}

type timesyncdState struct {
	synchronized bool
	// timesync is nil when systemd-timesyncd is not running, or runs on a
	// systemd release without the org.freedesktop.timesync1 interface (< 239)
	timesync *timesyncProperties
}

// ntpLeapStatus names the two leap indicator bits of an NTP packet (RFC 5905).
var ntpLeapStatus = map[string]string{
	"0": "normal",
	"1": "insert-second",
	"2": "delete-second",
	"3": "unknown",
}

// parseTimesyncProperties reads the output of `timedatectl show-timesync`.
// The leap status is not a property of its own: it is the Leap field of the
// last NTPMessage the daemon received, which is absent until the first answer
// from a server arrives.
func parseTimesyncProperties(stdout string) *timesyncProperties {
	props := parseSystemdShowOutput(stdout)
	res := &timesyncProperties{}

	// timedatectl leaves out properties with an empty value, so a daemon
	// with no configured servers prints no SystemNTPServers line at all.
	// Older systemd versions emit `LinkNTPServers` instead of including
	// DHCP-provided servers in SystemNTPServers; fold them in so the
	// effective list is what users get.
	res.servers = append(strings.Fields(props["SystemNTPServers"]), strings.Fields(props["LinkNTPServers"])...)
	if res.servers == nil {
		res.servers = []string{}
	}
	res.fallbackServers = strings.Fields(props["FallbackNTPServers"])
	if res.fallbackServers == nil {
		res.fallbackServers = []string{}
	}
	if v := strings.TrimSpace(props["ServerName"]); v != "" {
		res.serverName = &v
	}
	if v := strings.TrimSpace(props["ServerAddress"]); v != "" {
		res.serverAddress = &v
	}
	if v, ok := parseSystemdTimespanUSec(props["PollIntervalUSec"]); ok {
		res.pollIntervalUSec = &v
	}
	if leap, ok := parseNTPMessageField(props["NTPMessage"], "Leap"); ok {
		if name, ok := ntpLeapStatus[leap]; ok {
			res.leapStatus = &name
		}
	}
	return res
}

// parseNTPMessageField reads one field of the NTPMessage property as
// timedatectl prints it: `{ Leap=0, Version=4, Mode=4, Stratum=3, ... }`.
func parseNTPMessageField(msg string, field string) (string, bool) {
	msg = strings.TrimSpace(msg)
	msg = strings.TrimPrefix(msg, "{")
	msg = strings.TrimSuffix(msg, "}")
	for _, part := range strings.Split(msg, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && key == field {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

// systemdTimespanUnits maps the time units systemd prints and accepts to
// microseconds, following src/basic/time-util.c.
var systemdTimespanUnits = map[string]float64{
	"us": 1, "usec": 1, "µs": 1, "μs": 1,
	"ms": 1e3, "msec": 1e3,
	"s": 1e6, "sec": 1e6, "second": 1e6, "seconds": 1e6,
	"m": 60e6, "min": 60e6, "minute": 60e6, "minutes": 60e6,
	"h": 3600e6, "hr": 3600e6, "hour": 3600e6, "hours": 3600e6,
	"d": 86400e6, "day": 86400e6, "days": 86400e6,
	"w": 604800e6, "week": 604800e6, "weeks": 604800e6,
	"M": 2629800e6, "month": 2629800e6, "months": 2629800e6,
	"y": 31557600e6, "year": 31557600e6, "years": 31557600e6,
}

// parseSystemdTimespanUSec converts a time span as `timedatectl show` prints
// it (`4min 16s`, `34min 8s`, `500ms`) to microseconds. A bare number is
// already microseconds. `infinity` and anything unparsable report false.
func parseSystemdTimespanUSec(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v, true
	}

	var total float64
	rest := s
	for {
		rest = strings.TrimLeftFunc(rest, unicode.IsSpace)
		if rest == "" {
			break
		}
		numEnd := strings.IndexFunc(rest, func(r rune) bool {
			return !unicode.IsDigit(r) && r != '.'
		})
		if numEnd == 0 {
			return 0, false
		}
		if numEnd < 0 {
			// a trailing number without a unit is not a timespan systemd prints
			return 0, false
		}
		num, err := strconv.ParseFloat(rest[:numEnd], 64)
		if err != nil {
			return 0, false
		}
		rest = strings.TrimLeftFunc(rest[numEnd:], unicode.IsSpace)
		unitEnd := strings.IndexFunc(rest, func(r rune) bool {
			return unicode.IsDigit(r) || unicode.IsSpace(r) || r == '.'
		})
		if unitEnd < 0 {
			unitEnd = len(rest)
		}
		mult, ok := systemdTimespanUnits[rest[:unitEnd]]
		if !ok {
			return 0, false
		}
		total += num * mult
		rest = rest[unitEnd:]
	}
	if total > math.MaxInt64 {
		return 0, false
	}
	return int64(math.Round(total)), true
}

func (t *mqlSystemdTimesyncd) resolveState() (*timesyncdState, error) {
	if t.fetched {
		return t.cachedState, nil
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.fetched {
		return t.cachedState, nil
	}
	state := &timesyncdState{}

	// Synchronized state lives in the `NTPSynchronized` property of the
	// org.freedesktop.timedate1 dbus interface. On systemd >= 239 this is
	// exposed via `timedatectl show`; that verb does not exist on older
	// systemd (e.g. v237 on Ubuntu 18.04), where `timedatectl show` exits
	// non-zero and returns nothing. In that case fall back to parsing the
	// human-readable `timedatectl status` output, whose "System clock
	// synchronized: yes/no" line is backed by the same property.
	// timedate1 is served by systemd-timedated, which exists to be started on
	// demand and exits when idle; starting it changes nothing on the host.
	if stdout, ok, err := runSystemctl(t.MqlRuntime, "timedatectl show --no-pager"); err != nil {
		return nil, err
	} else if ok {
		props := parseSystemdShowOutput(stdout)
		state.synchronized = props["NTPSynchronized"] == "yes"
	} else if stdout, ok, err := runSystemctl(t.MqlRuntime, "timedatectl status --no-pager"); err != nil {
		return nil, err
	} else if ok {
		state.synchronized = parseTimedatectlStatusSynchronized(stdout)
	}

	// Per-server state comes from show-timesync (org.freedesktop.timesync1).
	// Asking that bus name for anything starts systemd-timesyncd through D-Bus
	// activation when it is not running, and timesyncd conflicts with chrony
	// and ntpd: one query would stop the host's NTP daemon, or restart a
	// timesyncd an administrator stopped. So ask only a running daemon.
	running, err := isSystemdUnitActive(t.MqlRuntime, "systemd-timesyncd")
	if err != nil {
		return nil, err
	}
	if running {
		if stdout, ok, err := runSystemctl(t.MqlRuntime, "timedatectl show-timesync --no-pager"); err != nil {
			return nil, err
		} else if ok {
			state.timesync = parseTimesyncProperties(stdout)
		}
	}

	t.fetched = true
	t.cachedState = state
	return state, nil
}

func (t *mqlSystemdTimesyncd) synchronized() (bool, error) {
	s, err := t.resolveState()
	if err != nil {
		return false, err
	}
	return s.synchronized, nil
}

func (t *mqlSystemdTimesyncd) servers() ([]any, error) {
	s, err := t.resolveState()
	if err != nil {
		return nil, err
	}
	if s.timesync == nil || s.timesync.servers == nil {
		t.Servers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return stringsToAny(s.timesync.servers), nil
}

func (t *mqlSystemdTimesyncd) fallbackServers() ([]any, error) {
	s, err := t.resolveState()
	if err != nil {
		return nil, err
	}
	if s.timesync == nil || s.timesync.fallbackServers == nil {
		t.FallbackServers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return stringsToAny(s.timesync.fallbackServers), nil
}

func (t *mqlSystemdTimesyncd) serverName() (string, error) {
	s, err := t.resolveState()
	if err != nil {
		return "", err
	}
	if s.timesync == nil || s.timesync.serverName == nil {
		t.ServerName.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *s.timesync.serverName, nil
}

func (t *mqlSystemdTimesyncd) serverAddress() (string, error) {
	s, err := t.resolveState()
	if err != nil {
		return "", err
	}
	if s.timesync == nil || s.timesync.serverAddress == nil {
		t.ServerAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *s.timesync.serverAddress, nil
}

func (t *mqlSystemdTimesyncd) pollIntervalUSec() (int64, error) {
	s, err := t.resolveState()
	if err != nil {
		return 0, err
	}
	if s.timesync == nil || s.timesync.pollIntervalUSec == nil {
		t.PollIntervalUSec.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *s.timesync.pollIntervalUSec, nil
}

func (t *mqlSystemdTimesyncd) leapStatus() (string, error) {
	s, err := t.resolveState()
	if err != nil {
		return "", err
	}
	if s.timesync == nil || s.timesync.leapStatus == nil {
		t.LeapStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *s.timesync.leapStatus, nil
}

type mqlSystemdTimesyncdInternal struct {
	cachedState *timesyncdState
	fetched     bool
	lock        sync.Mutex
}
