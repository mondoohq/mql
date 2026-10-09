// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package date

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// TimeSync is what a system reports about keeping its clock in time. A nil
// field is one the platform could not answer.
type TimeSync struct {
	// Synchronized says whether the clock is synchronized to a time source.
	Synchronized *bool
	// Source is the NTP server name or address, or the reference clock, the
	// system clock follows.
	Source *string
}

// windowsTimeSyncCmd reads the Windows Time service status and its current
// source. Errors (the service is not running) are kept in the output, since
// their error code tells that case apart.
const windowsTimeSyncCmd = "@{Status=(w32tm /query /status 2>&1) -join \"`n\";Source=(w32tm /query /source 2>&1) -join \"`n\"} | ConvertTo-Json"

// WindowsTimeSync reads the Windows Time service's view of the clock.
func WindowsTimeSync(conn shared.Connection) (*TimeSync, error) {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return &TimeSync{}, nil
	}
	cmd, err := conn.RunCommand(powershell.Encode(windowsTimeSyncCmd))
	if err != nil {
		return nil, fmt.Errorf("failed to query the Windows Time service: %w", err)
	}
	content, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to read the Windows Time service status: %w", err)
	}
	var out struct {
		Status string `json:"Status"`
		Source string `json:"Source"`
	}
	if err := json.Unmarshal(content, &out); err != nil {
		return nil, fmt.Errorf("failed to parse the Windows Time service status: %w", err)
	}
	return parseW32tm(out.Status, out.Source), nil
}

// w32tmServiceNotStarted is the HRESULT w32tm prints when the Windows Time
// service is not running. The message around it is localized, the code is not.
const w32tmServiceNotStarted = "0x80070426"

// Reference IDs that mean the clock follows no external source: none at all
// (the "Local CMOS Clock" source), and "LOCL", the free-running system clock.
const (
	refIDUnspecified = 0x00000000
	refIDLocal       = 0x4C4F434C
)

// parseW32tm reads `w32tm /query /status` and `w32tm /query /source`.
//
// The status labels are localized ("Leap Indicator" is "Sprungindikator" on a
// German system), so the values are read by position and shape instead: the
// first line is the leap indicator ("0(no warning)", "3(not synchronized)"),
// the second the stratum ("4 (secondary reference - syncd by (S)NTP)"), and
// the reference ID is the only value written as hex ("0x0A000004 (source IP:
// 10.0.0.4)"). The source is only reported while the clock follows an
// external one, since otherwise it names the local clock in the system's
// language.
func parseW32tm(status, source string) *TimeSync {
	res := &TimeSync{}
	if strings.Contains(status, w32tmServiceNotStarted) {
		// No service, no synchronization.
		res.Synchronized = boolPtr(false)
		return res
	}

	var values []string
	for _, line := range strings.Split(status, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_, value, ok := strings.Cut(line, ":")
		if !ok {
			return res
		}
		values = append(values, strings.TrimSpace(value))
	}
	if len(values) < 2 {
		return res
	}

	leap, ok := leadingInt(values[0])
	if !ok || leap < 0 || leap > 3 {
		return res
	}
	stratum, ok := leadingInt(values[1])
	if !ok {
		return res
	}
	refID, ok := uint64(0), false
	for _, v := range values[2:] {
		if hex, found := strings.CutPrefix(v, "0x"); found {
			field := strings.Fields(hex)
			if len(field) == 0 {
				break
			}
			if id, err := strconv.ParseUint(field[0], 16, 32); err == nil {
				refID, ok = id, true
			}
			break
		}
	}
	if !ok {
		return res
	}

	synced := leap != 3 && stratum >= 1 && stratum <= 15 &&
		refID != refIDUnspecified && refID != refIDLocal
	res.Synchronized = &synced
	if synced {
		res.Source = windowsTimeSource(source)
	}
	return res
}

// windowsTimeSource trims the configuration flags Windows keeps on a peer
// name: "time.windows.com,0x9" is the server time.windows.com.
func windowsTimeSource(source string) *string {
	source = strings.TrimSpace(source)
	if name, flags, ok := strings.Cut(source, ","); ok && strings.HasPrefix(strings.TrimSpace(flags), "0x") {
		source = strings.TrimSpace(name)
	}
	if source == "" || strings.ContainsAny(source, "\n") {
		return nil
	}
	return &source
}

// leadingInt parses the number a value starts with: 4 for "4 (secondary
// reference - syncd by (S)NTP)", 0 for "0(no warning)".
func leadingInt(s string) (int, bool) {
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || end == 0 && s[end] == '-') {
		end++
	}
	n, err := strconv.Atoi(s[:end])
	return n, err == nil
}

// ParseChronycTracking reads `chronyc -n -c tracking`, one line of comma
// separated values: reference ID (hex), the source's address or reference
// clock name, stratum, ..., and the leap status last ("Normal", "Insert
// second", "Delete second", "Not synchronised").
func ParseChronycTracking(stdout string) *TimeSync {
	res := &TimeSync{}
	line := strings.TrimSpace(stdout)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Split(line, ",")
	if len(fields) < 14 {
		return res
	}
	refID, err := strconv.ParseUint(fields[0], 16, 32)
	if err != nil {
		return res
	}
	leap := strings.TrimSpace(fields[len(fields)-1])
	switch leap {
	case "Normal", "Insert second", "Delete second":
		res.Synchronized = boolPtr(true)
	case "Not synchronised":
		res.Synchronized = boolPtr(false)
		return res
	default:
		return res
	}
	if name := strings.TrimSpace(fields[1]); name != "" && refID != refIDUnspecified {
		res.Source = &name
	}
	return res
}

// MacOSTimeSource returns the network time server configured in
// /etc/ntp.conf, which is where macOS keeps the server set in System
// Settings. Nil when the file is missing or names no server.
func MacOSTimeSource(fs afero.Fs) *string {
	f, err := fs.Open("/etc/ntp.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseNtpConfServer(f)
}

// parseNtpConfServer returns the host of the first server or pool directive.
func parseNtpConfServer(r io.Reader) *string {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "server" || fields[0] == "pool" {
			return &fields[1]
		}
	}
	return nil
}

func boolPtr(b bool) *bool {
	return &b
}
