// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// systemProfilerSharingCmd populates the unified Sharing panel view —
// the same data shown by `system_profiler SPSharingDataType`. Output
// is one `Service Name: On|Off` line per toggle, indented under a
// `Sharing:` header, so the line parser doesn't need to deal with
// `system_profiler -json`'s schema drift across macOS versions.
const systemProfilerSharingCmd = "system_profiler SPSharingDataType"

type mqlMacosSharingInternal struct {
	lock    sync.Mutex
	fetched bool
	state   map[string]bool

	sourcesLock sync.Mutex
	sources     *sharingSources
}

func (s *mqlMacosSharing) id() (string, error) {
	return "macos.sharing", nil
}

// fetchState runs `system_profiler SPSharingDataType` once and returns the
// parsed map of service name → enabled.
//
// An empty map means the Sharing panel could not be read, not that every
// service is off. macOS 26 dropped SPSharingDataType altogether -- the
// command exits 0 and prints nothing -- so an empty result must never be
// read as "everything is off". sharingFlag reads each toggle from its own
// setting instead (see macos_sharing_sources.go).
func (s *mqlMacosSharing) fetchState() (map[string]bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.fetched {
		return s.state, nil
	}

	res, err := NewResource(s.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(systemProfilerSharingCmd),
	})
	if err != nil {
		return nil, err
	}
	cmd := res.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		s.state = map[string]bool{}
		s.fetched = true
		return s.state, nil
	}

	s.state = parseSharingOutput(cmd.GetStdout().Data)
	s.fetched = true
	return s.state, nil
}

// parseSharingOutput parses the human-readable output of
// `system_profiler SPSharingDataType`. The format has been stable
// across the last decade of macOS releases:
//
//	Sharing:
//
//	    Computer Name: My Mac
//	    Bluetooth Sharing: Off
//	    File Sharing: On
//	    Screen Sharing: Off
//	    AirPlay Receiver: On
//
// Each `Name: Value` line whose value is exactly `On` or `Off` is
// captured into the returned map. Lines like `Computer Name: ...`
// don't match the On/Off shape and are quietly skipped.
func parseSharingOutput(stdout string) map[string]bool {
	out := map[string]bool{}
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ": ")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+2:])
		switch value {
		case "On":
			out[key] = true
		case "Off":
			out[key] = false
		}
	}
	return out
}

// sharingFlag returns the bool for one Sharing panel entry.
//
// A panel that returned entries but not this one reads as `false`: some macOS
// versions omit services that aren't installed (DVD or CD Sharing on Apple
// Silicon), and "not present" is operationally the same as "off".
//
// A panel that returned nothing at all is a different thing -- nothing was
// measured. That is the normal outcome on macOS 26, which has no
// SPSharingDataType reporter, so the toggle is read from the setting behind
// it instead, never assumed off.
func (s *mqlMacosSharing) sharingFlag(name string) (bool, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	// Before macOS 26 the panel is tried first. An empty panel there falls
	// through to the settings below instead of erroring: they exist on
	// those releases too, so a read value beats "unavailable".
	if !sharingPanelRemoved(conn.Asset().GetPlatform().GetVersion()) {
		state, err := s.fetchState()
		if err != nil {
			return false, err
		}
		if len(state) > 0 {
			return state[name], nil
		}
	}

	s.sourcesLock.Lock()
	if s.sources == nil {
		runtime := s.MqlRuntime
		s.sources = &sharingSources{
			conn:      conn,
			listUsers: func() ([]targetUser, error) { return targetUserHomes(runtime) },
		}
	}
	sources := s.sources
	s.sourcesLock.Unlock()
	return sources.flag(name)
}

// sharingPanelRemoved reports whether this macOS release has no
// SPSharingDataType reporter: macOS 26 and later. There system_profiler
// exits 0 with no output, and at 150-290ms it is the most expensive step of
// reading the panel, so it is skipped. An unknown version still tries it.
func sharingPanelRemoved(version string) bool {
	major, _, _ := strings.Cut(version, ".")
	n, err := strconv.Atoi(major)
	return err == nil && n >= 26
}

func (s *mqlMacosSharing) screenSharing() (bool, error) {
	return s.sharingFlag("Screen Sharing")
}

func (s *mqlMacosSharing) remoteManagement() (bool, error) {
	return s.sharingFlag("Remote Management")
}

func (s *mqlMacosSharing) fileSharing() (bool, error) {
	return s.sharingFlag("File Sharing")
}

func (s *mqlMacosSharing) printerSharing() (bool, error) {
	return s.sharingFlag("Printer Sharing")
}

func (s *mqlMacosSharing) internetSharing() (bool, error) {
	return s.sharingFlag("Internet Sharing")
}

func (s *mqlMacosSharing) bluetoothSharing() (bool, error) {
	return s.sharingFlag("Bluetooth Sharing")
}

func (s *mqlMacosSharing) mediaSharing() (bool, error) {
	return s.sharingFlag("Media Sharing")
}

func (s *mqlMacosSharing) contentCaching() (bool, error) {
	return s.sharingFlag("Content Caching")
}

func (s *mqlMacosSharing) airplayReceiver() (bool, error) {
	return s.sharingFlag("AirPlay Receiver")
}

func (s *mqlMacosSharing) dvdSharing() (bool, error) {
	return s.sharingFlag("DVD or CD Sharing")
}
