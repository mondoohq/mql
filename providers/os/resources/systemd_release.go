// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/systemd"
)

// systemdRelease is the release of the host's systemd, or 0 when it cannot be
// told. systemd.InstalledVersion reads it without running anything: exactly
// from the name of libsystemd-shared since 231, and before that from the
// manager binary, or as a stand-in below 231 when the binary does not say.
// A release before 231 is confirmed with `systemctl --version` when commands
// can run, so the stand-in only answers for offline scans.
func systemdRelease(runtime *plugin.Runtime) (int, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return 0, nil
	}
	installed := 0
	if fs := conn.FileSystem(); fs != nil {
		installed = systemd.InstalledVersion(&afero.Afero{Fs: fs})
	}
	if installed >= 231 || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return installed, nil
	}
	stdout, ok, err := runSystemctl(runtime, "systemctl --version")
	if err != nil {
		return 0, err
	}
	if v := parseSystemctlRelease(stdout); ok && v > 0 {
		return v, nil
	}
	return installed, nil
}

// parseSystemctlRelease reads the release number from `systemctl --version`,
// whose first line is "systemd 237" or "systemd 252 (252.39-1~deb12u2)".
func parseSystemctlRelease(output string) int {
	line, _, _ := strings.Cut(output, "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "systemd" {
		return 0
	}
	v, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return v
}
