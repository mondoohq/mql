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
// told. It reads the release from the name of libsystemd-shared, which works
// without running anything, and asks `systemctl --version` for a release
// before 231, which did not ship that library.
func systemdRelease(runtime *plugin.Runtime) (int, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return 0, nil
	}
	if fs := conn.FileSystem(); fs != nil {
		if v := systemd.InstalledVersion(&afero.Afero{Fs: fs}); v > 0 {
			return v, nil
		}
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return 0, nil
	}
	stdout, ok, err := runSystemctl(runtime, "systemctl --version")
	if err != nil || !ok {
		return 0, err
	}
	return parseSystemctlRelease(stdout), nil
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
