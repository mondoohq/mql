// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

// runnableBinary returns the path at which the scan may run bin, a product's
// own binary found on the target (nginx, mysqld, kubelet), or "" when it may
// not. An absolute path is run only when no account other than root, or the
// one the scan runs commands as, can replace it or any directory on the way to
// it (see packages.ResolveTrustedExecutable): the scan often runs as root, and
// running such a binary would hand that account root. A bare name is left to
// the scan's PATH, like every other command the scan runs. Windows targets
// keep bin as it is.
func runnableBinary(conn shared.Connection, bin string) string {
	if bin == "" || isWindowsAsset(conn) || !strings.HasPrefix(bin, "/") {
		return bin
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return ""
	}
	if _, trusted := packages.ResolveTrustedExecutable(conn, bin); !trusted {
		return ""
	}
	return bin
}
