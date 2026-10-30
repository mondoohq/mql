// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"context"
	"errors"
	"io"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// exitToolMissing is the exit status the scripts use when the tool they
// run is not installed, the status a shell itself uses for a missing command.
const exitToolMissing = 127

// runCommand runs a script on the asset. A command that ran past its time
// budget is a target not answering in time, which is a kind of its own.
func runCommand(conn shared.Connection, script string) (*shared.Command, error) {
	cmd, err := conn.RunCommand(script)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, llx.Unavailable(err)
		}
		return nil, err
	}
	return cmd, nil
}

// commandFailed is the error for a script that exited with a failure, read
// from its stderr. A missing tool is classified as not found: what the
// provider had to ask is not on the asset.
func commandFailed(cmd *shared.Command, msg string) error {
	stderr, _ := io.ReadAll(cmd.Stderr)
	err := errors.New(msg + ": " + strings.TrimSpace(string(stderr)))
	if cmd.ExitStatus == exitToolMissing {
		return llx.NotFound(err)
	}
	return err
}
