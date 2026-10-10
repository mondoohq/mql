// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// runAixCommand runs a command and returns its output. A non-zero exit is an
// error carrying stderr.
func runAixCommand(runtime *plugin.Runtime, command string) (string, string, error) {
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData(command),
	})
	if err != nil {
		return "", "", err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return "", "", exit.Error
	}
	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return "", "", stdout.Error
	}
	stderr := cmd.GetStderr()
	if stderr.Error != nil {
		return "", "", stderr.Error
	}
	if exit.Data != 0 {
		return stdout.Data, stderr.Data, fmt.Errorf("%q exited with %d: %s", command, exit.Data, strings.TrimSpace(stderr.Data))
	}
	return stdout.Data, stderr.Data, nil
}
