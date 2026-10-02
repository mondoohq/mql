// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// sbinDirs hold system administration tools such as pvs and zpool. RHEL 7
// leaves them off a non-root user's PATH (/usr/local/bin:/usr/bin), where the
// shell answers a bare tool name with "command not found" although the tool
// is installed.
var sbinDirs = []string{"/usr/sbin", "/sbin"}

// sbinCommandCandidates returns cmdline followed by the same command line
// with its tool named by its absolute path in each of sbinDirs. A command
// line whose tool already names a path is returned alone.
func sbinCommandCandidates(cmdline string) []string {
	cmdline = strings.TrimSpace(cmdline)
	tool, args, hasArgs := strings.Cut(cmdline, " ")
	if tool == "" || strings.Contains(tool, "/") {
		return []string{cmdline}
	}
	res := make([]string, 0, len(sbinDirs)+1)
	res = append(res, cmdline)
	for _, dir := range sbinDirs {
		c := path.Join(dir, tool)
		if hasArgs {
			c += " " + args
		}
		res = append(res, c)
	}
	return res
}

// isCommandNotFound reports whether the shell could not find the tool of a
// command line, which POSIX shells signal with exit code 127.
func isCommandNotFound(exit int64) bool {
	return exit == 127
}

// runSbinCommand runs cmdline through the command resource. When the shell
// cannot find its tool, it retries with the tool's absolute path in each of
// sbinDirs and returns the first run that found the tool. When none did, it
// returns the first run, so the caller still sees "command not found" and can
// treat the tool as not installed.
func runSbinCommand(runtime *plugin.Runtime, cmdline string) (*mqlCommand, error) {
	var first *mqlCommand
	for _, c := range sbinCommandCandidates(cmdline) {
		o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
			"command": llx.StringData(c),
		})
		if err != nil {
			return nil, err
		}
		cmd := o.(*mqlCommand)
		exit := cmd.GetExitcode()
		if exit.Error != nil {
			return nil, exit.Error
		}
		if !isCommandNotFound(exit.Data) {
			return cmd, nil
		}
		if first == nil {
			first = cmd
		}
	}
	return first, nil
}
