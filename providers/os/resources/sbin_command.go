// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"regexp"
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
// line whose tool already names a path is returned alone. Leading `env` and
// VAR=value words stay in front of the tool.
func sbinCommandCandidates(cmdline string) []string {
	cmdline = strings.TrimSpace(cmdline)
	prefix := ""
	rest := cmdline
	for {
		word, after, _ := strings.Cut(rest, " ")
		if (word == "env" && prefix == "") || envAssignmentWord.MatchString(word) {
			prefix += word + " "
			rest = after
			continue
		}
		break
	}
	tool, args, hasArgs := strings.Cut(rest, " ")
	if tool == "" || strings.Contains(tool, "/") {
		return []string{cmdline}
	}
	res := make([]string, 0, len(sbinDirs)+1)
	res = append(res, cmdline)
	for _, dir := range sbinDirs {
		c := prefix + path.Join(dir, tool)
		if hasArgs {
			c += " " + args
		}
		res = append(res, c)
	}
	return res
}

// envAssignmentWord matches a VAR=value word; the value may be empty (VAR=).
var envAssignmentWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=\S*$`)

// elevationNotFound matches what sudo and doas print, with exit status 1, when
// the tool is not on their PATH (sudo's secure_path).
var elevationNotFound = regexp.MustCompile(`(?m)^(sudo|doas): \S+: command not found`)

// isCommandNotFound reports whether the tool of a command line could not be
// found: POSIX shells and env signal that with exit code 127, sudo and doas
// with exit code 1 and a "command not found" message.
func isCommandNotFound(exit int64, stderr string) bool {
	if exit == 127 {
		return true
	}
	return exit != 0 && elevationNotFound.MatchString(stderr)
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
		if !isCommandNotFound(exit.Data, cmd.GetStderr().Data) {
			return cmd, nil
		}
		if first == nil {
			first = cmd
		}
	}
	return first, nil
}
