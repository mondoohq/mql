// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ToOSProcess derives Executable from the last path segment of the command's
// first word. The edge cases matter more than the happy path: the obvious
// "cleanup" here is path.Base, which reports "." for an empty path and "bin"
// for "/usr/bin/", where this reports "" for both.
func TestProcessEntryToOSProcess(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		executable string
	}{
		{
			name:       "absolute path with flags",
			command:    "/usr/lib/systemd/systemd --switched-root --system --deserialize 31",
			executable: "systemd",
		},
		{
			name:       "bare name, no path",
			command:    "sshd",
			executable: "sshd",
		},
		{
			name:       "relative path",
			command:    "./bin/agent --config /etc/agent.yaml",
			executable: "agent",
		},
		{
			name:       "quoted path containing a space",
			command:    `"/opt/my app/bin/worker" --verbose`,
			executable: "worker",
		},
		{
			name:       "empty command",
			command:    "",
			executable: "",
		},
		{
			name:       "trailing slash yields an empty executable, not the parent dir",
			command:    "/usr/bin/",
			executable: "",
		},
		{
			name:       "root yields an empty executable, not a slash",
			command:    "/",
			executable: "",
		},
		{
			name:       "unbalanced quoting leaves the executable empty",
			command:    `/usr/bin/foo "unterminated`,
			executable: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := ProcessEntry{Pid: 42, Command: test.command}
			got := p.ToOSProcess()

			assert.Equal(t, test.executable, got.Executable)
			assert.Equal(t, int64(42), got.Pid)
			// Command is passed through untouched regardless of how it parses.
			assert.Equal(t, test.command, got.Command)
		})
	}
}

// Deriving the executable must not allocate a slice of every path segment.
// Taking the last segment shares the memory of the argument and allocates
// nothing, while splitting allocates one slice per call whatever the depth.
//
// The assertion is a bound on allocations per call rather than a comparison
// of process-wide bytes. runtime.MemStats counts the whole process, so an
// allocation by any other goroutine during the measurement lands in it. That
// noise is a few objects, which is why the earlier byte comparison of a
// shallow against a deep path failed on a loaded runner while the code was
// correct. One allocation per call separates the two implementations by
// construction: this one makes none, splitting makes one.
func TestExecutableFromPathDoesNotAllocate(t *testing.T) {
	paths := []struct {
		name string
		path string
	}{
		{"shallow", "/usrxlibxsystemdxbinxlibxexecxoptxvarxrunxsystemd"},
		{"deep", "/usr/lib/systemd/bin/lib/exec/opt/var/run/systemd"},
		{"no separator", "sshd"},
	}

	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(1000, func() {
				stringSink = executableFromPath(p.path)
			})
			assert.Less(t, allocs, 1.0,
				"executableFromPath allocated %v objects per call, so the path is being split", allocs)
		})
	}
}

// TestExecutableFromPathMatchesToOSProcess keeps the helper and its caller in
// step, so the allocation guard above covers what the resource really runs.
// A command without arguments is the whole path, which is what lets the two
// be compared without repeating the shell splitting here.
func TestExecutableFromPathMatchesToOSProcess(t *testing.T) {
	paths := []string{
		"/usr/lib/systemd/systemd",
		"sshd",
		"./bin/agent",
		"/usr/bin/",
		"/",
		"",
	}

	for _, path := range paths {
		got := ProcessEntry{Pid: 1, Command: path}.ToOSProcess()
		assert.Equal(t, executableFromPath(path), got.Executable, path)
	}
}

// stringSink keeps the result reachable so the allocations are not optimized
// away while measuring.
var stringSink string
