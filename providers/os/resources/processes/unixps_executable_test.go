// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"runtime"
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

// Deriving the executable must not allocate a slice of every path segment, so
// the memory ToOSProcess uses must not grow with how deep the path is. Two
// commands of identical length that differ only in separator count isolate
// that: splitting allocates a slice proportional to the segment count, taking
// the last segment allocates nothing at all.
//
// This measures bytes rather than allocation counts on purpose -- strings.Split
// allocates one slice whatever the depth, so a count-based check cannot tell
// the two implementations apart.
func TestToOSProcessDoesNotScaleWithPathDepth(t *testing.T) {
	shallow := ProcessEntry{Pid: 1, Command: "/usrxlibxsystemdxbinxlibxexecxoptxvarxrunxsystemd --system"}
	deep := ProcessEntry{Pid: 1, Command: "/usr/lib/systemd/bin/lib/exec/opt/var/run/systemd --system"}

	// same byte length, so any difference comes from the separators alone
	assert.Equal(t, len(shallow.Command), len(deep.Command), "test inputs must be the same length")

	shallowBytes := allocatedBytes(1000, func() { processSink = shallow.ToOSProcess() })
	deepBytes := allocatedBytes(1000, func() { processSink = deep.ToOSProcess() })

	// Compared with a tolerance, not for equality. TotalAlloc is a process-wide
	// counter, so anything else allocating between the two reads moves it --
	// which made this fail intermittently, in both directions, by 16 bytes over
	// 1000 calls.
	//
	// The tolerance is far below what a regression costs. Measured on the same
	// inputs: taking the last segment allocates 0 bytes either way, while
	// splitting allocates 32,000 for the shallow path and 176,000 for the deep
	// one -- a difference of 144,000. Anything between the 16 bytes of noise and
	// those 144,000 works; 8 KiB is ~500x the noise and ~1/17th of the signal.
	const tolerance = 8 << 10

	assert.InDelta(t, shallowBytes, deepBytes, tolerance,
		"memory scaled with path depth (%d bytes shallow vs %d deep over 1000 calls), "+
			"so the path is being split into a slice again", shallowBytes, deepBytes)
}

// processSink keeps the results reachable so the allocations are not optimized
// away while measuring.
var processSink *OSProcess

func allocatedBytes(n int, f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range n {
		f()
	}
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}
