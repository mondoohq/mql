// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package conanlock

import (
	"strconv"
	"strings"
)

// conanLock represents a parsed conan.lock file.
type conanLock struct {
	Version   string         `json:"version"`
	GraphLock conanGraphLock `json:"graph_lock"`
	Requires  []string       `json:"requires"`
	// BuildRequires, PythonRequires and ConfigRequires are all build-time
	// tooling rather than content of the produced artifact. ConfigRequires
	// arrived with Conan 2's `conan config install-pkg`; before it was read
	// here, a lockfile's config packages were dropped entirely — not scoped
	// out, but absent, so `--include-dev` did not bring them back either.
	BuildRequires  []string `json:"build_requires"`
	PythonRequires []string `json:"python_requires"`
	ConfigRequires []string `json:"config_requires"`

	// evidence is a list of file paths where the conan.lock was found.
	evidence []string `json:"-"`
}

// conanGraphLock represents the v1 graph_lock format.
type conanGraphLock struct {
	Nodes map[string]conanGraphNode `json:"nodes"`
}

// conanGraphNode represents a single node in the v1 graph lock.
type conanGraphNode struct {
	Ref  string `json:"ref"`
	Pref string `json:"pref"`
	Path string `json:"path"`
	// Context is "build" for a node in the build context (a tool_requires and
	// its closure) and "host" — or absent — otherwise. It is how a v1 lockfile
	// says what v2 says with a separate build_requires list.
	Context string `json:"context"`
}

// isV2 returns true if this is a v2 format lockfile (version >= 0.5).
//
// Compared component-wise rather than as a float. Conan has shipped "0.4" and
// "0.5", both of which parse as floats, but a lockfile version is a dotted
// version and not a number: a future "0.5.1" fails ParseFloat, and the error
// path selected the V1 PARSER for a v2 lockfile — which reports nothing at all
// rather than failing, since a v2 file has no graph_lock to walk. Reading the
// components keeps a later patch release working.
func (l *conanLock) isV2() bool {
	fields := strings.Split(strings.TrimSpace(l.Version), ".")
	major, err := strconv.Atoi(fields[0])
	if err != nil {
		return false
	}
	if major > 0 {
		return true
	}
	if len(fields) < 2 {
		return false
	}
	minor, err := strconv.Atoi(fields[1])
	if err != nil {
		return false
	}
	return minor >= 5
}
