// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cassandraconf

import (
	"regexp"
	"strings"
)

// ParseProperties parses a Java properties file, which is the format of
// cassandra-rackdc.properties and cassandra-topology.properties.
//
// Both `=` and `:` separate a key from its value, `#` and `!` open a comment,
// and surrounding whitespace is not part of either side. A repeated key takes
// its last value, as the Java loader does.
func ParseProperties(content string) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		i := strings.IndexAny(line, "=:")
		if i < 0 {
			// A bare key is legal and means the empty string.
			out[line] = ""
			continue
		}
		key := strings.TrimSpace(line[:i])
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(line[i+1:])
	}
	return out
}

// reVersion matches the version `cassandra -v` prints, which is the bare
// version on a line of its own, optionally carrying a qualifier such as
// -SNAPSHOT. Matching whole lines keeps a JVM notice printed ahead of it
// (for example "Picked up JAVA_TOOL_OPTIONS: ...") from being mistaken for
// the version.
var reVersion = regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)(?:-[A-Za-z0-9.]+)?$`)

// ParseVersion extracts the server version from `cassandra -v` output,
// returning the empty string when the output carries no recognizable version.
func ParseVersion(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if m := reVersion.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}
