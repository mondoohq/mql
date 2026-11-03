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
// It follows java.util.Properties.load on whitespace, because Cassandra reads
// some values without trimming them: the key ends at the first `=`, `:` or
// whitespace; whitespace around that separator is skipped; whitespace before
// the key is skipped; and trailing whitespace stays part of the value.
// `prefer_local=true ` is therefore "true " here as it is to Cassandra, whose
// Boolean.parseBoolean reads it as false. `#` and `!` open a comment. A
// repeated key takes its last value, as the Java loader does. Escapes and
// continuation lines are not interpreted.
func ParseProperties(content string) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimLeft(strings.TrimSuffix(line, "\r"), propertiesSpace)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		i := strings.IndexAny(line, "=:"+propertiesSpace)
		if i < 0 {
			// A bare key is legal and means the empty string.
			out[line] = ""
			continue
		}
		key, rest := line[:i], strings.TrimLeft(line[i:], propertiesSpace)
		if rest != "" && (rest[0] == '=' || rest[0] == ':') {
			rest = strings.TrimLeft(rest[1:], propertiesSpace)
		}
		if key == "" {
			continue
		}
		out[key] = rest
	}
	return out
}

// propertiesSpace is the whitespace java.util.Properties skips around keys
// and separators.
const propertiesSpace = " \t\f"

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
