// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package buildgradle

import (
	"bufio"
	"io"
	"strings"
)

// Where a Gradle project's versions actually live.
//
// A build script rarely states its versions inline. They are declared once, for
// the whole build, in a `gradle.properties` or a root `ext` block — often in a
// script of their own (`constants.gradle`, `versions.gradle`) that the modules
// apply. The module then writes `implementation "androidx.annotation:annotation:$androidxAnnotationVersion"`,
// and reading that file alone yields an artifact with no version, which no
// advisory can match.
//
// These two collectors read the two formats those declarations come in. Which
// files to feed them is the caller's question, because it depends on the
// project layout, not on the file format.

// maxPropertyLines bounds a property-source read. These are small files by
// nature, and the scan is driven by repository content.
const maxPropertyLines = 20000

// CollectScriptProperties reads the version properties a Gradle script
// declares: `def x = '1.2'`, `val x = "1.2"`, `ext.x = '1.2'`, and the bare
// `x = '1.2'` form used inside an `ext { }` or `project.ext { }` block.
func CollectScriptProperties(r io.Reader) map[string]string {
	var lines []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() && len(lines) < maxPropertyLines {
		lines = append(lines, scanner.Text())
	}
	return collectVars(lines)
}

// CollectPropertiesFile reads a gradle.properties: `key=value` lines, where the
// value is unquoted and runs to the end of the line.
//
// Only property names that look like a version reference are kept. A
// gradle.properties also carries build settings — `org.gradle.jvmargs`,
// `android.useAndroidX`, memory flags — and those share a namespace with the
// version properties a script interpolates. Keeping them would let a build
// setting be substituted into a coordinate.
func CollectPropertiesFile(r io.Reader) map[string]string {
	out := map[string]string{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 0; scanner.Scan() && n < maxPropertyLines; n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || !isVersionProperty(key, value) {
			continue
		}
		out[key] = value
	}
	return out
}

// isVersionProperty reports whether a gradle.properties entry can be a version
// a script interpolates.
//
// A dotted name is always a build setting: Gradle's own settings are namespaced
// (`org.gradle.*`, `android.*`), and a script interpolating `$x` cannot name a
// dotted property that way regardless.
//
// Beyond that the VALUE decides, not the name. Requiring "version" in the key
// was the obvious rule and the wrong one: real projects name version properties
// `kotlinCoroutines`, `okhttpRelease`, `agp` and `composeBom`, and dropping
// those leaves exactly the versionless coordinates this collector exists to
// fill in. What has to be excluded is a build setting sharing the namespace --
// `useAndroidX=true`, `jvmargs=-Xmx2g` -- and those are told apart by their
// values, which do not look like versions.
//
// A value that does look like one is kept whatever the key is called. If a
// script interpolates it into a coordinate, that is the string Gradle would
// substitute there too, so keeping it reports what the build does.
func isVersionProperty(key, value string) bool {
	if strings.Contains(key, ".") {
		return false
	}
	return looksLikeVersion(value)
}

// looksLikeVersion reports whether a value could be a version: it starts with a
// digit, or a "v" before one, and carries none of the characters that mark a
// path, a flag, a list or a sentence.
func looksLikeVersion(v string) bool {
	if v == "" {
		return false
	}
	first := v[0]
	if (first == 'v' || first == 'V') && len(v) > 1 {
		first = v[1]
	}
	if first < '0' || first > '9' {
		return false
	}
	return !strings.ContainsAny(v, " \t\"'\\/=,;")
}
