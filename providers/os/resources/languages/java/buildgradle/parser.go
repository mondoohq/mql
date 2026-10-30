// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package buildgradle

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages/java"
)

// gradleBuild is the dependency declarations read out of a Gradle build script.
type gradleBuild struct {
	// Deps are the declared dependencies, in declaration order.
	Deps []gradleDep

	// evidence is the list of file paths the declarations were read from.
	evidence []string
}

// gradleDep is one declared dependency.
type gradleDep struct {
	// GroupId is the Maven group ID (e.g. "org.apache.commons").
	GroupId string
	// ArtifactId is the Maven artifact ID (e.g. "commons-text").
	ArtifactId string
	// Version is the declared version, or "" when the build script does not
	// state one here — a version managed by a BOM/platform, or an unresolved
	// interpolation. Empty means unknown, never "any".
	Version string
	// Configuration is the Gradle configuration it was declared in
	// (e.g. "implementation", "testImplementation").
	Configuration string
	// IsTest reports whether the configuration only ever applies to test or
	// build tooling, never to the shipped runtime.
	IsTest bool
}

var (
	// A dependency declaration opens with the configuration name. Inside a
	// dependencies block, an identifier followed by an argument is a
	// declaration; anything else (a nested closure, a bare statement) is not.
	configRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)[\s(]\s*["'A-Za-z(]`)

	// Quoted string literals, single or double quoted.
	quotedRe = regexp.MustCompile(`['"]([^'"\n]*)['"]`)

	// The map-notation form: group: 'x', name: 'y', version: 'z' (Groovy) or
	// group = "x", name = "y", version = "z" (Kotlin DSL).
	mapGroupRe     = regexp.MustCompile(`\bgroup\s*[:=]\s*['"]([^'"]+)['"]`)
	mapNameRe      = regexp.MustCompile(`\b(?:name|module)\s*[:=]\s*['"]([^'"]+)['"]`)
	mapVersionRe   = regexp.MustCompile(`\bversion\s*[:=]\s*['"]([^'"]+)['"]`)
	dependenciesRe = regexp.MustCompile(`(^|\W)dependencies\s*\{`)
	buildscriptRe  = regexp.MustCompile(`(^|\W)buildscript\s*\{`)

	// Variable assignments that a version interpolation can refer to:
	// `def x = '1.2'`, `val x = "1.2"`, `ext.x = '1.2'`, or a bare `x = '1.2'`
	// inside an ext block.
	varRe = regexp.MustCompile(`^(?:def|val|var)?\s*(?:ext\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]([^'"]*)['"]`)

	// $name and ${name} interpolations inside a version string.
	interpRe = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_.]*)\}?`)

	// Groovy string concatenation: 'group:artifact:' + versionVariable. The
	// version lands outside the quotes, so it has to be folded back in before
	// the literal can be read as a coordinate.
	concatRe = regexp.MustCompile(`(['"])\s*\+\s*([A-Za-z_][A-Za-z0-9_.]*)`)
)

// nonDependencyCall lists call forms that appear in a configuration position but
// name no Maven coordinate: a sibling project, a file on disk, the Gradle API
// itself, or a BOM/platform import (a constraint, which ships no code and so can
// never be "used" by anything).
var nonDependencyCall = []string{
	"project(", "files(", "fileTree(", "gradleApi(", "localGroovy(",
	"gradleTestKit(", "platform(", "enforcedPlatform(", "testFixtures(",
}

// devConfigurations are configurations whose dependencies never reach the
// shipped runtime: build tooling, code generators and static analysis.
var devConfigurations = map[string]bool{
	"classpath": true, "annotationProcessor": true, "kapt": true, "ksp": true,
	"developmentOnly": true, "checkstyle": true, "pmd": true, "spotbugs": true,
	"jacocoAgent": true, "jacocoAnt": true, "errorprone": true, "lintChecks": true,
}

// parseBuildGradle reads dependency declarations out of a Gradle build script.
//
// Gradle build scripts are programs, not data, so this reads the declarations
// that are stated literally and says nothing about the rest. That asymmetry is
// deliberate: a coordinate spelled out in the script is a fact, while one
// assembled at configuration time (a version catalog accessor, a coordinate
// built from a function call) is not recoverable without running Gradle. An
// unreadable declaration is therefore omitted rather than guessed at.
func parseBuildGradle(r io.Reader, external map[string]string) (*gradleBuild, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	// Bounded like the property collectors: a build script is small by nature,
	// and the file comes from scanned repository content rather than from us.
	for scanner.Scan() && len(lines) < maxPropertyLines {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Variables are collected over the whole file first: a version property is
	// as often declared below the dependencies block as above it.
	vars := collectVars(lines)
	// Properties from elsewhere in the project fill what this file does not
	// declare. The file's own declarations win, as they do in Gradle.
	for k, v := range external {
		if _, ok := vars[k]; !ok {
			vars[k] = v
		}
	}

	build := &gradleBuild{}
	depth := 0
	depsDepth := -1
	buildscriptDepth := -1

	for _, raw := range lines {
		line := stripComment(raw)

		if depsDepth < 0 && dependenciesRe.MatchString(line) {
			depsDepth = depth
			// A single-line block (`dependencies { implementation '...' }`)
			// declares on this same line, after the brace.
			if rest := afterFirstBrace(line); rest != "" {
				build.Deps = append(build.Deps, parseDepLine(rest, vars, buildscriptDepth >= 0)...)
			}
		} else if depsDepth == depth-1 {
			// A declaration sits directly in the dependencies block. Anything
			// deeper is inside a trailing configuration closure — an
			// `exclude group: 'x', module: 'y'` reads exactly like map
			// notation, and is a dependency being removed, not added.
			build.Deps = append(build.Deps, parseDepLine(line, vars, buildscriptDepth >= 0)...)
		}

		if buildscriptDepth < 0 && buildscriptRe.MatchString(line) {
			buildscriptDepth = depth
		}

		depth += braceDelta(line)

		if depsDepth >= 0 && depth <= depsDepth {
			depsDepth = -1
		}
		if buildscriptDepth >= 0 && depth <= buildscriptDepth {
			buildscriptDepth = -1
		}
	}

	return build, nil
}

// collectVars maps variable names to their literal string values, for resolving
// a version written as an interpolation.
func collectVars(lines []string) map[string]string {
	vars := map[string]string{}
	for _, raw := range lines {
		line := strings.TrimSpace(stripComment(raw))
		if m := varRe.FindStringSubmatch(line); m != nil {
			vars[m[1]] = m[2]
		}
	}
	return vars
}

// stripComment removes a trailing line comment. Quotes are tracked so that a
// "//" inside a string literal (a repository URL, most often) is not mistaken
// for the start of a comment.
func stripComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return line[:i]
		}
	}
	return line
}

// braceDelta is the net block nesting a line opens, counting only braces
// outside string literals.
//
// Counting the whole line lets a brace inside a string move the tracker: a
// `def s = "{"` anywhere in a build script pushes the depth up by one, and
// every declaration after it then sits one level deeper than the dependencies
// block it is actually in -- so it is read as a trailing configuration closure
// and dropped. That is a dependency silently missing from the inventory, which
// is the failure this extractor exists to remove rather than reproduce.
//
// A GString like "${'{'}" is balanced by luck and survived the old count; an
// unbalanced one did not. Quotes are tracked the same way stripComment tracks
// them, so the two agree about what is inside a string.
func braceDelta(line string) int {
	depth := 0
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '{':
			depth++
		case c == '}':
			depth--
		}
	}
	return depth
}

// afterFirstBrace returns what follows the first "{" on a line, trimmed of a
// trailing "}".
func afterFirstBrace(line string) string {
	_, after, ok := strings.Cut(line, "{")
	if !ok {
		return ""
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(after), "}"))
}

// inlineConcat folds a concatenated version variable back into the string
// literal it extends, so that `'g:a:' + fooVersion` reads as `'g:a:1.2.3'`.
// A variable that does not resolve is left alone: the coordinate then states no
// version, which is the truth about it.
//
// The rewrite is deliberately partial, and coupled to quotedRe -- change one
// and check the other. concatRe matches the CLOSING quote of the left-hand
// literal plus the variable, and the replacement puts the variable's value
// first and that quote after it. So `'g:a:' + fooVersion` becomes
// `'g:a:1.2.3'`: the quote that used to close the literal early now closes it
// after the version, and quotedRe reads the whole coordinate out from the
// original opening quote. No complete token is ever built -- the two regexes
// meet in the middle, and a change to either that alters where the quote lands
// silently stops coordinates resolving.
func inlineConcat(s string, vars map[string]string) string {
	return concatRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := concatRe.FindStringSubmatch(m)
		name := sub[2]
		if _, after, ok := strings.CutLast(name, "."); ok {
			name = after
		}
		v, ok := vars[name]
		if !ok {
			return m
		}
		return v + sub[1]
	})
}

// parseDepLine reads the dependency declarations on one line of a dependencies
// block. A line may declare more than one (`implementation 'a:b:1', 'c:d:2'`).
func parseDepLine(line string, vars map[string]string, inBuildscript bool) []gradleDep {
	trimmed := strings.TrimSpace(line)
	m := configRe.FindStringSubmatch(trimmed)
	if m == nil {
		return nil
	}
	config := m[1]
	rest := inlineConcat(trimmed[len(config):], vars)

	for _, skip := range nonDependencyCall {
		if strings.Contains(rest, skip) {
			return nil
		}
	}

	isTest := isDevConfiguration(config, inBuildscript)

	// String-coordinate form first. A trailing configuration closure can carry
	// `group:`/`module:` exclusions, so the map form is only considered when no
	// coordinate literal was found at all.
	var deps []gradleDep
	for _, q := range quotedRe.FindAllStringSubmatch(rest, -1) {
		if d, ok := parseCoordinate(q[1], vars); ok {
			d.Configuration = config
			d.IsTest = isTest
			deps = append(deps, d)
		}
	}
	if len(deps) > 0 {
		return deps
	}

	group := firstSubmatch(mapGroupRe, rest)
	name := firstSubmatch(mapNameRe, rest)
	if group == "" || name == "" {
		return nil
	}
	return []gradleDep{{
		GroupId:       group,
		ArtifactId:    name,
		Version:       java.ConcreteVersion(resolveInterp(firstSubmatch(mapVersionRe, rest), vars)),
		Configuration: config,
		IsTest:        isTest,
	}}
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// parseCoordinate reads a "group:artifact[:version[:classifier]][@ext]" literal.
//
// The version is optional because a project using a BOM declares its
// dependencies without one, and those are still real dependencies worth
// inventorying — reporting the artifact with an unknown version is accurate,
// where dropping it would leave the project looking like it has fewer
// dependencies than it does.
func parseCoordinate(s string, vars map[string]string) (gradleDep, bool) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return gradleDep{}, false
	}
	group, artifact := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if !validCoordinatePart(group) || !validCoordinatePart(artifact) {
		return gradleDep{}, false
	}
	// A dynamic version or a range names a set of releases rather than one, and
	// is refused here for the reason the version catalog refuses it: a purl
	// carrying "1.+" matches nothing while reading as a definite claim. The
	// artifact is still inventoried, with the version unknown.
	var version string
	if len(parts) >= 3 {
		version = java.ConcreteVersion(resolveInterp(strings.TrimSpace(parts[2]), vars))
	}
	return gradleDep{GroupId: group, ArtifactId: artifact, Version: version}, true
}

// validCoordinatePart rejects a string that cannot be a Maven coordinate
// component, which is what keeps an unrelated quoted string on a dependency
// line (a URL, a file path, an exclusion pattern) from being read as one.
func validCoordinatePart(s string) bool {
	if s == "" || strings.ContainsAny(s, " /\\") {
		return false
	}
	// An unresolved interpolation names a coordinate we cannot determine, and a
	// package recorded under the literal name "${springVersion}" would be a
	// fabricated entry rather than a missing one.
	return !strings.Contains(s, "$")
}

// resolveInterp substitutes a "$var"/"${var}" version against the collected
// variables, returning "" when it cannot be resolved — an unknown version, not
// a literal dollar sign, is what an unresolved interpolation means.
func resolveInterp(v string, vars map[string]string) string {
	v = strings.TrimSpace(v)
	if v == "" || !strings.Contains(v, "$") {
		return v
	}
	out := interpRe.ReplaceAllStringFunc(v, func(ref string) string {
		name := strings.Trim(strings.TrimPrefix(ref, "$"), "{}")
		// A qualified reference (project.ext.fooVersion) resolves on its last
		// segment, which is the property name.
		if _, after, ok := strings.CutLast(name, "."); ok {
			name = after
		}
		return vars[name]
	})
	if strings.Contains(out, "$") || out == "" {
		return ""
	}
	return out
}

// isDevConfiguration reports whether a configuration's dependencies stay out of
// the shipped runtime. Everything under buildscript is build tooling, as is any
// configuration naming a test source set.
func isDevConfiguration(config string, inBuildscript bool) bool {
	if inBuildscript || devConfigurations[config] {
		return true
	}
	return strings.Contains(strings.ToLower(config), "test")
}
