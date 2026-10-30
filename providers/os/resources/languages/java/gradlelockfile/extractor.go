// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gradlelockfile

import (
	"bufio"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/java"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*gradleLockfile)(nil)
)

// Extractor parses Gradle lock files to extract resolved dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "gradlelockfile"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	lockfile, err := parseGradleLockfile(r)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		lockfile.evidence = append(lockfile.evidence, filename)
	}

	return lockfile, nil
}

// parseGradleLockfile parses a gradle.lockfile from a reader.
// Format: group:artifact:version=config1,config2,...
func parseGradleLockfile(r io.Reader) (*gradleLockfile, error) {
	lockfile := &gradleLockfile{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// "empty=" marks the end of the lockfile
		if line == "empty=" {
			break
		}

		// Split on = to get dependency and configurations
		dep, configs, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		// Split dependency on : to get group:artifact:version
		parts := strings.SplitN(dep, ":", 3)
		if len(parts) != 3 {
			continue
		}

		configurations := strings.Split(configs, ",")
		isTest := isTestOnly(configurations)

		lockfile.Entries = append(lockfile.Entries, gradleLockEntry{
			GroupId:        parts[0],
			ArtifactId:     parts[1],
			Version:        parts[2],
			Configurations: configurations,
			IsTest:         isTest,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lockfile, nil
}

// isTestOnly returns true if all configurations contain "test" (case-insensitive).
func isTestOnly(configurations []string) bool {
	if len(configurations) == 0 {
		return false
	}
	for _, config := range configurations {
		if !strings.Contains(strings.ToLower(config), "test") {
			return false
		}
	}
	return true
}

// Root returns nil — a gradle.lockfile has no single root project.
func (l *gradleLockfile) Root() *languages.Package {
	return nil
}

// Direct returns nil — gradle.lockfile does not distinguish direct from transitive.
func (l *gradleLockfile) Direct() languages.Packages {
	return nil
}

// Transitive returns all locked dependencies.
func (l *gradleLockfile) Transitive() languages.Packages {
	var packages languages.Packages
	for _, entry := range l.Entries {
		name := entry.GroupId + ":" + entry.ArtifactId
		// A lockfile entry names the configurations that resolved it, and an
		// entry resolved only by test configurations is a test-only dependency
		// — the same fact an npm devDependency states. Reporting it as prod
		// ranks a CVE in a test harness alongside one in the shipped runtime.
		//
		// This is narrower than buildgradle's isDevConfiguration, which also
		// treats annotationProcessor and kapt as dev, and the difference is
		// intended. A lockfile states the configurations that actually resolved
		// an artifact, so an entry naming only annotationProcessor is genuinely
		// on no runtime classpath — but it names them exactly, and widening the
		// match to configuration names seen in a build script would classify on
		// a heuristic where an exact fact is available. Extend this list when a
		// lockfile is observed carrying such a name, not on the strength of the
		// other parser's list.
		scope := languages.PackageScopeProd
		if entry.IsTest {
			scope = languages.PackageScopeDev
		}
		packages = append(packages, &languages.Package{
			Name:         name,
			Version:      entry.Version,
			Scope:        scope,
			Purl:         java.NewPackageUrl(entry.GroupId, entry.ArtifactId, entry.Version),
			Cpes:         java.NewCpes(entry.GroupId, entry.ArtifactId, entry.Version),
			EvidenceList: java.NewEvidenceList(l.evidence),
		})
	}
	return packages
}
