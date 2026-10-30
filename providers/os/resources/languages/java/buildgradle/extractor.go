// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package buildgradle

import (
	"io"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/java"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*gradleBuild)(nil)
)

// Extractor parses Gradle build scripts (build.gradle, build.gradle.kts) to
// extract declared project dependencies.
//
// Gradle's own `gradle.lockfile` is the better source where it exists — it is
// resolved, so it carries transitive dependencies and exact versions. But
// dependency locking is opt-in and most projects never enable it, which left a
// plain Gradle project reporting no dependencies at all: not a partial
// inventory, an empty one. The build script is what those projects actually
// have, and its declarations are the direct dependencies.
type Extractor struct {
	// Properties supplies version properties declared OUTSIDE the script being
	// parsed — a gradle.properties, a root project's `ext` block, or a shared
	// script applied into the build. Gradle resolves a version reference
	// against the whole project's property scope, and most real projects
	// declare their versions once, away from the module that uses them:
	// ExoPlayer keeps every version in a root `constants.gradle`. Without them
	// a reference resolves to nothing and the dependency is inventoried with no
	// version, which no advisory can match.
	//
	// The script's own declarations take precedence, as they do in Gradle.
	// Optional: a nil map parses the file alone.
	Properties map[string]string
}

func (e *Extractor) Name() string {
	return "buildgradle"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	build, err := parseBuildGradle(r, e.Properties)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		build.evidence = append(build.evidence, filename)
	}

	return build, nil
}

// Root returns nil — a build script does not reliably name the project it
// builds. The artifact name comes from settings.gradle's `rootProject.name`
// (or the directory name), which is not this file's to state.
func (b *gradleBuild) Root() *languages.Package {
	return nil
}

// Direct returns every declared dependency.
//
// Everything a build script declares is direct by definition — the script is
// where the project asks for it. Test-only dependencies are included and carry
// dev scope: "direct" is about who declared a dependency, "dev" about whether it
// ships, and the two are independent.
func (b *gradleBuild) Direct() languages.Packages {
	return b.packages()
}

// Transitive returns the declared dependencies. A build script states only what
// the project asked for; resolving the closure below it needs Gradle itself,
// and no transitive dependency is invented here to stand in for that.
func (b *gradleBuild) Transitive() languages.Packages {
	return b.packages()
}

func (b *gradleBuild) packages() languages.Packages {
	var packages languages.Packages
	at := map[string]int{}
	for _, dep := range b.Deps {
		name := dep.GroupId + ":" + dep.ArtifactId

		scope := languages.PackageScopeProd
		if dep.IsTest {
			scope = languages.PackageScopeDev
		}

		// The same coordinate is routinely declared in several configurations
		// (implementation and testImplementation both). It is one package, and
		// it ships if ANY configuration ships it — so a later production
		// declaration promotes an entry first seen as dev. Deciding this by
		// declaration order would make the scope depend on the order lines
		// happen to appear in.
		key := name + "@" + dep.Version
		if i, ok := at[key]; ok {
			if scope == languages.PackageScopeProd {
				packages[i].Scope = languages.PackageScopeProd
			}
			continue
		}
		at[key] = len(packages)

		packages = append(packages, &languages.Package{
			Name:         name,
			Version:      dep.Version,
			Scope:        scope,
			Purl:         java.NewPackageUrl(dep.GroupId, dep.ArtifactId, dep.Version),
			Cpes:         java.NewCpes(dep.GroupId, dep.ArtifactId, dep.Version),
			EvidenceList: java.NewEvidenceList(b.evidence),
		})
	}
	return packages
}
