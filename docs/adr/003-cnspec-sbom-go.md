# ADR: cnspec SBOM Cataloger for Go

**Status:** Proposed
**Date:** 2026-04-16

---

## Context

cnspec needs native SBOM cataloging for Go modules and binaries to detect dependencies in both local and remote scanning contexts (SSH, WinRM, containers). Go is a dominant language in cloud-native infrastructure (Kubernetes, Docker, Terraform, Prometheus), making it a high-priority ecosystem for SBOM generation.

Go has a well-defined dependency management system centered on `go.mod` and `go.sum` files, plus the ability to embed build information directly into compiled binaries via `debug.BuildInfo`.

---

## File Formats

### go.mod (Module File)

The `go.mod` file declares the module path and its dependency requirements.

```
module github.com/example/myproject

go 1.21

require (
    github.com/pkg/errors v0.9.1
    golang.org/x/sync v0.3.0 // indirect
)
```

**Key fields:**
- `module` directive: declares the module path (used as root package name)
- `go` directive: minimum Go version
- `require` directives: each dependency with module path and version
- `// indirect` comment: distinguishes transitive from direct dependencies

**Format:** Line-oriented text. The `require` block uses parenthesized grouping. Versions follow Go module versioning (`v1.2.3`, `v0.0.0-20210101000000-abcdef123456` for pseudo-versions).

### go.sum (Checksum Database)

The `go.sum` file contains cryptographic hashes for each dependency.

```
github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
```

**Format:** Each line is `<module> <version>[/go.mod] <hash>`. Two entries per dependency: one for the module source and one for its `go.mod` file. Hashes use `h1:` prefix (SHA-256 of the module zip).

### vendor/modules.txt (Vendored Dependencies)

When `go mod vendor` is used, `vendor/modules.txt` lists all vendored modules.

```
# github.com/pkg/errors v0.9.1
## explicit; go 1.12
github.com/pkg/errors
```

**Format:** Lines starting with `#` declare a module and version. Lines starting with `##` contain metadata. Plain lines list packages within the module.

### Go Binary Analysis (Future Phase)

Compiled Go binaries embed `debug.BuildInfo` containing the full module dependency tree. This enables SBOM extraction from compiled binaries without source code access. Go's stdlib provides `debug/buildinfo.ReadFile()` for cross-platform binary reading (ELF, PE, Mach-O).

**Note:** Binary analysis will be implemented in a follow-up PR as it requires additional infrastructure for reading binary formats over the filesystem abstraction.

---

## Parsing Strategy

### go.mod Parser

1. Read file line by line via `afero.Fs`
2. Extract `module` directive for root package identification
3. Extract `go` directive for Go version
4. Parse `require` block(s):
   - Handle both single-line `require path version` and grouped `require ( ... )` syntax
   - Detect `// indirect` comment to classify direct vs. transitive dependencies
5. Parse `replace` directives to resolve local replacements (these override the original module path/version)
6. Parse `exclude` directives to filter out excluded versions

**Version handling:** Go uses semantic versioning with extensions:
- Standard: `v1.2.3`
- Pre-release: `v1.2.3-beta.1`
- Pseudo-versions: `v0.0.0-20210101000000-abcdef123456` (timestamp + commit hash)
- Major version suffixes in module paths: `github.com/foo/bar/v2`

### go.sum Parser

1. Read file line by line
2. Parse each line as `module version hash`
3. Filter to `h1:` hash lines (skip `/go.mod` hash lines for package listing)
4. Group by module path + version

### vendor/modules.txt Parser

1. Read file line by line
2. Parse `#` lines for module path and version
3. Track `## explicit` annotation to identify direct dependencies

### Error Handling

- Malformed lines are skipped with a warning (never abort the scan)
- Unknown go.mod directives are ignored (forward compatibility)
- Files that cannot be read produce a warning and return partial results

---

## Package Identification

### PURL (Package URL)

Format: `pkg:golang/<module-path>@<version>`

Examples:
- `pkg:golang/github.com/pkg/errors@v0.9.1`
- `pkg:golang/golang.org/x/sync@v0.3.0`
- `pkg:golang/github.com/foo/bar/v2@v2.1.0`

Per the [PURL spec for Go](https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/golang-definition.md):
- Type: `golang`
- Namespace + name: the full module path (namespace is everything before the last `/` segment)
- Version: the Go module version string

### CPE Generation

Format: `cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*`

For Go modules, vendor and product are derived from the module path:
- `github.com/pkg/errors` → vendor: `pkg`, product: `errors`
- `golang.org/x/sync` → vendor: `golang.org/x`, product: `sync`

### License Extraction

Go modules do not embed license information in `go.mod` or `go.sum`. License detection requires reading `LICENSE` files from the module source, which is out of scope for the initial parser. Future enrichment can be added via registry API lookups.

---

## Dev/Prod Classification

Go's `go.mod` file distinguishes direct and indirect (transitive) dependencies via the `// indirect` comment:

- **Direct dependencies**: `require` entries without `// indirect`
- **Indirect (transitive) dependencies**: `require` entries with `// indirect` comment

The `vendor/modules.txt` file also marks direct dependencies with `## explicit`.

---

## Dependency Relationships

### From go.mod

The `go.mod` file provides a flat dependency list, not a tree. Direct vs. indirect is indicated by the `// indirect` comment. For full dependency graph resolution, `go.sum` can supplement with the complete set of transitive dependencies.

### From vendor/modules.txt

Lists all vendored modules with explicit/implicit classification but no parent-child relationships.

### Relationship Type

All dependencies from `go.mod` are emitted as `DependsOn` relationships from the root module. The direct/indirect distinction is preserved as metadata.

---

## Remote Scanning Considerations

### afero.Fs Usage

All file reads go through `afero.Fs`:
- `afero.Afero.ReadFile()` for reading `go.mod`, `go.sum`, `vendor/modules.txt`
- `afero.Afero.Exists()` for checking file presence
- `afero.Afero.IsDir()` for directory detection

### File Size

- `go.mod`: Typically small (< 10KB even for large projects)
- `go.sum`: Can be larger (100KB+ for projects with many dependencies) but still text-based and line-oriented, so streaming line-by-line is efficient
- `vendor/modules.txt`: Similar size characteristics to `go.mod`

No special file size handling is needed for Go ecosystem files.

### Search Paths

Default search locations for Go projects:
- Project root directories containing `go.mod`
- `/app`, `/home/*/go`, `/usr/local/go` for container images
- Configurable via `go.packages(path: "/custom/path")`

---

## Verification Plan

### Fixture-Based Tests
- Real-world `go.mod` files from popular projects (Kubernetes, Docker, Terraform)
- Edge cases: pseudo-versions, replace directives, exclude directives, major version suffixes
- Multiple `require` blocks, single-line requires
- `go.sum` with hundreds of entries
- `vendor/modules.txt` with explicit/implicit markers

### Interactive Testing
- Local: `mql run os -c "go.packages { root directDependencies }"`
- Remote: Same query over SSH to verify `afero.Fs` works end-to-end
- Container: Scan a Go-based container image (e.g., `golang:1.21`)

### PURL Validation
- Verify generated PURLs match the PURL spec for the `golang` type
- Test scoped paths, major version suffixes, pseudo-versions

### CPE Validation
- Verify CPE generation for common Go module path patterns
- Test edge cases: modules with deeply nested paths, stdlib modules

---

## Implementation Plan

### Phase 1 (This PR)
1. `go.mod` parser with direct/indirect classification
2. `go.sum` parser for hash extraction and transitive dependency listing
3. MQL resources: `go.packages`, `go.package`
4. PURL and CPE generation
5. SBOM generator integration

### Phase 2 (Follow-up PR)
1. `vendor/modules.txt` parser
2. Go binary analysis via `debug/buildinfo`
3. `replace` directive resolution
