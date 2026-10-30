# ADR: cnspec SBOM Cataloger for Java

**Status:** Proposed
**Date:** 2026-04-16

---

## Context

cnspec needs native SBOM cataloging for Java/JVM packages to detect dependencies in both local and remote scanning contexts (SSH, WinRM, containers). Java is one of the most widely deployed ecosystems in enterprise environments, with applications packaged as JAR, WAR, and EAR archives containing embedded metadata about their dependencies.

The Java ecosystem uses two primary build systems — Maven and Gradle — each with distinct dependency declaration and lock file formats. Additionally, compiled Java archives (JAR files) embed dependency metadata that can be extracted without access to build files.

---

## File Formats

### pom.properties (Inside JAR Archives)

Located at `META-INF/maven/<groupId>/<artifactId>/pom.properties` inside JAR files. This is the most reliable source of Maven coordinates for packaged artifacts.

```properties
groupId=org.apache.commons
artifactId=commons-lang3
version=3.12.0
```

**Key fields:** `groupId`, `artifactId`, `version` — the Maven coordinate triple.

### MANIFEST.MF (Inside JAR Archives)

Located at `META-INF/MANIFEST.MF` inside JAR files. Contains implementation metadata.

```
Manifest-Version: 1.0
Implementation-Title: commons-lang3
Implementation-Version: 3.12.0
Implementation-Vendor: The Apache Software Foundation
Bundle-SymbolicName: org.apache.commons.lang3
Bundle-Version: 3.12.0
```

**Key fields:**
- `Implementation-Title` / `Implementation-Version`: Package name and version
- `Bundle-SymbolicName` / `Bundle-Version`: OSGi bundle metadata (common in enterprise JARs)
- `Implementation-Vendor`: Vendor information for CPE generation

### pom.xml (Maven Project Model)

Maven project descriptor declaring dependencies.

```xml
<project>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
```

**Key elements:** `<dependency>` blocks with `groupId`, `artifactId`, `version`, and optional `scope` (compile, test, provided, runtime).

### gradle.lockfile (Gradle Lock File)

Gradle dependency lock file with resolved versions.

```
# This is a Gradle generated file for dependency locking.
# Manual edits can mess up your build.
# This file is expected to be part of source control.
org.apache.commons:commons-lang3:3.12.0=compileClasspath,runtimeClasspath
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
```

**Format:** Each line is `<group>:<artifact>:<version>=<configuration1>,<configuration2>,...`. Lines starting with `#` are comments. An `empty=` line marks the end.

### JAR/WAR/EAR Archives

Java archive files are ZIP-format archives:
- **JAR** (Java Archive): Libraries and applications
- **WAR** (Web Application Archive): Web applications, may contain JARs in `WEB-INF/lib/`
- **EAR** (Enterprise Application Archive): Enterprise apps, may contain JARs and WARs

Spring Boot "fat JARs" contain nested JARs in `BOOT-INF/lib/` or `lib/`.

---

## Parsing Strategy

### Archive Scanner (Image Scans)

1. Walk the filesystem for `*.jar`, `*.war`, `*.ear` files via `afero.Fs`
2. For each archive:
   a. Read the ZIP file contents (via `archive/zip` with `io.ReaderAt` from `afero.File`, or by reading into memory for remote fs)
   b. Look for `META-INF/maven/**/pom.properties` — extract groupId, artifactId, version
   c. If no pom.properties, fall back to `META-INF/MANIFEST.MF` — extract Implementation-Title/Version
   d. For WAR files: scan `WEB-INF/lib/*.jar` entries as nested archives
   e. For fat JARs: scan `BOOT-INF/lib/*.jar` or `lib/*.jar` entries as nested archives
3. Deduplicate packages by groupId:artifactId:version

### pom.xml Parser (Directory Scans)

1. Read `pom.xml` via `afero.Fs`
2. Parse XML using `encoding/xml`
3. Extract `<project>` coordinates (root package)
4. Extract `<dependencies>` with groupId, artifactId, version, scope
5. Classify: `scope=test` or `scope=provided` → dev dependency; all others → production

### gradle.lockfile Parser (Directory Scans)

1. Read `gradle.lockfile` via `afero.Fs`
2. Parse line by line: `group:artifact:version=configurations`
3. Classify: configurations containing `test` → dev dependency; others → production

### Error Handling

- Corrupt or unreadable ZIP archives produce a warning and are skipped
- Missing pom.properties in a JAR falls back to MANIFEST.MF
- If neither is present, the JAR filename is parsed as a last resort (name-version.jar pattern)
- Malformed XML in pom.xml produces a warning and partial results
- Remote scanning: large JARs (>50MB) are skipped with a warning to avoid excessive memory usage

---

## Package Identification

### PURL (Package URL)

Format: `pkg:maven/<groupId>/<artifactId>@<version>`

Examples:
- `pkg:maven/org.apache.commons/commons-lang3@3.12.0`
- `pkg:maven/com.google.guava/guava@31.1-jre`

Per the [PURL spec for Maven](https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/maven-definition.md):
- Type: `maven`
- Namespace: groupId
- Name: artifactId
- Version: Maven version string

### CPE Generation

Format: `cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*`

For Maven packages:
- Vendor: derived from groupId (last segment, e.g., `apache` from `org.apache.commons`)
- Product: artifactId
- Version: numeric version

### License Extraction

Licenses can be found in:
- `META-INF/LICENSE` files inside JARs
- `<licenses>` element in pom.xml
- MANIFEST.MF `Bundle-License` header

Initial implementation focuses on pom.xml `<licenses>` parsing. Remote license lookup via Maven Central is deferred.

---

## Dev/Prod Classification

### From pom.xml
- `<scope>compile</scope>` or no scope → production
- `<scope>runtime</scope>` → production
- `<scope>test</scope>` → dev
- `<scope>provided</scope>` → dev (provided at runtime by container)

### From gradle.lockfile
- Configurations containing `test` (e.g., `testCompileClasspath`) → dev
- All other configurations → production

### From JAR scanning
- JARs found in `WEB-INF/lib/`, `BOOT-INF/lib/`, or application classpath → production
- No dev/prod distinction available from archive scanning alone

---

## Dependency Relationships

### From pom.xml
Direct dependencies are listed in `<dependencies>`. Transitive dependencies are not resolved (would require downloading the full dependency tree from Maven Central). The parser reports only declared dependencies.

### From gradle.lockfile
All entries are resolved (transitives included). Direct vs. transitive is not distinguished in the lock file format.

### From JAR scanning
No dependency tree available — each JAR is an independent package entry.

---

## Remote Scanning Considerations

### afero.Fs Usage
- All file reads go through `afero.Fs`
- JAR/WAR/EAR files are opened via `afero.Fs.Open()` and read using `archive/zip`
- For local filesystems, `afero.File` implements `io.ReaderAt` (needed by `archive/zip`), enabling direct ZIP reading
- For remote filesystems (SSH/WinRM), files are read into memory using `io.ReadAll` then wrapped in `bytes.NewReader` to provide `io.ReaderAt`

### File Size Considerations
- JAR files are typically small (< 10MB)
- WAR/EAR files can be large (50-200MB+)
- Spring Boot fat JARs can be 50-100MB
- **Limit:** Skip archives exceeding a configurable size limit (default 100MB) with a warning
- Nested JAR scanning reads entries from the parent archive's ZIP reader (no additional disk I/O)

### Search Paths

Default search locations:
- `/app`, `/opt`, `/usr/local/lib` — common application deployment paths
- `WEB-INF/lib/`, `BOOT-INF/lib/` — inside WAR/fat JAR archives
- `~/.m2/repository` — local Maven cache (directory scans)
- Configurable via `java.packages(path: "/custom/path")`

---

## Verification Plan

### Fixture-Based Tests
- pom.properties: Simple key-value file
- MANIFEST.MF: Multi-line header format with continuation lines
- pom.xml: Project with dependencies across multiple scopes
- gradle.lockfile: Lock file with mixed configurations
- JAR file: Real JAR with embedded pom.properties and MANIFEST.MF
- Nested JARs: Spring Boot fat JAR structure

### Interactive Testing
- Local: `mql run os -c "java.packages(path: '.') { list { name version purl } }"`
- Container: Scan a Java-based container image (e.g., `eclipse-temurin:21`)
- Remote: Same query over SSH

### PURL/CPE Validation
- Verify Maven PURL format matches the spec
- Test groupId with various depth levels (org.apache.commons, com.google.guava)

---

## Implementation Plan

### Phase 1 (This PR)
1. pom.properties parser (simplest, most reliable source)
2. MANIFEST.MF parser (fallback metadata)
3. gradle.lockfile parser (simple line-oriented format)
4. pom.xml parser (XML dependency declarations)
5. JAR archive scanner with nested JAR support
6. MQL resources: `java.packages`, `java.package`
7. SBOM generator integration (type: `maven`)

### Phase 2 (Follow-up PR)
1. GraalVM native-image binary analysis
2. `build.gradle` / `build.gradle.kts` parsing
3. WAR/EAR deep scanning with per-archive grouping
