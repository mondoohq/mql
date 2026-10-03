// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

// writeTestJar writes a jar holding only the given pom.properties.
func writeTestJar(t *testing.T, fs afero.Fs, path, groupID, artifactID, version string) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("META-INF/maven/" + groupID + "/" + artifactID + "/pom.properties")
	require.NoError(t, err)
	_, err = f.Write([]byte("artifactId=" + artifactID + "\ngroupId=" + groupID + "\nversion=" + version + "\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, afero.WriteFile(fs, path, buf.Bytes(), 0o644))
}

// suseJavaFs is /usr/share/java on SLES 15 SP7 with the log4j and jackson
// rpms installed: the JPackage layout keeps a package's jars in its own
// subdirectory, next to top-level jars from other packages. The pom.properties
// coordinates are the ones in the rpm's jars.
func suseJavaFs(t *testing.T) *afero.Afero {
	fs := afero.NewMemMapFs()
	writeTestJar(t, fs, "/usr/share/java/jackson-core.jar", "com.fasterxml.jackson.core", "jackson-core", "2.18.11")
	writeTestJar(t, fs, "/usr/share/java/log4j/log4j-core.jar", "org.apache.logging.log4j", "log4j-core", "2.26.1")
	writeTestJar(t, fs, "/usr/share/java/log4j/log4j-api.jar", "org.apache.logging.log4j", "log4j-api", "2.26.1")
	writeTestJar(t, fs, "/usr/share/java/jackson-dataformats/jackson-dataformat-xml.jar", "com.fasterxml.jackson.dataformat", "jackson-dataformat-xml", "2.18.11")
	// Two levels down: past javaArchiveSearchDepth.
	writeTestJar(t, fs, "/usr/share/java/a/b/too-deep.jar", "example", "too-deep", "1.0")
	return &afero.Afero{Fs: fs}
}

func packageNames(pkgs []*languages.Package) []string {
	res := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		res = append(res, p.Name+"@"+p.Version)
	}
	return res
}

// Fails if the default search goes back to globbing <dir>/*.jar: log4j-core
// in /usr/share/java/log4j is then missed and a log4j version check passes on
// a host that has it installed. Also fails if the depth bound is dropped.
func TestJavaDefaultsFindJPackageSubdirectories(t *testing.T) {
	afs := suseJavaFs(t)
	_, transitive, files := collectJavaDefaults(afs, []string{"/usr/share/java"})
	assert.ElementsMatch(t, []string{
		"com.fasterxml.jackson.core:jackson-core@2.18.11",
		"com.fasterxml.jackson.dataformat:jackson-dataformat-xml@2.18.11",
		"org.apache.logging.log4j:log4j-api@2.26.1",
		"org.apache.logging.log4j:log4j-core@2.26.1",
	}, packageNames(transitive))
	assert.Contains(t, files, "/usr/share/java/log4j/log4j-core.jar")
	assert.NotContains(t, files, "/usr/share/java/a/b/too-deep.jar")
}

// java.packages(path: "/usr/share/java") goes through collectJavaFromDir.
// Fails if it skips subdirectories again.
func TestJavaPathDirFindsJPackageSubdirectories(t *testing.T) {
	afs := suseJavaFs(t)
	_, _, transitive, files, err := collectJavaFromDir(afs, "/usr/share/java")
	require.NoError(t, err)
	assert.Contains(t, packageNames(transitive), "org.apache.logging.log4j:log4j-core@2.26.1")
	assert.Contains(t, files, "/usr/share/java/jackson-dataformats/jackson-dataformat-xml.jar")
	assert.NotContains(t, files, "/usr/share/java/a/b/too-deep.jar")
}

// Fails if the depth argument is off by one (depth 0 must not enter any
// subdirectory, depth 1 must reach <dir>/a but not <dir>/a/b), or if
// non-matching files are listed.
func TestFindJavaArchivesDepth(t *testing.T) {
	fs := afero.NewMemMapFs()
	for _, p := range []string{"/d/top.jar", "/d/README", "/d/a/one.jar", "/d/a/b/two.jar", "/d/a/b/c/three.jar"} {
		require.NoError(t, afero.WriteFile(fs, p, []byte("x"), 0o644))
	}
	afs := &afero.Afero{Fs: fs}
	isJar := func(name string) bool { return len(name) > 4 && name[len(name)-4:] == ".jar" }

	got, err := findJavaArchives(afs, "/d", 0, isJar)
	require.NoError(t, err)
	assert.Equal(t, []string{"/d/top.jar"}, got)
	got, err = findJavaArchives(afs, "/d", 1, isJar)
	require.NoError(t, err)
	assert.Equal(t, []string{"/d/top.jar", "/d/a/one.jar"}, got)
	got, err = findJavaArchives(afs, "/missing", 2, isJar)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Empty(t, got)
}

// Application directories stay top-level: their node_modules and vendor
// trees made a default scan over SSH with --sudo take minutes when every
// default path was walked. Fails if the subdirectory walk is applied to every
// default path rather than defaultJavaArchiveTrees.
func TestJavaDefaultsWalkOnlyArchiveTrees(t *testing.T) {
	afs := suseJavaFs(t)
	writeTestJar(t, afs.Fs, "/opt/app.jar", "example", "app", "1.0")
	writeTestJar(t, afs.Fs, "/opt/someapp/lib/nested.jar", "example", "nested", "1.0")
	_, _, files := collectJavaDefaults(afs, []string{"/opt", "/usr/share/java"})
	assert.Contains(t, files, "/opt/app.jar")
	assert.Contains(t, files, "/usr/share/java/log4j/log4j-core.jar")
	assert.NotContains(t, files, "/opt/someapp/lib/nested.jar")
}

// One archive in a directory of jars that is not a valid archive is skipped,
// as before; it must not hide the others. Named on its own it is an error.
func TestJavaDirSkipsInvalidArchive(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeTestJar(t, mem, "/srv/lib/log4j-core-2.14.1.jar", "org.apache.logging.log4j", "log4j-core", "2.14.1")
	require.NoError(t, afero.WriteFile(mem, "/srv/lib/broken.jar", []byte("not a zip"), 0o644))
	afs := &afero.Afero{Fs: mem}

	_, _, transitive, _, err := collectJavaPackages(afs, "/srv/lib")
	require.NoError(t, err)
	assert.Equal(t, []string{"org.apache.logging.log4j:log4j-core@2.14.1"}, packageNames(transitive))

	_, _, _, _, err = collectJavaPackages(afs, "/srv/lib/broken.jar")
	assert.ErrorIs(t, err, llx.ErrMalformedData)
}

// A jar the scan may not read is a refusal, in a directory or on its own.
func TestJavaUnreadableArchive(t *testing.T) {
	withStructuredErrors(t, true)
	mem := afero.NewMemMapFs()
	jar := "/srv/priv/log4j-core-2.14.1.jar"
	writeTestJar(t, mem, jar, "org.apache.logging.log4j", "log4j-core", "2.14.1")
	afs := &afero.Afero{Fs: &unreadableFs{Fs: mem, files: []string{jar}}}

	for _, p := range []string{"/srv/priv", jar} {
		_, _, _, _, err := collectJavaPackages(afs, p)
		assert.ErrorIs(t, explicitLockfileError(err), llx.ErrForbidden, p)
	}
}
