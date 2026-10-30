// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jarscanner

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestJar creates a minimal JAR file with the given entries.
func createTestJar(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for name, content := range entries {
		f, err := w.Create(name)
		require.NoError(t, err)
		_, err = f.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, w.Close())
	return buf.Bytes()
}

func TestScanZipDataWithPomProperties(t *testing.T) {
	jarData := createTestJar(t, map[string]string{
		"META-INF/maven/org.apache.commons/commons-lang3/pom.properties": `groupId=org.apache.commons
artifactId=commons-lang3
version=3.12.0
`,
		"META-INF/MANIFEST.MF": `Manifest-Version: 1.0
Implementation-Title: commons-lang3
Implementation-Version: 3.12.0
`,
	})

	packages, err := scanZipData(jarData, "/app/libs/commons-lang3-3.12.0.jar", 0)
	require.NoError(t, err)
	require.Equal(t, 1, len(packages))

	// Should prefer pom.properties over MANIFEST.MF
	assert.Equal(t, "org.apache.commons:commons-lang3", packages[0].Name)
	assert.Equal(t, "3.12.0", packages[0].Version)
	assert.Equal(t, "pkg:maven/org.apache.commons/commons-lang3@3.12.0", packages[0].Purl)
}

func TestScanZipDataManifestFallback(t *testing.T) {
	jarData := createTestJar(t, map[string]string{
		"META-INF/MANIFEST.MF": `Manifest-Version: 1.0
Implementation-Title: my-library
Implementation-Version: 2.0.0
Implementation-Vendor: Example Corp
`,
	})

	packages, err := scanZipData(jarData, "/app/libs/my-library.jar", 0)
	require.NoError(t, err)
	require.Equal(t, 1, len(packages))

	// Falls back to MANIFEST.MF when no pom.properties
	assert.Equal(t, "my-library", packages[0].Name)
	assert.Equal(t, "2.0.0", packages[0].Version)
}

func TestScanZipDataNestedJar(t *testing.T) {
	// Create an inner JAR
	innerJar := createTestJar(t, map[string]string{
		"META-INF/maven/com.google.guava/guava/pom.properties": `groupId=com.google.guava
artifactId=guava
version=31.1-jre
`,
	})

	// Create an outer fat JAR containing the inner JAR in BOOT-INF/lib/
	var outerBuf bytes.Buffer
	outerWriter := zip.NewWriter(&outerBuf)

	// Add the main app's pom.properties
	f, err := outerWriter.Create("META-INF/maven/com.example/myapp/pom.properties")
	require.NoError(t, err)
	_, err = f.Write([]byte("groupId=com.example\nartifactId=myapp\nversion=1.0.0\n"))
	require.NoError(t, err)

	// Add the nested JAR
	f, err = outerWriter.Create("BOOT-INF/lib/guava-31.1-jre.jar")
	require.NoError(t, err)
	_, err = f.Write(innerJar)
	require.NoError(t, err)

	require.NoError(t, outerWriter.Close())

	packages, err := scanZipData(outerBuf.Bytes(), "/app/myapp.jar", 0)
	require.NoError(t, err)

	// Should find both the outer app and the nested guava JAR
	assert.Equal(t, 2, len(packages))

	names := map[string]bool{}
	for _, p := range packages {
		names[p.Name] = true
	}
	assert.True(t, names["com.example:myapp"])
	assert.True(t, names["com.google.guava:guava"])
}

func TestIsArchive(t *testing.T) {
	assert.True(t, IsArchive("commons-lang3.jar"))
	assert.True(t, IsArchive("myapp.war"))
	assert.True(t, IsArchive("enterprise.ear"))
	assert.True(t, IsArchive("/path/to/file.JAR"))
	assert.False(t, IsArchive("readme.txt"))
	assert.False(t, IsArchive("pom.xml"))
}

func TestScanArchiveIntegration(t *testing.T) {
	// Create a temp JAR file on disk
	jarData := createTestJar(t, map[string]string{
		"META-INF/maven/org.example/test-lib/pom.properties": `groupId=org.example
artifactId=test-lib
version=1.0.0
`,
	})

	tmpDir := t.TempDir()
	jarPath := filepath.Join(tmpDir, "test-lib-1.0.0.jar")
	require.NoError(t, os.WriteFile(jarPath, jarData, 0644))

	// Use afero OsFs to test the full path
	afs := aferoFromDir(tmpDir)
	packages, err := ScanArchive(afs, jarPath)
	require.NoError(t, err)
	require.Equal(t, 1, len(packages))
	assert.Equal(t, "org.example:test-lib", packages[0].Name)
}

func aferoFromDir(_ string) *afero.Afero {
	return &afero.Afero{Fs: afero.NewOsFs()}
}

// Debian's liblightcouch-java 0.0.6 (Debian 11): pom.properties has no groupId,
// the group is only in the entry path.
func TestScanZipDataPomPropertiesWithoutGroupId(t *testing.T) {
	jarData := createTestJar(t, map[string]string{
		"META-INF/maven/org.lightcouch/lightcouch/pom.properties": "#Created by Apache Maven 3.6.3\nartifactId=lightcouch\nversion=0.0.6\n",
	})

	packages, err := scanZipData(jarData, "/usr/share/java/lightcouch.jar", 0)
	require.NoError(t, err)
	require.Equal(t, 1, len(packages))
	assert.Equal(t, "org.lightcouch:lightcouch", packages[0].Name)
	assert.Equal(t, "pkg:maven/org.lightcouch/lightcouch@0.0.6", packages[0].Purl)
}
