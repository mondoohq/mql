// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pomproperties

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestPomPropertiesExtractorSimple(t *testing.T) {
	f, err := os.Open("./testdata/simple.pom.properties")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "META-INF/maven/org.apache.commons/commons-lang3/pom.properties")
	require.NoError(t, err)

	root := info.Root()
	require.NotNil(t, root)
	assert.Equal(t, "org.apache.commons:commons-lang3", root.Name)
	assert.Equal(t, "3.12.0", root.Version)
	assert.Equal(t, "pkg:maven/org.apache.commons/commons-lang3@3.12.0", root.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "META-INF/maven/org.apache.commons/commons-lang3/pom.properties"}}, root.EvidenceList)

	// pom.properties has no direct deps
	assert.Nil(t, info.Direct())

	// Transitive returns the single package
	transitive := info.Transitive()
	assert.Equal(t, 1, len(transitive))
	assert.Equal(t, "org.apache.commons:commons-lang3", transitive[0].Name)
}

func TestPomPropertiesExtractorGuava(t *testing.T) {
	f, err := os.Open("./testdata/guava.pom.properties")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/pom.properties")
	require.NoError(t, err)

	root := info.Root()
	require.NotNil(t, root)
	assert.Equal(t, "com.google.guava:guava", root.Name)
	assert.Equal(t, "31.1-jre", root.Version)
	assert.Equal(t, "pkg:maven/com.google.guava/guava@31.1-jre", root.Purl)
}

// liblightcouch-java 0.0.6-1.1 on Debian 11 ships a pom.properties without
// groupId at META-INF/maven/org.lightcouch/lightcouch/pom.properties.
func TestPomPropertiesExtractorGroupIdFromEntryPath(t *testing.T) {
	f, err := os.Open("./testdata/lightcouch-no-groupid.pom.properties")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{EntryPath: "META-INF/maven/org.lightcouch/lightcouch/pom.properties"}
	info, err := e.Parse(f, "/usr/share/java/lightcouch.jar")
	require.NoError(t, err)

	root := info.Root()
	require.NotNil(t, root)
	assert.Equal(t, "org.lightcouch:lightcouch", root.Name)
	assert.Equal(t, "0.0.6", root.Version)
	assert.Equal(t, "pkg:maven/org.lightcouch/lightcouch@0.0.6", root.Purl)
}

func TestPomPropertiesExtractorGroupIdFromEntryPathGuards(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		entryPath string
		wantName  string
	}{
		{
			name:      "explicit groupId wins over the path",
			content:   "groupId=com.example\nartifactId=lightcouch\nversion=0.0.6\n",
			entryPath: "META-INF/maven/org.lightcouch/lightcouch/pom.properties",
			wantName:  "com.example:lightcouch",
		},
		{
			name:      "artifactId does not match the path",
			content:   "artifactId=other\nversion=1.0\n",
			entryPath: "META-INF/maven/org.lightcouch/lightcouch/pom.properties",
			wantName:  "other",
		},
		{
			name:      "path is not META-INF/maven/<g>/<a>/pom.properties",
			content:   "artifactId=lightcouch\nversion=0.0.6\n",
			entryPath: "META-INF/maven/lightcouch/pom.properties",
			wantName:  "lightcouch",
		},
		{
			name:      "no entry path",
			content:   "artifactId=lightcouch\nversion=0.0.6\n",
			entryPath: "",
			wantName:  "lightcouch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := (&Extractor{EntryPath: tt.entryPath}).Parse(strings.NewReader(tt.content), "x.jar")
			require.NoError(t, err)
			root := info.Root()
			require.NotNil(t, root)
			assert.Equal(t, tt.wantName, root.Name)
		})
	}
}
