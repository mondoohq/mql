// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package buildgradle

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectPropertiesFile(t *testing.T) {
	props := CollectPropertiesFile(strings.NewReader(`
# a comment
androidxAnnotationVersion=1.3.0
junitVersion = 4.13.2
kotlinVersion=2.0.21

# build settings share the namespace and must not become versions
org.gradle.jvmargs=-Xmx4g
android.useAndroidX=true
systemProp.http.proxyHost=proxy.example.com
POM_NAME=demo
empty=
`))

	assert.Equal(t, "1.3.0", props["androidxAnnotationVersion"])
	assert.Equal(t, "4.13.2", props["junitVersion"], "surrounding whitespace is trimmed")
	assert.Equal(t, "2.0.21", props["kotlinVersion"])

	// A gradle.properties carries build configuration alongside versions, and
	// a script interpolating $x would otherwise be able to pick one up.
	for _, k := range []string{"org.gradle.jvmargs", "android.useAndroidX", "systemProp.http.proxyHost", "POM_NAME", "empty"} {
		assert.NotContains(t, props, k, "%s is not a version property", k)
	}
}

func TestCollectScriptProperties(t *testing.T) {
	// The shape ExoPlayer uses: every version in one root script, inside a
	// project.ext block, applied into the modules.
	props := CollectScriptProperties(strings.NewReader(`
// Copyright notice
project.ext {
    androidxAnnotationVersion = '1.3.0'
    truthVersion = '1.1.3'
}
def log4jVersion = '2.14.1'
val kotlinVersion = "2.0.21"
ext.snakeyamlVersion = '1.29'
`))

	assert.Equal(t, "1.3.0", props["androidxAnnotationVersion"])
	assert.Equal(t, "1.1.3", props["truthVersion"])
	assert.Equal(t, "2.14.1", props["log4jVersion"])
	assert.Equal(t, "2.0.21", props["kotlinVersion"])
	assert.Equal(t, "1.29", props["snakeyamlVersion"])
}

// TestExternalPropertiesResolveAVersion is the case the field exists for: a
// module's script names a version it does not declare, and without the
// project's properties the dependency is inventoried with no version — which no
// advisory can match.
func TestExternalPropertiesResolveAVersion(t *testing.T) {
	script := `
dependencies {
    implementation "androidx.annotation:annotation:$androidxAnnotationVersion"
    implementation 'com.google.truth:truth:' + truthVersion
}
`
	bare, err := (&Extractor{}).Parse(strings.NewReader(script), "build.gradle")
	require.NoError(t, err)
	assert.Empty(t, bare.Transitive().Find("androidx.annotation:annotation").Version,
		"with no project properties the version is unknown, never invented")

	e := &Extractor{Properties: map[string]string{
		"androidxAnnotationVersion": "1.3.0",
		"truthVersion":              "1.1.3",
	}}
	bom, err := e.Parse(strings.NewReader(script), "build.gradle")
	require.NoError(t, err)

	assert.Equal(t, "1.3.0", bom.Transitive().Find("androidx.annotation:annotation").Version, "interpolation")
	assert.Equal(t, "1.1.3", bom.Transitive().Find("com.google.truth:truth").Version, "concatenation")
}

// TestOwnDeclarationsBeatExternalProperties pins Gradle's precedence: a module
// that declares a version locally overrides the project-wide one.
func TestOwnDeclarationsBeatExternalProperties(t *testing.T) {
	e := &Extractor{Properties: map[string]string{"okioVersion": "1.0.0"}}
	bom, err := e.Parse(strings.NewReader(`
def okioVersion = '3.9.0'
dependencies {
    implementation "com.squareup.okio:okio:$okioVersion"
}
`), "build.gradle")
	require.NoError(t, err)

	assert.Equal(t, "3.9.0", bom.Transitive().Find("com.squareup.okio:okio").Version,
		"the script's own declaration wins over the project-wide property")
}

// Requiring "version" in the key was the obvious filter and the wrong one:
// projects routinely name a version property after the library rather than
// after the word, and dropping those leaves exactly the versionless coordinates
// this collector exists to fill in.
func TestCollectPropertiesFileKeepsVersionsNotNamedVersion(t *testing.T) {
	props := CollectPropertiesFile(strings.NewReader(`
kotlinCoroutines=1.7.3
okhttpRelease=4.12.0
agp=8.5.2
composeBom=2024.09.00
compileSdk=34
retrofit=v2.11.0

# still not versions, and now told apart by their values rather than their names
useAndroidX=true
jvmargs=-Xmx4g
buildDir=build/output
description=a demo project
`))

	for k, want := range map[string]string{
		"kotlinCoroutines": "1.7.3",
		"okhttpRelease":    "4.12.0",
		"agp":              "8.5.2",
		"composeBom":       "2024.09.00",
		// An integer is what Gradle would substitute, so it is what gets read.
		"compileSdk": "34",
		"retrofit":   "v2.11.0",
	} {
		assert.Equal(t, want, props[k], "%s is a version property", k)
	}

	for _, k := range []string{"useAndroidX", "jvmargs", "buildDir", "description"} {
		assert.NotContains(t, props, k, "%s is a build setting, not a version", k)
	}
}
