// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package conanfile

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

func parse(t *testing.T, path string) languages.Packages {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, path)
	require.NoError(t, err)
	assert.Nil(t, bom.Root())
	assert.Nil(t, bom.Transitive(), "a conanfile declares only what the project requires")
	return bom.Direct()
}

func TestParseTxt(t *testing.T) {
	pkgs := parse(t, "testdata/conanfile.txt")

	zlib := pkgs.Find("zlib")
	require.NotNil(t, zlib)
	assert.Equal(t, "1.3.1", zlib.Version)
	assert.Equal(t, "pkg:conan/zlib@1.3.1", zlib.Purl)
	assert.Equal(t, languages.PackageScopeProd, zlib.Scope)

	// A range is not a version: reporting "[>=3.0 <4]" would produce a
	// coordinate that matches no advisory and reads as though it were one.
	openssl := pkgs.Find("openssl")
	require.NotNil(t, openssl)
	assert.Empty(t, openssl.Version)
	assert.Equal(t, "pkg:conan/openssl", openssl.Purl)

	mylib := pkgs.Find("mylib")
	require.NotNil(t, mylib)
	assert.Equal(t, "pkg:conan/acme/mylib@2.0?channel=stable", mylib.Purl)

	cmake := pkgs.Find("cmake")
	require.NotNil(t, cmake)
	assert.Equal(t, languages.PackageScopeDev, cmake.Scope, "tool_requires is build tooling")

	// An unknown section's entries are not requirements. Without the guard,
	// "CMakeDeps" and "zlib/*:shared=True" would be parsed as references.
	for _, notADep := range []string{"CMakeDeps", "CMakeToolchain"} {
		assert.Nil(t, pkgs.Find(notADep), "%s is a generator, not a dependency", notADep)
	}
	assert.Len(t, pkgs, 5)
}

func TestParsePy(t *testing.T) {
	pkgs := parse(t, "testdata/conanfile.py")

	zlib := pkgs.Find("zlib")
	require.NotNil(t, zlib)
	assert.Equal(t, "1.3.1", zlib.Version)
	assert.Equal(t, languages.PackageScopeProd, zlib.Scope)

	require.NotNil(t, pkgs.Find("fmt"))

	cmake := pkgs.Find("cmake")
	require.NotNil(t, cmake)
	assert.Equal(t, languages.PackageScopeDev, cmake.Scope)

	conanTools := pkgs.Find("conan-tools")
	require.NotNil(t, conanTools)
	assert.Equal(t, languages.PackageScopeDev, conanTools.Scope)

	// A requirements() method computes references at install time. Reading them
	// statically would recover a version from a partially evaluated Python
	// expression, which is worse than none: it looks resolved and matches the
	// wrong advisories. conan.lock is what answers for such a project.
	assert.Nil(t, pkgs.Find("openssl"), "a conditional self.requires() is not static")
	assert.Nil(t, pkgs.Find("boost"), "an f-string reference is not static")
	assert.Len(t, pkgs, 4)
}

// TestPyRecipeAttributesAreNotDependencies guards the fields most likely to be
// misread as a reference: a recipe's own name and version sit right beside the
// requires attributes it declares.
func TestPyRecipeAttributesAreNotDependencies(t *testing.T) {
	pkgs := parse(t, "testdata/conanfile.py")
	assert.Nil(t, pkgs.Find("app"))
	for _, p := range pkgs {
		assert.NotEqual(t, "os", p.Name, "a settings tuple is not a requirement")
	}
}

func TestParseTxtEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"no sections at all", "zlib/1.3.1\nfmt/10.2.1\n", nil},
		{"comment-only line", "[requires]\n# zlib/1.3.1\nfmt/10.2.1\n", []string{"fmt"}},
		{"blank file", "", nil},
		{"duplicate reference", "[requires]\nzlib/1.3.1\nzlib/1.3.1\n", []string{"zlib"}},
		{"uppercase section", "[REQUIRES]\nzlib/1.3.1\n", []string{"zlib"}},
		{"malformed reference is dropped", "[requires]\nnoversion\nzlib/1.3.1\n", []string{"zlib"}},
		{"conan 1 build_requires", "[build_requires]\ncmake/3.28.1\n", []string{"cmake"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bom, err := (&Extractor{}).Parse(strings.NewReader(tt.body), "conanfile.txt")
			require.NoError(t, err)
			var got []string
			for _, p := range bom.Direct() {
				got = append(got, p.Name)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestName(t *testing.T) {
	assert.Equal(t, "conanfile", (&Extractor{}).Name())
}
