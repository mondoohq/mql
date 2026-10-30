// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gemspec

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGemspecExtractor(t *testing.T) {
	f, err := os.Open("./testdata/example.gemspec")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/inspec.gemspec")
	require.NoError(t, err)

	// Root
	root := info.Root()
	require.NotNil(t, root)
	assert.Equal(t, "inspec", root.Name)
	assert.Equal(t, "6.8.1", root.Version)
	assert.Equal(t, "pkg:gem/inspec@6.8.1", root.Purl)
	// The fixture states `spec.license = "Apache-2.0"`. It was parsed and then
	// dropped on the floor until this was fixed.
	assert.Equal(t, "Apache-2.0", root.License)

	// Direct = non-dev deps
	direct := info.Direct()
	assert.Equal(t, 3, len(direct))
	assert.NotNil(t, direct.Find("train"))
	assert.NotNil(t, direct.Find("rake"))
	assert.NotNil(t, direct.Find("mongo"))
	assert.Nil(t, direct.Find("minitest")) // dev dep excluded

	// Transitive = all declared deps
	transitive := info.Transitive()
	assert.Equal(t, 4, len(transitive))
	assert.NotNil(t, transitive.Find("minitest"))

	// Exact pin "= 2.13.2" — versioned PURL with extracted version
	mongo := direct.Find("mongo")
	require.NotNil(t, mongo)
	assert.Equal(t, "= 2.13.2", mongo.Version)
	assert.Equal(t, "pkg:gem/mongo@2.13.2", mongo.Purl)

	// Range constraint — versionless PURL
	train := direct.Find("train")
	require.NotNil(t, train)
	assert.Equal(t, "~> 3.10", train.Version)
	assert.Equal(t, "pkg:gem/train", train.Purl) // versionless

	// No constraint — versionless PURL
	rake := direct.Find("rake")
	require.NotNil(t, rake)
	assert.Equal(t, "", rake.Version)
	assert.Equal(t, "pkg:gem/rake", rake.Purl)
}

// TestGemspecLicenseForms is the regression test for a gemspec's license being
// read but never reported: the extractor matched name, version and
// dependencies, and left Package.License empty even when the file said
// `spec.license = "Apache-2.0"` — which the checked-in fixture does.
//
// RubyGems accepts two spellings of the same field. `license=` sets a
// one-element list and `licenses=` sets the list directly, so a gemspec that
// writes both ends up with whichever it wrote last.
func TestGemspecLicenseForms(t *testing.T) {
	for _, c := range []struct {
		name string
		spec string
		want string
	}{
		{
			name: "singular license",
			spec: `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.license = "Apache-2.0"
end`,
			want: "Apache-2.0",
		},
		{
			name: "singular license, single quotes",
			spec: "Gem::Specification.new do |spec|\n  spec.name = 'example'\n  spec.license = 'MIT'\nend",
			want: "MIT",
		},
		{
			// A list is a choice among the members, rendered as SPDX's OR.
			name: "plural licenses",
			spec: `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.licenses = ["MIT", "Apache-2.0"]
end`,
			want: "(MIT OR Apache-2.0)",
		},
		{
			// A one-element list must not acquire parentheses: "(MIT)" is a
			// different string to every consumer comparing identifiers.
			name: "plural licenses with one member",
			spec: `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.licenses = ["MIT"]
end`,
			want: "MIT",
		},
		{
			// The plural form must not be mistaken for the singular one, which
			// would report only the first member.
			name: "plural form is not read as the singular one",
			spec: `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.licenses = ["MIT", "GPL-2.0", "BSD-3-Clause"]
end`,
			want: "(MIT OR GPL-2.0 OR BSD-3-Clause)",
		},
		{
			// Ruby semantics: the second assignment replaces the first.
			name: "last assignment wins",
			spec: `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.licenses = ["MIT", "Apache-2.0"]
  spec.license = "MIT"
end`,
			want: "MIT",
		},
		{
			// A gemspec that declared nothing must report nothing rather than
			// an empty expression that reads as a declaration.
			name: "no license stated",
			spec: `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.version = "1.0.0"
end`,
			want: "",
		},
		{
			name: "empty license value",
			spec: `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.license = ""
end`,
			want: "",
		},
		{
			// The name is not a license: an unrelated `.name =` line must not
			// leak into the field.
			name: "license is not confused with other fields",
			spec: `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.homepage = "https://example.com"
end`,
			want: "",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			info, err := (&Extractor{}).Parse(strings.NewReader(c.spec), "example.gemspec")
			require.NoError(t, err)
			root := info.Root()
			require.NotNil(t, root)
			assert.Equal(t, c.want, root.License)
		})
	}
}

// TestGemspecLicenseBounds covers the size bounds on a gemspec's license. The
// patterns here are line-scoped but unbounded within a line, and a .gemspec is
// read out of a gem someone else published, so the length of the value is the
// publisher's choice — and it flows on into SBOM documents and generated NOTICE
// files.
//
// The cap is a literal here rather than the constant the implementation reads:
// an expectation taken from the same constant would move with it and pin
// nothing.
func TestGemspecLicenseBounds(t *testing.T) {
	// A license identifier of exactly n bytes, carrying no quote to close the
	// Ruby string early.
	name := func(n int) string { return strings.Repeat("a", n) }

	// 100 valid identifiers on one `licenses = [...]` line. Each is fine on its
	// own; the expression they join into is not a license statement.
	many := "\"" + strings.Join(func() []string {
		out := make([]string, 100)
		for i := range out {
			out[i] = "GPL-2.0-or-later"
		}
		return out
	}(), "\", \"") + "\""

	for _, c := range []struct {
		name string
		spec string
		want string
	}{
		{
			// A real name is nowhere near the cap and must keep being reported.
			name: "a full license name is well under the cap",
			spec: "Gem::Specification.new do |spec|\n  spec.name = \"example\"\n" +
				"  spec.license = \"GNU Lesser General Public License, Version 2.1\"\nend",
			want: "GNU Lesser General Public License, Version 2.1",
		},
		{
			name: "an oversized singular license is dropped",
			spec: "Gem::Specification.new do |spec|\n  spec.name = \"example\"\n" +
				"  spec.license = \"" + name(300) + "\"\nend",
			want: "",
		},
		{
			// The oversized member is the only thing wrong with the list.
			name: "an oversized member does not take its siblings with it",
			spec: "Gem::Specification.new do |spec|\n  spec.name = \"example\"\n" +
				"  spec.licenses = [\"" + name(300) + "\", \"MIT\"]\nend",
			want: "MIT",
		},
		{
			name: "a list past the total cap is dropped",
			spec: "Gem::Specification.new do |spec|\n  spec.name = \"example\"\n" +
				"  spec.licenses = [" + many + "]\nend",
			want: "",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			info, err := (&Extractor{}).Parse(strings.NewReader(c.spec), "example.gemspec")
			require.NoError(t, err)
			root := info.Root()
			require.NotNil(t, root)
			assert.Equal(t, c.want, root.License)
		})
	}
}

// A commented-out line states nothing. Reading one reports a gem under a
// license it does not declare, and a wrong license is worse than none: nothing
// downstream can tell it from a real declaration.
func TestGemspecIgnoresCommentedOutLines(t *testing.T) {
	spec, err := parseGemspec(strings.NewReader(`Gem::Specification.new do |spec|
  spec.name = "demo"
  spec.version = "1.0.0"
  # spec.license = "GPL-3.0"
  # spec.licenses = ["AGPL-3.0-only"]
end`))
	require.NoError(t, err)

	assert.Empty(t, spec.Licenses, "a commented-out license must not be read")
	assert.Equal(t, "demo", spec.Name)
	assert.Equal(t, "1.0.0", spec.Version)
}

// The commented-out form must not shadow a real one stated elsewhere.
func TestGemspecReadsTheUncommentedLicense(t *testing.T) {
	spec, err := parseGemspec(strings.NewReader(`Gem::Specification.new do |spec|
  spec.name = "demo"
  # spec.license = "GPL-3.0"
  spec.license = "MIT"
end`))
	require.NoError(t, err)
	assert.Equal(t, []string{"MIT"}, spec.Licenses)
}
