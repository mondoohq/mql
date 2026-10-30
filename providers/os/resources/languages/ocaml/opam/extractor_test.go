// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package opam

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

func TestParseLocked(t *testing.T) {
	f, err := os.Open("testdata/example.opam.locked")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "testdata/example.opam.locked")
	require.NoError(t, err)

	root := bom.Root()
	require.NotNil(t, root)
	assert.Equal(t, "example", root.Name)
	assert.Equal(t, "0.3.1", root.Version)
	assert.Equal(t, "pkg:opam/example@0.3.1", root.Purl)

	assert.Nil(t, bom.Transitive())

	deps := bom.Direct()
	assert.Len(t, deps, 6)

	// Pinned version parsed out of the {= "x"} formula.
	dune := deps.Find("dune")
	require.NotNil(t, dune)
	assert.Equal(t, "3.6.1", dune.Version)
	assert.Equal(t, "pkg:opam/dune@3.6.1", dune.Purl)
	assert.Equal(t, languages.PackageScopeProd, dune.Scope)

	fmtPkg := deps.Find("fmt")
	require.NotNil(t, fmtPkg)
	assert.Equal(t, "0.9.0", fmtPkg.Version)

	// with-test / with-doc dependencies are scoped dev.
	alcotest := deps.Find("alcotest")
	require.NotNil(t, alcotest)
	assert.Equal(t, languages.PackageScopeDev, alcotest.Scope, "with-test → dev")
	odoc := deps.Find("odoc")
	require.NotNil(t, odoc)
	assert.Equal(t, languages.PackageScopeDev, odoc.Scope, "with-doc → dev")
}

func TestParsePlain(t *testing.T) {
	f, err := os.Open("testdata/plain.opam")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "path/to/plain.opam")
	require.NoError(t, err)

	// No name: field → name derived from the filename.
	root := bom.Root()
	require.NotNil(t, root)
	assert.Equal(t, "plain", root.Name)
	assert.Equal(t, "", root.Version)
	assert.Equal(t, "pkg:opam/plain", root.Purl)

	deps := bom.Direct()
	assert.Len(t, deps, 3)
	// Unpinned constraint ({>= ...}) yields no concrete version.
	lwt := deps.Find("lwt")
	require.NotNil(t, lwt)
	assert.Equal(t, "", lwt.Version)
	assert.Equal(t, "pkg:opam/lwt", lwt.Purl)
	ocaml := deps.Find("ocaml")
	require.NotNil(t, ocaml)
	assert.Equal(t, "", ocaml.Version, "constraint-only dep has no pinned version")
}

// TestParseDependsDisjunction verifies that an opam `|` disjunction keeps only
// the first alternative and that brackets/braces inside quoted strings do not
// throw off the tokenizer.
func TestParseDependsDisjunction(t *testing.T) {
	content := `opam-version: "2.0"
name: "disj"
depends: [
  "ocaml" {>= "4.08"}
  "alt-a" | "alt-b"
  "conf-pkg" {= "1.0"}
]
`
	f, err := parseOpam(content)
	require.NoError(t, err)
	f.name = packageName(f.declaredName, "disj.opam")
	deps := f.Direct()

	names := map[string]bool{}
	for _, d := range deps {
		names[d.Name] = true
	}
	assert.True(t, names["ocaml"], "ocaml kept")
	assert.True(t, names["alt-a"], "first disjunction branch kept")
	assert.False(t, names["alt-b"], "second disjunction branch dropped")
	assert.True(t, names["conf-pkg"], "dependency after a disjunction still parsed")
}

func TestName(t *testing.T) {
	e := &Extractor{}
	assert.Equal(t, "opam", e.Name())
}

// merlin.opam (merlin 5.x) comments a dependency out with a `#` line, and opam
// also has `(* ... *)` block comments. Both were read as dependencies, so
// merlin listed "reason". Fails if either comment form is tokenized again.
func TestParseDependsSkipsComments(t *testing.T) {
	content := `opam-version: "2.0"
depends: [
  "dune" {>= "3.0.0"}
  "merlin-lib" {= version}
  "ppx_let" {with-test}
#  "reason" {with-test} Removed temporarily until reason is compatible with 5.5
  (* "menhir" {>= "20201216"}
     "csexp" (* nested *) *)
  "yojson" {>= "2.0.0"} # trailing "comment" with a ] bracket
  "str#ing" {= "1.0"}
]
`
	bom, err := (&Extractor{}).Parse(strings.NewReader(content), "merlin.opam")
	require.NoError(t, err)
	var names []string
	for _, p := range bom.Direct() {
		names = append(names, p.Name)
	}
	assert.Equal(t, []string{"dune", "merlin-lib", "ppx_let", "yojson", "str#ing"}, names)
}

// A depends list that never closes is a truncated file, not one without
// dependencies.
func TestParseDependsUnterminated(t *testing.T) {
	_, err := (&Extractor{}).Parse(strings.NewReader("depends: [ \"unterminated\n"), "dune.opam")
	assert.Error(t, err)

	bom, err := (&Extractor{}).Parse(strings.NewReader("opam-version: \"2.0\"\n"), "dune.opam")
	require.NoError(t, err)
	assert.Empty(t, bom.Direct())
}
