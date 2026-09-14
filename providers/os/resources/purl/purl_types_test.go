// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package purl_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

func TestValidType(t *testing.T) {
	t.Run("Valid types should return true", func(t *testing.T) {
		validTypes := []purl.Type{
			purl.TypeWindows, purl.TypeAppx, purl.TypeMacos, purl.TypeGeneric,
			purl.TypeApk, purl.TypeDebian, purl.TypeAlpm, purl.TypeRPM,
			purl.Type_X_Platform, purl.TypeSnap, purl.TypeFlatpak, purl.TypeCos,
			purl.TypeWindowsDriver, purl.TypeEbuild, purl.TypeNix, purl.TypeGithub,
		}

		for _, validType := range validTypes {
			assert.True(t,
				purl.ValidType(validType),
				"Expected type %s to be valid", validType)
		}
	})

	t.Run("Invalid types should return false", func(t *testing.T) {
		invalidTypes := []purl.Type{"invalid", "unknown", purl.Type("random")}

		for _, invalidType := range invalidTypes {
			assert.False(t,
				purl.ValidType(invalidType),
				"Expected type %s to be invalid", invalidType)
		}
	})

	t.Run("Empty type should return false", func(t *testing.T) {
		assert.False(t,
			purl.ValidType(purl.Type("")),
			"Expected empty type to be invalid")
	})
}

func TestValidTypeString(t *testing.T) {
	t.Run("Valid type strings should return true", func(t *testing.T) {
		validTypes := []string{
			string(purl.TypeWindows), string(purl.TypeAppx), string(purl.TypeMacos),
			packageurl.TypeGeneric, packageurl.TypeApk, packageurl.TypeDebian,
			packageurl.TypeAlpm, packageurl.TypeRPM, "windows", "appx", "macos",
			"platform", string(purl.Type_X_Platform),
			// Types mql actively emits. "snap" regressed once already: it was
			// declared and shipped by snap_packages.go while missing from
			// KnownTypes, so every caller gating on ValidTypeString rejected a
			// package mql itself had produced.
			"snap", "flatpak", "cos", "windows-driver", "github",
		}

		for _, validType := range validTypes {
			assert.True(t,
				purl.ValidTypeString(validType),
				"Expected type string %s to be valid", validType)
		}
	})

	t.Run("Invalid type strings should return false", func(t *testing.T) {
		invalidTypes := []string{"invalid", "unknown", "random"}

		for _, invalidType := range invalidTypes {
			assert.False(t, purl.ValidTypeString(invalidType), "Expected type string %s to be invalid", invalidType)
		}
	})

	t.Run("Empty type string should return false", func(t *testing.T) {
		assert.False(t,
			purl.ValidTypeString(""),
			"Expected empty type string to be invalid")
	})
}

// TestEveryDeclaredTypeIsRegistered is the structural guard behind the "snap"
// regression: a purl type is declared in one place and registered in another,
// and nothing but this test connects the two. Adding a Type* var without a
// KnownTypes entry makes ValidType reject a type mql ships.
func TestEveryDeclaredTypeIsRegistered(t *testing.T) {
	fset := token.NewFileSet()
	// Relative to the package directory, which is where `go test` runs a test
	// binary regardless of where the `go test` command itself was invoked.
	file, err := parser.ParseFile(fset, "purl_types.go", nil, 0)
	require.NoError(t, err, "purl_types.go must parse")

	declared := []string{}
	registered := map[string]bool{}

	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valueSpec.Names {
				if strings.HasPrefix(name.Name, "Type") {
					declared = append(declared, name.Name)
					continue
				}
				if name.Name != "KnownTypes" || i >= len(valueSpec.Values) {
					continue
				}
				composite, ok := valueSpec.Values[i].(*ast.CompositeLit)
				require.True(t, ok, "KnownTypes must be a composite literal")
				for _, element := range composite.Elts {
					keyValue, ok := element.(*ast.KeyValueExpr)
					require.True(t, ok, "KnownTypes entries must be key/value pairs")
					key, ok := keyValue.Key.(*ast.Ident)
					require.True(t, ok, "KnownTypes keys must be Type identifiers")
					registered[key.Name] = true
				}
			}
		}
	}

	require.NotEmpty(t, declared, "no purl types found, the parser found the wrong file")
	for _, name := range declared {
		assert.True(t, registered[name],
			"purl.%s is declared but missing from KnownTypes, so ValidType rejects it", name)
	}
}
