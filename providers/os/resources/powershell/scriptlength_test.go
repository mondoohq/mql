// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers/os/resources/powershell"
)

// knownOverCap records the embedded scripts that already exceed the command-line
// cap. They are listed rather than fixed here because each needs a live target
// to verify a rewrite against, and both are tracked separately. The point of the
// list is that it may not grow: a script added or grown past the cap that is not
// on it fails this test.
//
// A script over the cap does not fail loudly. The target rejects the command
// before PowerShell runs, and the non-zero exit reads like the queried feature
// being absent — an empty answer rather than an error — which is how these
// shipped unnoticed.
var knownOverCap = map[string]string{
	// Sent to the target with powershell.Encode over the same path as
	// SCHEDULED_TASKS, so this is broken on Windows targets today. Needs a
	// Windows host to verify any rewrite: it walks the ProfileList registry
	// hive and the IdentityStore cache.
	"providers/os/resources/users/ps1getlocalusers.go:getLocalUsersScript": "tracked separately; needs a Windows host to verify a rewrite",

	// Runs on the *scanner* host, not a remote target, and only as a fallback
	// when the Exchange admin REST endpoint is unavailable. On a Linux or macOS
	// scanner the shell is `sh -c`, where ARG_MAX is megabytes and the cap does
	// not apply; it only breaks when the scanner itself runs Windows.
	"providers/ms365/resources/ms365_exchange.go:exchangeReport": "scanner-side fallback; only affected on a Windows scanner host",
}

// psMarkers identify a string literal as a PowerShell script.
var psMarkers = []string{
	"$ErrorActionPreference", "PSCustomObject", "ConvertTo-Json", "ForEach-Object",
	"Select-Object", "Where-Object", "Out-String", "Import-Module", "Get-Item",
	"Get-Content", "Get-CimInstance", "Get-WmiObject", "Get-ItemProperty",
	"Get-", "Set-", "New-Object", "Invoke-", "Test-Path", "Add-Type", "Export-",
	"$_.", "[System.", "-ErrorAction",
}

func looksLikePowerShell(s string) bool {
	n := 0
	for _, m := range psMarkers {
		if strings.Contains(s, m) {
			n++
		}
	}
	// Two independent markers keeps out incidental matches such as "Get-" in a URL.
	return n >= 2
}

// flattenStringExpr resolves a string literal, or a chain of "+"-concatenated
// string literals, into its value. Anything else yields ok=false.
func flattenStringExpr(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, leftOK := flattenStringExpr(v.X)
		r, rightOK := flattenStringExpr(v.Y)
		if !leftOK || !rightOK {
			return "", false
		}
		return l + r, true
	case *ast.ParenExpr:
		return flattenStringExpr(v.X)
	}
	return "", false
}

type scriptFinding struct {
	file, name string
	line       int
	src, enc   int
}

func (f scriptFinding) key() string { return f.file + ":" + f.name }

// TestEmbeddedPowerShellScriptsFitCommandLine measures every embedded PowerShell
// script in the tree against the command-line cap.
//
// It measures the *literal* length, which is what a static pass can see. Two
// classes of script are therefore only partly covered, and the headroom column
// is an upper bound for both:
//
//   - Templates filled in at run time. The ms365 reports interpolate OAuth
//     tokens, and the cloud metadata helpers interpolate IMDS tokens; a JWT is
//     itself on the order of a kilobyte, so several of these are much closer to
//     the cap in production than they read here.
//   - Scripts whose interpolated part is unbounded: SidLookupScript grows with
//     the number of local accounts, AclScript and the registry helpers with a
//     path, and filesfind.BuildPowershellCmd with MQL arguments the user wrote.
//
// Bounding those needs a check at the point of assembly rather than here.
func TestEmbeddedPowerShellScriptsFitCommandLine(t *testing.T) {
	root := "../../../.."

	var found []scriptFinding
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			// .claude holds developer worktrees, which are whole extra copies
			// of the tree and would be measured many times over.
			case ".git", ".claude", "node_modules", "dist", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		abs, _ := filepath.Abs(path)
		rootAbs, _ := filepath.Abs(root)
		rel, _ := filepath.Rel(rootAbs, abs)
		rel = filepath.ToSlash(rel)

		record := func(name string, e ast.Expr, pos token.Pos) {
			s, ok := flattenStringExpr(e)
			if !ok || len(s) < 120 || !looksLikePowerShell(s) {
				return
			}
			found = append(found, scriptFinding{
				file: rel, name: name, line: fset.Position(pos).Line,
				src: len(s), enc: len(powershell.Encode(s)),
			})
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.ValueSpec: // const and var declarations, package or function scope
				for i, nm := range d.Names {
					if i < len(d.Values) {
						record(nm.Name, d.Values[i], nm.Pos())
					}
				}
			case *ast.AssignStmt: // function-local `cmd := ` + "`" + `…` + "`" + `
				for i, lhs := range d.Lhs {
					if i >= len(d.Rhs) {
						break
					}
					name := "(local)"
					if id, ok := lhs.(*ast.Ident); ok {
						name = id.Name + " (local)"
					}
					record(name, d.Rhs[i], lhs.Pos())
				}
			case *ast.CallExpr: // powershell.Encode("…inline literal…")
				sel, ok := d.Fun.(*ast.SelectorExpr)
				if !ok || len(d.Args) != 1 {
					return true
				}
				switch sel.Sel.Name {
				case "Encode", "EncodeUnix", "Wrap":
					record(sel.Sel.Name+"(inline)", d.Args[0], d.Lparen)
				}
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)

	// If the walk finds nothing the test would pass vacuously, which is the
	// failure mode this whole file exists to prevent.
	require.Greater(t, len(found), 20, "the sweep found almost no scripts; the walk root is probably wrong")

	sort.Slice(found, func(i, j int) bool { return found[i].enc > found[j].enc })

	var table strings.Builder
	fmt.Fprintf(&table, "\n%-52s %-34s %6s %8s %9s  %s\n",
		"FILE", "SCRIPT", "SRC", "ENCODED", "HEADROOM", "STATUS")
	for _, f := range found {
		status := "ok"
		switch {
		case f.enc > powershell.MaxCommandLength:
			status = "OVER CAP"
		case f.src > powershell.MaxScriptLength:
			status = "over budget"
		case powershell.MaxCommandLength-f.enc < 1500:
			status = "tight"
		}
		fmt.Fprintf(&table, "%-52s %-34s %6d %8d %9d  %s\n",
			f.file, f.name, f.src, f.enc, powershell.MaxCommandLength-f.enc, status)
	}
	fmt.Fprintf(&table, "\n%d embedded scripts measured\n", len(found))
	t.Log(table.String())

	seen := map[string]bool{}
	for _, f := range found {
		seen[f.key()] = true
		if f.enc <= powershell.MaxCommandLength {
			continue
		}
		assert.Contains(t, knownOverCap, f.key(),
			"%s:%d %s is %d chars (%d encoded), over the %d character cap. "+
				"Compact it, or split it into two round trips — do not raise the cap.",
			f.file, f.line, f.name, f.src, f.enc, powershell.MaxCommandLength)
	}

	// Keep the exception list honest: an entry that no longer exceeds the cap,
	// or that names a script that no longer exists, has to come off it.
	for _, f := range found {
		if _, ok := knownOverCap[f.key()]; ok {
			assert.Greater(t, f.enc, powershell.MaxCommandLength,
				"%s now fits (%d encoded); remove it from knownOverCap", f.key(), f.enc)
		}
	}
	for key := range knownOverCap {
		assert.True(t, seen[key], "knownOverCap names %s, which the sweep did not find; remove it", key)
	}
}
