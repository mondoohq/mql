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
	"go.mondoo.com/mql/providers/os/resources/powershell"
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
	// Runs on the *scanner* host, not a remote target, and only as a fallback
	// when the Exchange admin REST endpoint is unavailable. On a Linux or macOS
	// scanner the shell is `sh -c`, where ARG_MAX is megabytes and the cap does
	// not apply; it only breaks when the scanner itself runs Windows.
	"providers/ms365/resources/ms365_exchange.go:exchangeReport": "scanner-side fallback; only affected on a Windows scanner host",
}

// stagedScripts records the embedded scripts that exceed the command-line cap
// and are nonetheless fine, because they never reach a command line: they are
// written to the target with powershell.Stage and run with `-File`, so the
// command carries a path rather than a program.
//
// This is a *different claim* from knownOverCap, not a softer one. An entry
// there says "over the cap and broken, tracked elsewhere"; an entry here says
// "over the cap and correct, because the transport changed". Without this list
// staging would fix a script and leave it failing this test forever, and the
// only available response would be to raise the cap — which is the thing this
// file exists to prevent.
//
// The reciprocal assertions below keep it honest. An entry must name a script
// the sweep actually found, must not also appear in knownOverCap, and must be
// passed to powershell.Stage somewhere in the tree. The last one is the point:
// it makes the exemption a statement about code rather than a note.
var stagedScripts = map[string]string{
	// 18,545 characters, 49,554 encoded — over both ceilings and not
	// compactable: the prelude every scope needs (install guard, section lists
	// and helpers, everything above Get-ScopeConfiguration) is 11,553 characters
	// on its own, so splitting the script into round trips leaves every one of
	// them over the WinRM cap. It is staged by providers/os/resources/iis.go and
	// run with -File.
	"providers/os/resources/windows/iis.go:IIS_CONFIGURATION": "staged as a file by the iis resource and run with -File",

	// 5,294 characters, 14,266 encoded. It walks the ProfileList registry hive
	// and the IdentityStore cache, so it is not meaningfully compactable, and
	// splitting it into round trips would still leave the union logic over the
	// cap. Staged by WindowsUserManager.List and run with -File. Verified
	// against a live Windows 11 25H2 host over WinRM.
	"providers/os/resources/users/ps1getlocalusers.go:getLocalUsersScript": "staged as a file by the windows user manager and run with -File",
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
//
// A third class used to be invisible entirely: a script kept in its own `.ps1`
// file and pulled in with `//go:embed`. There is no string literal to measure,
// so the sweep walked straight past it — which is how a 13,849-character script
// reached review inside a resource whose tests all passed. The walk now reads
// those files too, and the mode it parses with is load-bearing:
// `//go:embed` is a *comment*, and `parser.ParseFile` with mode 0 discards
// comments, so a wider AST walk alone finds nothing. It needs
// `parser.ParseComments` and the `GenDecl.Doc` the directive hangs off.
func TestEmbeddedPowerShellScriptsFitCommandLine(t *testing.T) {
	root := "../../../.."

	var found []scriptFinding
	// staged collects the identifier of every script handed to powershell.Stage,
	// so the stagedScripts exemption list can be checked against real calls.
	staged := map[string]bool{}
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
		// ParseComments, not 0. `//go:embed` is a comment; with mode 0 the AST
		// carries no Doc at all and every embedded .ps1 is invisible.
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
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

		// recordEmbed measures a script kept in its own file. The pattern is
		// relative to the directory of the .go file that declares it, exactly as
		// the embed package resolves it.
		recordEmbed := func(name, pattern string, pos token.Pos) {
			body, rerr := os.ReadFile(filepath.Join(filepath.Dir(path), pattern))
			if rerr != nil {
				return
			}
			s := string(body)
			if len(s) < 120 || !looksLikePowerShell(s) {
				return
			}
			found = append(found, scriptFinding{
				file: rel, name: name, line: fset.Position(pos).Line,
				src: len(s), enc: len(powershell.Encode(s)),
			})
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.GenDecl: // `//go:embed x.ps1` hangs off the declaration's Doc
				if d.Doc == nil {
					return true
				}
				for _, c := range d.Doc.List {
					pattern, ok := strings.CutPrefix(c.Text, "//go:embed ")
					if !ok {
						continue
					}
					for pat := range strings.FieldsSeq(pattern) {
						if !strings.HasSuffix(pat, ".ps1") {
							continue
						}
						for _, spec := range d.Specs {
							vs, ok := spec.(*ast.ValueSpec)
							if !ok || len(vs.Names) == 0 {
								continue
							}
							recordEmbed(vs.Names[0].Name, pat, vs.Names[0].Pos())
						}
					}
				}
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
				if !ok {
					return true
				}
				// powershell.Stage(conn, "name", SOME_SCRIPT): remember which
				// script identifiers are actually staged, so the exemption list
				// can be checked against calls rather than taken on trust.
				if sel.Sel.Name == "Stage" {
					for _, arg := range d.Args {
						switch a := arg.(type) {
						case *ast.Ident:
							staged[a.Name] = true
						case *ast.SelectorExpr:
							staged[a.Sel.Name] = true
						}
					}
					return true
				}
				if len(d.Args) != 1 {
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
	names := map[string]string{}
	for _, f := range found {
		seen[f.key()] = true
		names[f.key()] = f.name
		if f.enc <= powershell.MaxCommandLength {
			continue
		}
		if _, ok := stagedScripts[f.key()]; ok {
			continue
		}
		assert.Contains(t, knownOverCap, f.key(),
			"%s:%d %s is %d chars (%d encoded), over the %d character cap. "+
				"Compact it, split it into two round trips, or stage it with "+
				"powershell.Stage and list it in stagedScripts — do not raise the cap.",
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

	// The same reciprocal treatment for stagedScripts, plus the one assertion
	// that makes the entry mean something: the script it names has to be passed
	// to powershell.Stage somewhere. Otherwise the list is a way of silencing
	// this test with a comment.
	for key := range stagedScripts {
		if !assert.True(t, seen[key],
			"stagedScripts names %s, which the sweep did not find; remove it", key) {
			continue
		}
		assert.NotContains(t, knownOverCap, key,
			"%s is in both stagedScripts and knownOverCap; it is either staged "+
				"and correct or unstaged and broken, not both", key)
		assert.True(t, staged[names[key]],
			"stagedScripts claims %s is staged, but no powershell.Stage call in "+
				"the tree takes %s as an argument", key, names[key])
	}
}
