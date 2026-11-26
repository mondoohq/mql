// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package filesfind

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsPowershellCmdGeneration(t *testing.T) {
	tests := []struct {
		TestTitle  string
		From       string
		FileType   string
		Regex      string
		Permission int64
		Search     string
		Depth      *int64
		Exclude    []string
		// the variables the walk reads
		ExpectedVars string
		// the test a candidate must pass to be reported
		ExpectedFilter string
	}{
		{
			TestTitle: "no filter",
			From:      `C:\Data`,
			ExpectedVars: `$Path = 'C:\Data'
$Pattern = '*'
$Exclude = @()
$MaxDepth = -1
`,
			ExpectedFilter: "$true",
		},
		{
			TestTitle: "file type",
			From:      `C:\Users\john\.aws`,
			FileType:  "file",
			ExpectedVars: `$Path = 'C:\Users\john\.aws'
$Pattern = '*'
$Exclude = @()
$MaxDepth = -1
`,
			ExpectedFilter: "-not $dir",
		},
		{
			TestTitle: "directory type with depth",
			From:      `C:\Program Files`,
			FileType:  "directory",
			Depth:     new(int64(1)),
			ExpectedVars: `$Path = 'C:\Program Files'
$Pattern = '*'
$Exclude = @()
$MaxDepth = 1
`,
			ExpectedFilter: "$dir",
		},
		{
			TestTitle: "link type",
			From:      `C:\Links`,
			FileType:  "symlink",
			ExpectedVars: `$Path = 'C:\Links'
$Pattern = '*'
$Exclude = @()
$MaxDepth = -1
`,
			ExpectedFilter: "$null -ne $e.LinkType",
		},
		{
			TestTitle: "a name is matched by the file system API, and -like decides",
			From:      `C:\Users`,
			Search:    "package.json",
			Exclude:   []string{"node_modules", "npm-cache"},
			ExpectedVars: `$Path = 'C:\Users'
$SearchName = 'package.json'
$Pattern = $SearchName
$Exclude = @('node_modules', 'npm-cache')
$MaxDepth = -1
`,
			ExpectedFilter: "$e.Name -like $SearchName",
		},
		{
			TestTitle: "a name with a bracket range lists every file",
			From:      `C:\Logs`,
			Search:    "app[0-9].log",
			ExpectedVars: `$Path = 'C:\Logs'
$SearchName = 'app[0-9].log'
$Pattern = '*'
$Exclude = @()
$MaxDepth = -1
`,
			ExpectedFilter: "$e.Name -like $SearchName",
		},
		{
			TestTitle:      "a name with a backtick escape lists every file",
			From:           `C:\Data`,
			Search:         "a`*b.txt",
			ExpectedVars:   "$Path = 'C:\\Data'\n$SearchName = 'a`*b.txt'\n$Pattern = '*'\n$Exclude = @()\n$MaxDepth = -1\n",
			ExpectedFilter: "$e.Name -like $SearchName",
		},
		{
			TestTitle:  "every filter combined",
			From:       `C:\Source`,
			FileType:   "file",
			Search:     "*.txt",
			Regex:      ".*test.*",
			Permission: 0o644,
			Depth:      new(int64(0)),
			ExpectedVars: `$Path = 'C:\Source'
$SearchName = '*.txt'
$Pattern = $SearchName
$RegexPattern = '.*test.*'
$Exclude = @()
$MaxDepth = 0
`,
			ExpectedFilter: "-not $dir -and $e.Name -like $SearchName -and $e.FullName -match $RegexPattern -and $e.IsReadOnly -eq $false",
		},
		{
			TestTitle:  "read-only permission",
			From:       `C:\Data`,
			Permission: 0o555,
			ExpectedVars: `$Path = 'C:\Data'
$Pattern = '*'
$Exclude = @()
$MaxDepth = -1
`,
			ExpectedFilter: "$e.IsReadOnly -eq $true",
		},
		{
			TestTitle:  "permission 0777 is no filter",
			From:       `C:\Data`,
			Permission: 0o777,
			ExpectedVars: `$Path = 'C:\Data'
$Pattern = '*'
$Exclude = @()
$MaxDepth = -1
`,
			ExpectedFilter: "$true",
		},
		{
			// a quote, typographic or not, must not end the string
			TestTitle: "quotes in user input stay inside the strings",
			From:      "C:\\Users\\john's folder\n",
			Search:    "it’s.txt",
			Regex:     "'; whoami; '",
			Exclude:   []string{"o'brien"},
			ExpectedVars: "$Path = 'C:\\Users\\john''s folder '\n" +
				"$SearchName = 'it’’s.txt'\n" +
				"$Pattern = $SearchName\n" +
				"$RegexPattern = '''; whoami; '''\n" +
				"$Exclude = @('o''brien')\n" +
				"$MaxDepth = -1\n",
			ExpectedFilter: "$e.Name -like $SearchName -and $e.FullName -match $RegexPattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.TestTitle, func(t *testing.T) {
			cmd := BuildPowershellCmd(tt.From, false, tt.FileType, tt.Regex, tt.Permission, tt.Search, tt.Depth, tt.Exclude)
			assert.Equal(t, tt.ExpectedVars+strings.Replace(powershellFindWalk, "%s", tt.ExpectedFilter, 1), cmd)
		})
	}
}

// requirePwsh skips unless PowerShell is installed.
func requirePwsh(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"pwsh", "powershell"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("needs PowerShell")
	return ""
}

// Synthetic: runs the walk on a tree shaped like a developer's home, with
// installed packages, a cache, a link and a file named like a directory.
func TestPowershellFindWalk(t *testing.T) {
	pwsh := requirePwsh(t)
	root := t.TempDir()
	for _, p := range []string{
		"u/proj/package.json",
		"u/proj/src/index.js",
		"u/proj/node_modules/a/package.json",
		"u/proj/node_modules/a/node_modules/b/package.json",
		"u/.cache/x/package.json",
		"u/proj/docs/node_modules",
		"u/logs/app1.log",
		"u/logs/appx.log",
		"u/it's/package.json",
	} {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, p), nil, 0o644))
	}
	linkErr := os.Symlink(filepath.Join(root, "u", "proj"), filepath.Join(root, "u", "linked"))

	find := func(from, fileType, search string, depth *int64, exclude ...string) []string {
		t.Helper()
		script := BuildPowershellCmd(from, false, fileType, "", 0o777, search, depth, exclude)
		out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
		require.NoError(t, err, string(out))
		var res []string
		for _, l := range strings.Split(strings.ReplaceAll(strings.TrimSpace(string(out)), "\r\n", "\n"), "\n") {
			if l != "" {
				res = append(res, filepath.ToSlash(strings.TrimPrefix(l, root+string(filepath.Separator))))
			}
		}
		return res
	}
	u := filepath.Join(root, "u")

	assert.Equal(t, []string{"u/.cache/x/package.json", "u/it's/package.json", "u/proj/package.json"},
		find(u, "", "package.json", nil, "node_modules"), "hidden directories are searched")
	assert.Equal(t, []string{"u/it's/package.json", "u/proj/package.json"},
		find(u, "", "package.json", nil, "node_modules", ".*"), "exclude globs as -like does")
	assert.Equal(t, []string{
		"u/.cache/x/package.json",
		"u/it's/package.json",
		"u/proj/node_modules/a/node_modules/b/package.json",
		"u/proj/node_modules/a/package.json",
		"u/proj/package.json",
	}, find(u, "", "package.json", nil), "without exclude every directory is searched")
	assert.Equal(t, []string{"u/proj/docs/node_modules"},
		find(filepath.Join(u, "proj"), "file", "node_modules", nil, "node_modules"), "a file is never excluded")
	assert.Equal(t, []string{"u/proj/node_modules/a/package.json"},
		find(filepath.Join(u, "proj", "node_modules"), "", "package.json", nil, "node_modules"), "from is searched even when its name matches")
	assert.Equal(t, []string{"u/proj", "u/proj/docs", "u/proj/src"},
		find(filepath.Join(u, "proj"), "directory", "", nil, "node_modules"), "an excluded directory is not reported")

	assert.Equal(t, []string{"u/proj"}, find(filepath.Join(u, "proj"), "", "", new(int64(0))), "depth 0 is from alone")
	assert.Equal(t, []string{"u/proj/package.json"}, find(filepath.Join(u, "proj"), "", "package.json", new(int64(1))))
	assert.Equal(t, []string{"u/proj/package.json"}, find(filepath.Join(u, "proj"), "", "package.json", new(int64(2))))
	assert.Equal(t, []string{"u/proj/node_modules/a/package.json", "u/proj/package.json"},
		find(filepath.Join(u, "proj"), "", "package.json", new(int64(3))), "node_modules/a/package.json is 3 levels below")
	assert.Equal(t, []string{"u/proj/package.json"}, find(filepath.Join(u, "proj", "package.json"), "", "", nil), "a file as from is the one candidate")
	assert.Empty(t, find(filepath.Join(u, "absent"), "", "", nil))

	assert.Equal(t, []string{"u/logs/app1.log"}, find(u, "", "app[0-9].log", nil), "a bracket range is matched by -like")

	if linkErr == nil && runtime.GOOS != "windows" {
		assert.NotContains(t, find(u, "", "package.json", nil, "node_modules"), "u/linked/package.json", "a link is not entered")
		assert.Equal(t, []string{"u/linked/package.json"}, find(filepath.Join(u, "linked"), "", "package.json", new(int64(1))), "a link as from is entered")
	}
}
