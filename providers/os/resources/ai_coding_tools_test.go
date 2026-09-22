// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsRealUserHome(t *testing.T) {
	tests := []struct {
		home string
		want bool
	}{
		{"/home/alice", true},
		{"/Users/bob", true},
		{"/root", true},
		{"/usr/home/carol", true}, // FreeBSD
		{`C:\Users\dave`, true},
		{"", false},
		{"/var/lib/nobody", false},  // system
		{"/Users/Shared", false},    // shared profile
		{`C:\Users\Public`, false},  // shared profile
		{`C:\Users\Default`, false}, // system profile
		{"/nonexistent/prefix", false},
	}
	for _, tt := range tests {
		assert.Equalf(t, tt.want, isRealUserHome(tt.home), "isRealUserHome(%q)", tt.home)
	}
}

// denyFs wraps an afero.Fs and returns a permission error for any path under
// deny, simulating an unprivileged scan of another user's home.
type denyFs struct {
	afero.Fs
	deny string
}

func (d *denyFs) permErr(op, name string) error {
	return &os.PathError{Op: op, Path: name, Err: os.ErrPermission}
}

func (d *denyFs) Open(name string) (afero.File, error) {
	if strings.HasPrefix(name, d.deny) {
		return nil, d.permErr("open", name)
	}
	return d.Fs.Open(name)
}

func (d *denyFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if strings.HasPrefix(name, d.deny) {
		return nil, d.permErr("open", name)
	}
	return d.Fs.OpenFile(name, flag, perm)
}

func (d *denyFs) Stat(name string) (os.FileInfo, error) {
	if strings.HasPrefix(name, d.deny) {
		return nil, d.permErr("stat", name)
	}
	return d.Fs.Stat(name)
}

func writeSkill(t *testing.T, fs afero.Fs, dir, name string) {
	t.Helper()
	require.NoError(t, fs.MkdirAll(dir+"/"+name, 0o755))
	content := "---\nname: " + name + "\ndescription: " + name + " skill.\n---\n# " + name + "\n"
	require.NoError(t, afero.WriteFile(fs, dir+"/"+name+"/SKILL.md", []byte(content), 0o644))
}

func TestCollectSkillFilesSkipsUnreadableDir(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeSkill(t, mem, "/home/alice/.cursor/skills", "readable")
	writeSkill(t, mem, "/home/bob/.cursor/skills", "hidden")

	// bob's home is unreadable (permission denied), alice's is fine.
	afs := &afero.Afero{Fs: &denyFs{Fs: mem, deny: "/home/bob"}}

	skills := collectSkillFiles(afs, []string{
		"/home/alice/.cursor/skills",
		"/home/bob/.cursor/skills",
		"/home/carol/.cursor/skills", // missing entirely
	})

	require.Len(t, skills, 1, "should return only the readable user's skill")
	assert.Equal(t, "readable", skills[0].name)
	assert.Contains(t, skills[0].source, "/home/alice/")
}

func TestCollectSkillFilesDedupsSourcePaths(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeSkill(t, mem, "/home/alice/.cursor/skills", "foo")
	afs := &afero.Afero{Fs: mem}

	// same dir passed twice (e.g. default path == override path) yields one skill
	skills := collectSkillFiles(afs, []string{
		"/home/alice/.cursor/skills",
		"/home/alice/.cursor/skills",
	})
	require.Len(t, skills, 1)
}

// writeGitCheckout writes a minimal .git directory with an origin remote and
// a HEAD ref pointing at sha via a loose ref file.
func writeGitCheckout(t *testing.T, fs afero.Fs, root, originURL, sha string) {
	t.Helper()
	gitDir := root + "/.git"
	require.NoError(t, fs.MkdirAll(gitDir+"/refs/heads", 0o755))
	config := "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = " + originURL + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	require.NoError(t, afero.WriteFile(fs, gitDir+"/config", []byte(config), 0o644))
	require.NoError(t, afero.WriteFile(fs, gitDir+"/HEAD", []byte("ref: refs/heads/main\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, gitDir+"/refs/heads/main", []byte(sha+"\n"), 0o644))
}

func TestSkillPURL(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"

	t.Run("github origin with loose ref", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		afs := &afero.Afero{Fs: mem}
		writeGitCheckout(t, mem, "/repo", "git@github.com:acme/skills.git", sha)
		writeSkill(t, mem, "/repo/skills", "deploy")

		assert.Equal(t, "pkg:github/acme/skills@0123456789ab?skill=deploy",
			skillPURL(afs, "/repo/skills/deploy/SKILL.md"))
	})

	t.Run("https origin URL", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		afs := &afero.Afero{Fs: mem}
		writeGitCheckout(t, mem, "/repo", "https://github.com/acme/skills.git", sha)
		writeSkill(t, mem, "/repo/skills", "deploy")

		assert.Equal(t, "pkg:github/acme/skills@0123456789ab?skill=deploy",
			skillPURL(afs, "/repo/skills/deploy/SKILL.md"))
	})

	t.Run("packed refs", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		afs := &afero.Afero{Fs: mem}
		writeGitCheckout(t, mem, "/repo", "git@github.com:acme/skills.git", sha)
		require.NoError(t, mem.Remove("/repo/.git/refs/heads/main"))
		packed := "# pack-refs with: peeled fully-peeled sorted\n" +
			sha + " refs/heads/main\n" +
			"^deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
		require.NoError(t, afero.WriteFile(mem, "/repo/.git/packed-refs", []byte(packed), 0o644))
		writeSkill(t, mem, "/repo/skills", "deploy")

		assert.Equal(t, "pkg:github/acme/skills@0123456789ab?skill=deploy",
			skillPURL(afs, "/repo/skills/deploy/SKILL.md"))
	})

	t.Run("detached HEAD resolves", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		afs := &afero.Afero{Fs: mem}
		writeGitCheckout(t, mem, "/repo", "git@github.com:acme/skills.git", sha)
		require.NoError(t, afero.WriteFile(mem, "/repo/.git/HEAD", []byte(sha+"\n"), 0o644))
		writeSkill(t, mem, "/repo/skills", "deploy")

		assert.Equal(t, "pkg:github/acme/skills@0123456789ab?skill=deploy",
			skillPURL(afs, "/repo/skills/deploy/SKILL.md"))
	})

	t.Run("linked worktree", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		afs := &afero.Afero{Fs: mem}
		// main checkout holds the shared config and refs
		writeGitCheckout(t, mem, "/repo", "git@github.com:acme/skills.git", sha)
		// linked worktree: .git file pointing at the per-worktree git dir
		wtGitDir := "/repo/.git/worktrees/wt"
		require.NoError(t, mem.MkdirAll(wtGitDir, 0o755))
		require.NoError(t, afero.WriteFile(mem, "/wt/.git", []byte("gitdir: "+wtGitDir+"\n"), 0o644))
		require.NoError(t, afero.WriteFile(mem, wtGitDir+"/commondir", []byte("../..\n"), 0o644))
		require.NoError(t, afero.WriteFile(mem, wtGitDir+"/HEAD", []byte("ref: refs/heads/main\n"), 0o644))
		writeSkill(t, mem, "/wt/skills", "deploy")

		assert.Equal(t, "pkg:github/acme/skills@0123456789ab?skill=deploy",
			skillPURL(afs, "/wt/skills/deploy/SKILL.md"))
	})

	t.Run("no git checkout", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		afs := &afero.Afero{Fs: mem}
		writeSkill(t, mem, "/plain/skills", "deploy")

		assert.Equal(t, "", skillPURL(afs, "/plain/skills/deploy/SKILL.md"))
	})

	t.Run("non-github origin", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		afs := &afero.Afero{Fs: mem}
		writeGitCheckout(t, mem, "/repo", "git@gitlab.com:acme/skills.git", sha)
		writeSkill(t, mem, "/repo/skills", "deploy")

		assert.Equal(t, "", skillPURL(afs, "/repo/skills/deploy/SKILL.md"))
	})

	t.Run("no origin remote", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		afs := &afero.Afero{Fs: mem}
		writeGitCheckout(t, mem, "/repo", "git@github.com:acme/skills.git", sha)
		config := "[remote \"upstream\"]\n\turl = git@github.com:other/skills.git\n"
		require.NoError(t, afero.WriteFile(mem, "/repo/.git/config", []byte(config), 0o644))
		writeSkill(t, mem, "/repo/skills", "deploy")

		assert.Equal(t, "", skillPURL(afs, "/repo/skills/deploy/SKILL.md"))
	})

	t.Run("unresolvable HEAD ref", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		afs := &afero.Afero{Fs: mem}
		writeGitCheckout(t, mem, "/repo", "git@github.com:acme/skills.git", sha)
		require.NoError(t, mem.Remove("/repo/.git/refs/heads/main"))
		writeSkill(t, mem, "/repo/skills", "deploy")

		assert.Equal(t, "", skillPURL(afs, "/repo/skills/deploy/SKILL.md"))
	})

	t.Run("malformed sha in ref file", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		afs := &afero.Afero{Fs: mem}
		writeGitCheckout(t, mem, "/repo", "git@github.com:acme/skills.git", sha)
		require.NoError(t, afero.WriteFile(mem, "/repo/.git/refs/heads/main", []byte("not-a-sha\n"), 0o644))
		writeSkill(t, mem, "/repo/skills", "deploy")

		assert.Equal(t, "", skillPURL(afs, "/repo/skills/deploy/SKILL.md"))
	})
}

// TestSkillPURLEncodesTheSkillDirectoryName pins that a skill directory name
// carrying purl syntax cannot break out of its qualifier.
//
// Regression test for https://github.com/mondoohq/mql/issues/10636 (4). The
// purl used to be assembled by string concatenation, so a directory named
// "a&b" produced "...?skill=a&b" -- two qualifiers, the second of them
// valueless -- and a directory with a "#" silently truncated the qualifier
// into a subpath.
func TestSkillPURLEncodesTheSkillDirectoryName(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"

	// Every one of these is a legal directory name on Linux and macOS and is
	// purl syntax at the same time.
	cases := []struct{ skillDir, want string }{
		{"a&b", "pkg:github/acme/skills@0123456789ab?skill=a%26b"},
		{"a?b", "pkg:github/acme/skills@0123456789ab?skill=a%3Fb"},
		{"a#b", "pkg:github/acme/skills@0123456789ab?skill=a%23b"},
		{"a=b", "pkg:github/acme/skills@0123456789ab?skill=a%3Db"},
		{"a%b", "pkg:github/acme/skills@0123456789ab?skill=a%25b"},
		{"deploy to prod", "pkg:github/acme/skills@0123456789ab?skill=deploy%20to%20prod"},
	}

	for _, tc := range cases {
		t.Run(tc.skillDir, func(t *testing.T) {
			mem := afero.NewMemMapFs()
			afs := &afero.Afero{Fs: mem}
			writeGitCheckout(t, mem, "/repo", "git@github.com:acme/skills.git", sha)
			writeSkill(t, mem, "/repo/skills", tc.skillDir)

			rendered := skillPURL(afs, "/repo/skills/"+tc.skillDir+"/SKILL.md")
			assert.Equal(t, tc.want, rendered)

			// ...and the encoding has to be the reversible one, not merely a
			// different set of bytes: what reads the purl back has to recover
			// the directory name the skill actually lives in.
			parsed, err := packageurl.FromString(rendered)
			require.NoError(t, err, "purl %q must parse", rendered)

			assert.Equal(t, "github", parsed.Type)
			assert.Equal(t, "acme", parsed.Namespace)
			assert.Equal(t, "skills", parsed.Name)
			assert.Equal(t, "0123456789ab", parsed.Version)
			assert.Len(t, parsed.Qualifiers, 1,
				"the directory name must stay inside one qualifier, got %q", rendered)
			assert.Equal(t, tc.skillDir, parsed.Qualifiers.Map()["skill"],
				"the directory name must survive the round trip intact")
		})
	}
}

func TestFileURIToPath(t *testing.T) {
	cases := []struct {
		uri  string
		want string
	}{
		{"file:///pub/go/src/go.mondoo.com/mql", "/pub/go/src/go.mondoo.com/mql"},
		{"file:///path/with%20space/repo", "/path/with space/repo"},
		{"file:///C:/Users/dev/repo", "C:/Users/dev/repo"},
		{"vscode-remote://ssh/pub/repo", ""},
		{"", ""},
		{"/not/a/uri", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, fileURIToPath(c.uri), "uri %q", c.uri)
	}
}

func TestVscodeUserDataDir(t *testing.T) {
	assert.Equal(t, "/home/x/.config/Cursor/User", vscodeUserDataDir("/home/x", "linux", "Cursor"))
	assert.Equal(t, "/Users/x/Library/Application Support/Windsurf/User", vscodeUserDataDir("/Users/x", "darwin", "Windsurf"))
	assert.Equal(t, "/home/x/.config/Cursor/User", vscodeUserDataDir("/home/x", "", "Cursor"))
}

func TestExtractZedPaths(t *testing.T) {
	// Simulate a bincode-ish blob: length prefixes (non-printable) between paths.
	blob := []byte{0x1a, 0x00, 0x00, 0x00}
	blob = append(blob, []byte("/pub/go/src/go.mondoo.com/mql")...)
	blob = append(blob, 0x00, 0x08)
	blob = append(blob, []byte("/home/dev/other-repo")...)
	blob = append(blob, 0x00)
	// A quoted JSON-style path and some noise that must be ignored.
	blob = append(blob, []byte(`"/quoted/path/repo"`)...)
	blob = append(blob, 0x00)
	blob = append(blob, []byte("SELECT * FROM workspaces")...)

	got := extractZedPaths(blob)
	assert.Contains(t, got, "/pub/go/src/go.mondoo.com/mql")
	assert.Contains(t, got, "/home/dev/other-repo")
	assert.Contains(t, got, "/quoted/path/repo")
	// the SQL run has no leading absolute path -> not extracted
	for _, p := range got {
		assert.NotContains(t, p, "SELECT")
	}
}

func TestZedCandidatePath(t *testing.T) {
	assert.Equal(t, "/a/b", zedCandidatePath("/a/b"))
	assert.Equal(t, "/a/b", zedCandidatePath(`"/a/b"`))
	assert.Equal(t, "C:/dev/repo", zedCandidatePath("C:/dev/repo"))
	assert.Equal(t, "", zedCandidatePath("no-path-here"))
	assert.Equal(t, "", zedCandidatePath("/"))
}

// An AI tool that has been installed but not configured can leave its JSON
// config file present and empty: Antigravity writes a zero-byte
// mcp_config.json. That is an empty config, and must read as no servers rather
// than as a parse error, which would score every check reading it as errored.
func TestUnmarshalJSONConfigEmptyFile(t *testing.T) {
	for name, data := range map[string]string{
		"empty":      "",
		"whitespace": " \n\t\n",
	} {
		t.Run(name, func(t *testing.T) {
			var config geminiMCPConfig
			require.NoError(t, unmarshalJSONConfig([]byte(data), &config))
			assert.Empty(t, config.McpServers)
		})
	}

	t.Run("valid", func(t *testing.T) {
		var config geminiMCPConfig
		require.NoError(t, unmarshalJSONConfig([]byte(`{"mcpServers":{"a":{"command":"x"}}}`), &config))
		assert.Len(t, config.McpServers, 1)
	})

	t.Run("malformed is still an error", func(t *testing.T) {
		var config geminiMCPConfig
		assert.Error(t, unmarshalJSONConfig([]byte(`{"mcpServers":`), &config))
	})
}

func TestReadJSONFileAferoEmptyFile(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()
	writeTestFile(t, dir, "settings.json", "")

	var settings geminiSettings
	require.NoError(t, readJSONFileAfero(afs, dir, "settings.json", &settings))
	assert.Empty(t, settings.Theme)
}
