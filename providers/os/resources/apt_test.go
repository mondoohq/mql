// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

func TestParseAptOneLine(t *testing.T) {
	content := `# Ubuntu sources
deb http://archive.ubuntu.com/ubuntu noble main restricted universe
deb-src http://archive.ubuntu.com/ubuntu noble main
deb [trusted=yes signed-by=/usr/share/keyrings/foo.gpg] https://repo.example.com/apt stable main
# deb http://disabled.example.com/ubuntu noble main
deb [arch=amd64] http://only-options.example.com noble main

not a repo line
deb http://incomplete.example.com`

	repos := parseAptOneLine(content)
	require.Len(t, repos, 5)

	require.Equal(t, aptRepo{
		Type:         "deb",
		URL:          "http://archive.ubuntu.com/ubuntu",
		Distribution: "noble",
		Components:   []string{"main", "restricted", "universe"},
		Enabled:      true,
	}, repos[0])

	require.Equal(t, aptRepo{
		Type:         "deb-src",
		URL:          "http://archive.ubuntu.com/ubuntu",
		Distribution: "noble",
		Components:   []string{"main"},
		Enabled:      true,
	}, repos[1])

	// trusted + signed-by options are parsed
	require.Equal(t, "https://repo.example.com/apt", repos[2].URL)
	require.True(t, repos[2].Trusted)
	require.Equal(t, "/usr/share/keyrings/foo.gpg", repos[2].SignedBy)
	require.Equal(t, []string{"main"}, repos[2].Components)

	// commented-out repo is captured as disabled
	require.Equal(t, "http://disabled.example.com/ubuntu", repos[3].URL)
	require.False(t, repos[3].Enabled)

	// unrelated options leave trusted/signedBy untouched
	require.Equal(t, "http://only-options.example.com", repos[4].URL)
	require.False(t, repos[4].Trusted)
	require.Empty(t, repos[4].SignedBy)
}

func TestParseAptDeb822(t *testing.T) {
	content := `# managed by some tool
Types: deb deb-src
URIs: http://archive.ubuntu.com/ubuntu
Suites: noble noble-updates
Components: main restricted
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: https://untrusted.example.com/apt
Suites: stable
Components: main
Trusted: yes
Enabled: no`

	repos := parseAptDeb822(content)

	// first stanza: 2 types x 1 uri x 2 suites = 4 repos
	// second stanza: 1 repo
	require.Len(t, repos, 5)

	require.Equal(t, "deb", repos[0].Type)
	require.Equal(t, "http://archive.ubuntu.com/ubuntu", repos[0].URL)
	require.Equal(t, "noble", repos[0].Distribution)
	require.Equal(t, []string{"main", "restricted"}, repos[0].Components)
	require.Equal(t, "/usr/share/keyrings/ubuntu-archive-keyring.gpg", repos[0].SignedBy)
	require.True(t, repos[0].Enabled)
	require.False(t, repos[0].Trusted)

	require.Equal(t, "noble-updates", repos[1].Distribution)
	require.Equal(t, "deb-src", repos[2].Type)

	// second stanza: trusted + disabled
	last := repos[4]
	require.Equal(t, "https://untrusted.example.com/apt", last.URL)
	require.True(t, last.Trusted)
	require.False(t, last.Enabled)
}

func TestAptBool(t *testing.T) {
	for _, v := range []string{"yes", "YES", "true", "1", " yes "} {
		require.True(t, aptBool(v), v)
	}
	for _, v := range []string{"no", "false", "0", "", "maybe"} {
		require.False(t, aptBool(v), v)
	}
}

// apt reads exactly two extensions out of sources.list.d. The previous filter
// passed a regex to files.find's `name`, which is an fnmatch glob, so it
// matched nothing and every fragment was dropped -- including the deb822
// .sources files that are the norm on Debian 12+ and Ubuntu 24.04+.
func TestIsAptSourceFile(t *testing.T) {
	included := []string{
		"/etc/apt/sources.list.d/debian.list",
		"/etc/apt/sources.list.d/kali.sources",
		"/etc/apt/sources.list.d/ubuntu.sources",
		"/etc/apt/sources.list.d/docker.list",
	}
	for _, p := range included {
		t.Run("include/"+p, func(t *testing.T) {
			assert.True(t, isAptSourceFile(p), "apt reads this file")
		})
	}

	excluded := []string{
		// apt's own backups, which must not be parsed as live config
		"/etc/apt/sources.list.d/debian.list.save",
		"/etc/apt/sources.list.d/debian.list.distUpgrade",
		"/etc/apt/sources.list.d/kali.sources.bak",
		// unrelated files that share the directory
		"/etc/apt/sources.list.d/README",
		"/etc/apt/sources.list.d/deadsnakes.gpg",
		"/etc/apt/sources.list.d/",
		"",
	}
	for _, p := range excluded {
		name := p
		if name == "" {
			name = "empty"
		}
		t.Run("exclude/"+name, func(t *testing.T) {
			assert.False(t, isAptSourceFile(p), "apt ignores this file")
		})
	}
}

// The stock Ubuntu 16.04 to 22.04 sources.list repeats `deb <mirror> <suite>`
// once per component group. Every line used to share one __id, so
// CreateResource returned the first line's resource for the later ones and
// universe and multiverse vanished from apt.repos. `apt-get indextargets` on
// the same host lists main, restricted, universe and multiverse for focal.
func TestAptReposRepeatedSuiteKeepEveryLine(t *testing.T) {
	b, err := os.ReadFile("testdata/apt-sources/ubuntu-2004-sources.list")
	require.NoError(t, err)
	parsed := parseAptOneLine(string(b))
	require.Len(t, parsed, 22, "10 enabled and 12 commented-out deb lines")

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	apt := &mqlApt{MqlRuntime: runtime}
	file := &mqlFile{MqlRuntime: runtime, Path: plugin.TValue[string]{Data: aptSourcesList, State: plugin.StateIsSet}}

	components := map[string][]string{}
	for i := range parsed {
		parsed[i].SourceFile = aptSourcesList
		r, err := apt.newRepo(file, i, parsed[i])
		require.NoError(t, err)
		if !r.Enabled.Data || r.Type.Data != "deb" {
			continue
		}
		key := r.Url.Data + " " + r.Distribution.Data
		for _, c := range r.Components.Data {
			components[key] = append(components[key], c.(string))
		}
	}

	assert.ElementsMatch(t, []string{"main", "restricted", "universe", "multiverse"},
		components["http://archive.ubuntu.com/ubuntu/ focal"])
	assert.ElementsMatch(t, []string{"main", "restricted", "universe", "multiverse"},
		components["http://security.ubuntu.com/ubuntu focal-security"])
}

// apt drops everything from a '#' to the end of a line. The trailing comment
// used to come back as components "#", "trailing" and "comment".
func TestParseAptOneLineTrailingComment(t *testing.T) {
	repos := parseAptOneLine(strings.Join([]string{
		"deb [ trusted=yes arch=amd64,i386 ] file:/srv/g03repo2 ./ # trailing comment",
		"deb http://archive.ubuntu.com/ubuntu noble main universe #no space",
		"# deb http://archive.ubuntu.com/ubuntu noble multiverse # disabled with comment",
	}, "\n"))
	require.Len(t, repos, 3)

	assert.Equal(t, "file:/srv/g03repo2", repos[0].URL)
	assert.Equal(t, "./", repos[0].Distribution)
	assert.Empty(t, repos[0].Components)
	assert.True(t, repos[0].Trusted)

	assert.Equal(t, []string{"main", "universe"}, repos[1].Components)

	assert.False(t, repos[2].Enabled)
	assert.Equal(t, []string{"multiverse"}, repos[2].Components)
}
