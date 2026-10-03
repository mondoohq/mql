// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package yum

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseYumRepoEntry(t *testing.T) {
	data := `
Repo-id      : base/7/x86_64
Repo-name    : CentOS-7 - Base
Repo-status  : enabled
Repo-revision: 1587512243
Repo-updated : Tue Apr 21 23:37:50 2020
Repo-pkgs    : 10070
Repo-size    : 8.9 G
Repo-mirrors : http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=os&infra=container
Repo-baseurl : http://mirror.imt-systems.com/centos/7.8.2003/os/x86_64/ (9 more)
Repo-expire  : 21600 second(s) (last: Tue Jun 16 07:13:59 2020)
	Filter     : read-only:present
Repo-filename: /etc/yum.repos.d/CentOS-Base.repo

Repo-id      : c7-media
Repo-name    : CentOS-7 - Media
Repo-status  : disabled
Repo-baseurl : file:///media/CentOS/, file:///media/cdrom/, file:///media/cdrecorder/
Repo-expire  : 21600 second(s) (last: Unknown)
  Filter     : read-only:present
Repo-filename: /etc/yum.repos.d/CentOS-Media.repo
	`
	repos, err := ParseRepos(strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, 2, len(repos))

	repo := repos[0]
	// yum 3 appends $releasever/$basearch to the id; the repo id is "base"
	assert.Equal(t, "base", repo.Id)
	assert.Equal(t, "CentOS-7 - Base", repo.Name)
	assert.Equal(t, "enabled", repo.Status)
	assert.Equal(t, "1587512243", repo.Revision)
	assert.Equal(t, "Tue Apr 21 23:37:50 2020", repo.Updated)
	assert.Equal(t, "10070", repo.Pkgs)
	assert.Equal(t, "8.9 G", repo.Size)
	assert.Equal(t, "http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=os&infra=container", repo.Mirrors)
	assert.Equal(t, []string{"http://mirror.imt-systems.com/centos/7.8.2003/os/x86_64/"}, repo.Baseurl)
	assert.Equal(t, "21600 second(s) (last: Tue Jun 16 07:13:59 2020)", repo.Expire)
	assert.Equal(t, "read-only:present", repo.Filter)
	assert.Equal(t, "/etc/yum.repos.d/CentOS-Base.repo", repo.Filename)

	repo = repos[1]
	assert.Equal(t, "c7-media", repo.Id)
	assert.Equal(t, "CentOS-7 - Media", repo.Name)
	assert.Equal(t, "disabled", repo.Status)
	assert.Equal(t, []string{"file:///media/CentOS/", "file:///media/cdrom/", "file:///media/cdrecorder/"}, repo.Baseurl)
}

func TestYumRepoRhel7(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/yum_rhel7.toml"))
	require.NoError(t, err)

	cmd, err := mock.RunCommand(RhelYumRepoListCommand)
	require.NoError(t, err)
	repos, err := ParseRepos(cmd.Stdout)
	require.NoError(t, err)
	assert.Equal(t, 15, len(repos))

	cmd, err = mock.RunCommand(Rhel6VarsCommand)
	require.NoError(t, err)
	vars, err := ParseVariables(cmd.Stdout)
	require.NoError(t, err)
	assert.Equal(t, "7Server", vars["releasever"])
}

func TestYumRepoRhel8(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/yum_rhel8.toml"))
	require.NoError(t, err)

	cmd, err := mock.RunCommand(RhelYumRepoListCommand)
	require.NoError(t, err)
	repos, err := ParseRepos(cmd.Stdout)
	require.NoError(t, err)
	assert.Equal(t, 17, len(repos))

	cmd, err = mock.RunCommand(fmt.Sprintf(DnfVarsCommand, PythonRhel))
	require.NoError(t, err)
	vars, err := ParseVariables(cmd.Stdout)
	require.NoError(t, err)
	assert.Equal(t, "8", vars["releasever"])
}

func parseDnf5Fixture(t *testing.T, name string) []*YumRepo {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	require.NoError(t, err)
	defer f.Close()
	repos, err := ParseDnf5Repos(f)
	require.NoError(t, err)
	return repos
}

func TestParseDnf5ReposFedora43(t *testing.T) {
	// `dnf5 repo info --all` on Fedora 43, dnf5 5.2.18
	repos := parseDnf5Fixture(t, "dnf5_fedora43_repoinfo.txt")
	require.Len(t, repos, 12)

	repo := repos[0]
	assert.Equal(t, "fedora", repo.Id)
	assert.Equal(t, "Fedora 43 - x86_64", repo.Name)
	assert.Equal(t, "enabled", repo.Status)
	assert.Equal(t, "604800 seconds (last: 2026-09-28 05:12:19)", repo.Expire)
	assert.Equal(t, "/etc/yum.repos.d/fedora.repo", repo.Filename)
	assert.Equal(t, []string{"https://d2lzkl7pfhq30w.cloudfront.net/pub/fedora/linux/releases/43/Everything/x86_64/os/"}, repo.Baseurl)
	assert.Equal(t, "https://mirrors.fedoraproject.org/metalink?repo=fedora-43&arch=x86_64", repo.Mirrors)
	assert.Equal(t, "77664", repo.Pkgs)
	assert.Equal(t, "117.1 GiB", repo.Size)
	assert.Equal(t, "1761190640", repo.Revision)
	assert.Equal(t, "2025-10-23 03:37:20", repo.Updated)

	// a disabled repo has no base URL and no repodata
	repo = repos[2]
	assert.Equal(t, "fedora-cisco-openh264-debuginfo", repo.Id)
	assert.Equal(t, "disabled", repo.Status)
	assert.Equal(t, "/etc/yum.repos.d/fedora-cisco-openh264.repo", repo.Filename)
	assert.Nil(t, repo.Baseurl)
	assert.Equal(t, "https://mirrors.fedoraproject.org/metalink?repo=fedora-cisco-openh264-debug-43&arch=x86_64", repo.Mirrors)
	assert.Empty(t, repo.Pkgs)
	assert.Empty(t, repo.Size)
	assert.Empty(t, repo.Revision)

	enabled := 0
	for _, r := range repos {
		if r.Status == "enabled" {
			enabled++
		}
	}
	assert.Equal(t, 3, enabled, "fedora, fedora-cisco-openh264 and updates")
}

func TestParseDnf5ReposAmazonLinux2027(t *testing.T) {
	// `dnf5 repo info --all` on Amazon Linux 2027, dnf5 5.4.2
	repos := parseDnf5Fixture(t, "dnf5_al2027_repoinfo.txt")
	require.Len(t, repos, 3)

	repo := repos[0]
	assert.Equal(t, "amazonlinux", repo.Id)
	assert.Equal(t, "Amazon Linux 2027 repository", repo.Name)
	assert.Equal(t, "enabled", repo.Status)
	assert.Equal(t, "/etc/yum.repos.d/amazonlinux.repo", repo.Filename)
	assert.Equal(t, []string{"https://al2027-repos-us-west-2-7f9a3b4e.s3.dualstack.us-west-2.amazonaws.com/core/guids/7eee71ed659b0d0571aafb3d6843efa5ae236105cf9c7cdfaf72a4360869078e/x86_64/"}, repo.Baseurl)
	assert.Equal(t, "https://al2027-repos-us-west-2-7f9a3b4e.s3.dualstack.us-west-2.amazonaws.com/core/mirrors/2027.0.20260914/x86_64/mirror.list", repo.Mirrors)
	assert.Equal(t, "7667", repo.Pkgs)
	assert.Equal(t, "12.6 GiB", repo.Size)
	assert.Equal(t, "1789596040", repo.Revision)

	assert.Equal(t, "amazonlinux-debuginfo", repos[1].Id)
	assert.Equal(t, "disabled", repos[1].Status)
	assert.Equal(t, "amazonlinux-source", repos[2].Id)
}

func TestParseDnf5ReposMultipleBaseurls(t *testing.T) {
	// Fedora 43 with a scratch reposdir: several configured base URLs are
	// printed space-separated on one line
	repos := parseDnf5Fixture(t, "dnf5_fedora43_multi_baseurl.txt")
	require.Len(t, repos, 2)

	assert.Equal(t, "mqlmirror", repos[0].Id)
	assert.Nil(t, repos[0].Baseurl)
	assert.Equal(t, "file:///media/ml", repos[0].Mirrors)

	assert.Equal(t, "mqltest", repos[1].Id)
	assert.Equal(t, "mql test repo", repos[1].Name)
	assert.Equal(t, []string{"file:///media/a/", "file:///media/b/", "file:///media/c/"}, repos[1].Baseurl)
	assert.Empty(t, repos[1].Mirrors)
}

func TestParseDnf5ReposIgnoresDnf4Output(t *testing.T) {
	// the two formats share no labels, so each parser finds nothing in the other's output
	f, err := os.Open("testdata/dnf4_centos9_metalink.txt")
	require.NoError(t, err)
	defer f.Close()
	repos, err := ParseDnf5Repos(f)
	require.NoError(t, err)
	assert.Empty(t, repos)

	repos, err = ParseRepos(strings.NewReader(`Repo ID              : fedora
Name                 : Fedora 43 - x86_64`))
	require.NoError(t, err)
	assert.Empty(t, repos)
}

func TestParseReposMetalink(t *testing.T) {
	// `yum -v repolist all` on CentOS Stream 9, dnf 4: a metalink repo prints
	// Repo-metalink instead of Repo-mirrors, with a nested Updated line
	f, err := os.Open("testdata/dnf4_centos9_metalink.txt")
	require.NoError(t, err)
	defer f.Close()
	repos, err := ParseRepos(f)
	require.NoError(t, err)
	require.Len(t, repos, 3)

	repo := repos[0]
	assert.Equal(t, "appstream", repo.Id)
	assert.Equal(t, "https://mirrors.centos.org/metalink?repo=centos-appstream-9-stream&arch=x86_64&protocol=https,http", repo.Mirrors)
	assert.Equal(t, "Tue 22 Sep 2026 01:38:40 PM UTC", repo.Updated)
	assert.Equal(t, []string{"https://download.cf.centos.org/9-stream/AppStream/x86_64/os/"}, repo.Baseurl)
	assert.Equal(t, "20,894", repo.Pkgs)
	assert.Equal(t, "/etc/yum.repos.d/centos.repo", repo.Filename)
}

// `yum -v repolist all` on RHEL 7 (yum 3.4.3) with the g03 test repos: a repo
// whose metalink uses $releasever and $basearch, and a name long enough to
// wrap.
func TestParseReposYum3Rhel7(t *testing.T) {
	f, err := os.Open("./testdata/yum3_rhel7_repolist.txt")
	require.NoError(t, err)
	defer f.Close()
	repos, err := ParseRepos(f)
	require.NoError(t, err)
	require.Len(t, repos, 29)

	byID := map[string]*YumRepo{}
	for _, r := range repos {
		assert.NotContains(t, r.Id, "/", "yum 3 appends /$releasever/$basearch to the id")
		byID[r.Id] = r
	}

	metalink := byID["g03-metalink"]
	require.NotNil(t, metalink, "printed as g03-metalink/7Server/x86_64")
	assert.Equal(t, "https://mirrors.example.invalid/metalink?repo=g03-7Server&arch=x86_64", metalink.Mirrors)

	disabled := byID["g03-disabled"]
	require.NotNil(t, disabled)
	assert.Equal(t, "G03 disabled repo with two base URLs and a long name to make yum wrap the line", disabled.Name)
	assert.Equal(t, []string{"file:///srv/g03a/", "file:///srv/g03b/"}, disabled.Baseurl)
	assert.Equal(t, "disabled", disabled.Status)
	assert.Equal(t, "/etc/yum.repos.d/g03.repo", disabled.Filename)

	devtools := byID["rhel-7-server-devtools-rhui-rpms"]
	require.NotNil(t, devtools)
	assert.Equal(t, "Red Hat Developer Tools RPMs for Red Hat Enterprise Linux 7 Server from RHUI", devtools.Name)

	g03 := byID["g03repo"]
	require.NotNil(t, g03)
	assert.Equal(t, "G03 local test repo 7Server g03value", g03.Name)
	assert.Equal(t, "enabled", g03.Status)
}

func TestParseReposWrappedBaseurl(t *testing.T) {
	repos, err := ParseRepos(strings.NewReader(strings.Join([]string{
		// a continuation before any repo is ignored
		"             : stray",
		"Repo-id      : multi",
		"Repo-baseurl : file:///a/, file:///b/,",
		"             : file:///c/",
		"Repo-status  : enabled",
	}, "\n")))
	require.NoError(t, err)
	require.Len(t, repos, 1)
	assert.Equal(t, []string{"file:///a/", "file:///b/", "file:///c/"}, repos[0].Baseurl)
}

// yum 3 prints "Loaded plugins: ..." on stdout before the variables.
func TestParseVariablesYum3PluginBanner(t *testing.T) {
	f, err := os.Open("./testdata/yum3_rhel7_vars.txt")
	require.NoError(t, err)
	defer f.Close()
	vars, err := ParseVariables(f)
	require.NoError(t, err)
	assert.Equal(t, "7Server", vars["releasever"])
	assert.Equal(t, "x86_64", vars["basearch"])
	assert.Equal(t, "ia32e", vars["arch"])
	assert.Equal(t, "g03value", vars["g03var"])

	_, err = ParseVariables(strings.NewReader("Loaded plugins: product-id\n"))
	require.Error(t, err)
}

func TestParseDnf5Variables(t *testing.T) {
	f, err := os.Open("./testdata/dnf5_fedora44_dump_variables.txt")
	require.NoError(t, err)
	defer f.Close()
	vars, err := ParseDnf5Variables(f)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"arch":             "x86_64",
		"basearch":         "x86_64",
		"g03var":           "g03value",
		"releasever":       "44",
		"releasever_major": "",
		"releasever_minor": "",
	}, vars)

	_, err = ParseDnf5Variables(strings.NewReader("Unknown argument \"--dump-variables\"\n"))
	require.Error(t, err)
}

// dnf 4 and yum 3 translate the labels and the status of `repolist -v`. Under
// LANG=de_DE.UTF-8 dnf 4 prints
//
//	Paketquellenkennung            : g03repo
//	Paketquellenstatus        : aktiviert
//
// which ParseRepos cannot read (dnf 4: no repos at all; yum 3: every repo
// disabled), so the commands must run in the C locale whatever the caller's.
func TestRepoListCommandsRunInCLocale(t *testing.T) {
	for _, cmd := range []string{RhelYumRepoListCommand, Dnf5RepoInfoCommand} {
		assert.True(t, strings.HasPrefix(cmd, "LC_ALL=C "), cmd)
	}
}
