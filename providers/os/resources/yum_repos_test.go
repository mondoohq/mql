// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/yum"
)

func yumRepoIds(t *testing.T, y *mqlYum) []string {
	t.Helper()
	repos, err := y.repos()
	require.NoError(t, err)
	ids := make([]string, len(repos))
	for i, r := range repos {
		ids[i] = r.(*mqlYumRepo).Id.Data
	}
	return ids
}

func TestYumReposDnf5(t *testing.T) {
	// Amazon Linux 2027: /usr/bin/yum is dnf5, and `yum -v repolist all`
	// exits 0 without printing any repo details
	out, err := os.ReadFile("yum/testdata/dnf5_al2027_repoinfo.txt")
	require.NoError(t, err)
	rt := newYumRuntime(t, map[string]string{"/usr/bin/dnf5": ""}, map[string]*mock.Command{
		yum.RhelYumRepoListCommand: {Stdout: "Updating and loading repositories:\nRepositories loaded.\n"},
		yum.Dnf5RepoInfoCommand:    {Stdout: string(out)},
	})

	y := &mqlYum{MqlRuntime: rt}
	assert.Equal(t, []string{"amazonlinux", "amazonlinux-debuginfo", "amazonlinux-source"}, yumRepoIds(t, y))

	repos, err := y.repos()
	require.NoError(t, err)
	repo := repos[0].(*mqlYumRepo)
	assert.Equal(t, "enabled", repo.Status.Data)
	assert.Equal(t, "/etc/yum.repos.d/amazonlinux.repo", repo.File.Data.Path.Data)
	assert.Equal(t, "7667", repo.Pkgs.Data)
}

func TestYumReposDnf5CommandFails(t *testing.T) {
	rt := newYumRuntime(t, map[string]string{"/usr/bin/dnf5": ""}, map[string]*mock.Command{
		yum.Dnf5RepoInfoCommand: {ExitStatus: 1, Stderr: "Failed to download metadata"},
	})
	y := &mqlYum{MqlRuntime: rt}
	_, err := y.repos()
	require.Error(t, err)
}

func TestYumReposDnf4(t *testing.T) {
	// Amazon Linux 2023, dnf 4: no /usr/bin/dnf5, so the verbose repolist is parsed
	rt := newYumRuntime(t, map[string]string{"/usr/bin/dnf-3": ""}, map[string]*mock.Command{
		yum.RhelYumRepoListCommand: {Stdout: `YUM version: 4.14.0
cachedir: /var/cache/dnf
Repo-id            : amazonlinux
Repo-name          : Amazon Linux 2023 repository
Repo-status        : enabled
Repo-filename      : /etc/yum.repos.d/amazonlinux.repo

Repo-id            : kernel-livepatch
Repo-name          : Amazon Linux 2023 Kernel Livepatch repository
Repo-status        : enabled
Repo-filename      : /etc/yum.repos.d/kernel-livepatch.repo
`},
		yum.Dnf5RepoInfoCommand: {ExitStatus: 127, Stderr: "dnf5: command not found"},
	})

	y := &mqlYum{MqlRuntime: rt}
	assert.Equal(t, []string{"amazonlinux", "kernel-livepatch"}, yumRepoIds(t, y))
}
