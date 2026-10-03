// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/ssh/cat"
)

// fakeContainer answers the listing commands the way a container's shell
// does for /usr/lib/systemd/journald.conf.d on ubuntu:24.04, which holds one
// regular file, a symlink and a subdirectory.
type fakeContainer struct{}

func (c *fakeContainer) RunCommand(command string) (*shared.Command, error) {
	res := &shared.Command{Command: command, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	switch {
	case strings.HasPrefix(command, "ls -1A /usr/lib/systemd/journald.conf.d"):
		res.Stdout.(*bytes.Buffer).WriteString("syslog.conf\nlinked.conf\nsub\n")
	default:
		res.ExitStatus = 1
		res.Stderr.(*bytes.Buffer).WriteString("ls: cannot access: No such file or directory\n")
	}
	return res, nil
}

// Readdirnames lists every entry, not only subdirectories. It used to run
// `find -maxdepth 1 -type d`, so every Glob and directory listing over the
// docker-container transport lost its regular files: journald drop-ins,
// polkit actions, python packages.
func TestReaddirnamesListsEveryEntry(t *testing.T) {
	runner := &fakeContainer{}
	f := &File{path: "/usr/lib/systemd/journald.conf.d", catFs: cat.New(runner)}

	names, err := f.Readdirnames(-1)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"syslog.conf", "linked.conf", "sub"}, names)
}

func TestReaddirnamesOfAMissingDirectoryIsAnError(t *testing.T) {
	f := &File{path: "/nope", catFs: cat.New(&fakeContainer{})}
	_, err := f.Readdirnames(-1)
	assert.Error(t, err, "a failed listing is not an empty directory")
}
