// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kballard/go-shellquote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func TestListDirCommand(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		// -A lists dotfiles; without it Claude Code's
		// backups/.claude.json.backup.* files are invisible
		{"/home/ubuntu/.claude/backups", []string{"ls", "-1A", "/home/ubuntu/.claude/backups"}},
		{"/srv/sp ace ü", []string{"ls", "-1A", "/srv/sp ace ü"}},
		{`/tmp/od'd $(x)`, []string{"ls", "-1A", `/tmp/od'd $(x)`}},
		// a leading dash must not be read as an option
		{"-rf", []string{"ls", "-1A", "./-rf"}},
	}
	for _, tc := range tests {
		args, err := shellquote.Split(listDirCommand(tc.path))
		require.NoError(t, err)
		assert.Equal(t, tc.want, args, tc.path)
	}
}

func TestParseDirListing(t *testing.T) {
	// `sudo ls -1A /home/ubuntu/.claude/backups` on Ubuntu 24.04
	out := ".claude.json.backup.1790911549739\n" +
		".claude.json.backup.1790911549764\n" +
		".claude.json.backup.1790913703114\n" +
		".claude.json.backup.1790913703572\n" +
		".claude.json.backup.notanumber\n"
	assert.Equal(t, []string{
		".claude.json.backup.1790911549739",
		".claude.json.backup.1790911549764",
		".claude.json.backup.1790913703114",
		".claude.json.backup.1790913703572",
		".claude.json.backup.notanumber",
	}, parseDirListing([]byte(out)))

	// spaces at either end of a name are part of the name, including on the
	// first and last line of the output
	out = " leading\nsp ace ü.txt\ntrailing \n"
	assert.Equal(t, []string{" leading", "sp ace ü.txt", "trailing "}, parseDirListing([]byte(out)))

	// . and .. never are entries, an empty directory has none
	assert.Equal(t, []string{".hidden"}, parseDirListing([]byte(".\n..\n.hidden\n")))
	assert.Empty(t, parseDirListing([]byte("")))
	assert.Empty(t, parseDirListing([]byte("\n")))

	// CRLF line endings
	assert.Equal(t, []string{"a", "b"}, parseDirListing([]byte("a\r\nb\r\n")))
}

func TestListDirError(t *testing.T) {
	// stderr of GNU coreutils 8.25 ls on Ubuntu 16.04
	err := listDirError("/nope", "ls: cannot access '/nope': No such file or directory\n")
	assert.True(t, errors.Is(err, os.ErrNotExist))
	assert.False(t, errors.Is(err, os.ErrPermission))

	err = listDirError("/root", "ls: cannot open directory '/root': Permission denied\n")
	assert.True(t, errors.Is(err, os.ErrPermission))
	assert.False(t, errors.Is(err, os.ErrNotExist))

	err = listDirError("/x", "ls: reading directory '/x': Input/output error\n")
	assert.False(t, errors.Is(err, os.ErrNotExist))
	assert.False(t, errors.Is(err, os.ErrPermission))
	assert.Contains(t, err.Error(), "Input/output error")
}

type fakeRun struct {
	stdout   string
	stderr   string
	exit     int
	commands []string
}

func (r *fakeRun) RunCommand(command string) (*shared.Command, error) {
	r.commands = append(r.commands, command)
	return &shared.Command{
		Command:    command,
		Stdout:     bytes.NewBufferString(r.stdout),
		Stderr:     bytes.NewBufferString(r.stderr),
		ExitStatus: r.exit,
	}, nil
}

type fakeStat struct {
	missing map[string]bool
}

func (s fakeStat) Stat(name string) (os.FileInfo, error) {
	if s.missing[name] {
		return nil, os.ErrNotExist
	}
	return &shared.FileInfo{FName: filepath.Base(name), FModTime: time.Unix(0, 0)}, nil
}

func TestReaddirSkipsEntryThatCannotBeStatted(t *testing.T) {
	run := &fakeRun{stdout: ".hidden\ngone\nkept\n"}
	fs := &Fs{commandRunner: run, statter: fakeStat{missing: map[string]bool{"/d/gone": true}}}

	infos, err := NewFile(fs, "/d", false).Readdir(-1)
	require.NoError(t, err)
	names := []string{}
	for _, fi := range infos {
		names = append(names, fi.Name())
	}
	assert.Equal(t, []string{".hidden", "kept"}, names)
}

func TestReaddirnamesFailedListing(t *testing.T) {
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })

	missing := &fakeRun{stderr: "ls: cannot access '/nope': No such file or directory\n", exit: 2}
	_, err := NewFile(&Fs{commandRunner: missing}, "/nope", false).Readdirnames(-1)
	assert.True(t, errors.Is(err, os.ErrNotExist))

	denied := &fakeRun{stderr: "ls: cannot open directory '/root': Permission denied\n", exit: 2}

	// v13 behavior: a refused listing reads as an empty directory
	plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)}))
	names, err := NewFile(&Fs{commandRunner: denied}, "/root", false).Readdirnames(-1)
	require.NoError(t, err)
	assert.Empty(t, names)

	plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	_, err = NewFile(&Fs{commandRunner: denied}, "/root", false).Readdirnames(-1)
	assert.True(t, errors.Is(err, os.ErrPermission))

	// a non-zero exit with output (GNU ls exits 1 on minor problems) keeps
	// the entries it listed
	partial := &fakeRun{stdout: "a\n", exit: 1}
	names, err = NewFile(&Fs{commandRunner: partial}, "/d", false).Readdirnames(-1)
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, names)
}

func TestReadContentQuotesPath(t *testing.T) {
	run := &fakeRun{stdout: "x"}
	f := NewFile(&Fs{commandRunner: run}, "-rf", false)
	_, err := f.readContent()
	require.NoError(t, err)
	args, err := shellquote.Split(run.commands[0])
	require.NoError(t, err)
	assert.Equal(t, []string{"cat", "./-rf"}, args)
}
