// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kballard/go-shellquote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/ssh/cat"
)

func TestCatFs(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/cat.toml")
	p, err := mock.New(0, &inventory.Asset{}, mock.WithPath(filepath))
	require.NoError(t, err)

	flags := map[string]*llx.Primitive{
		"sudo": llx.BoolPrimitive(true),
	}

	cw := &CommandWrapper{
		commandRunner: p,
		sudo:          shared.ParseSudo(flags),
	}

	catfs := cat.New(cw)

	// get file stats
	fi, err := catfs.Stat("/etc/ssh/sshd_config")
	require.NoError(t, err)

	assert.Equal(t, int64(4317), fi.Size())
	assert.Equal(t, false, fi.IsDir())
	assert.Equal(t, os.FileMode(0x180), fi.Mode())
	assert.Equal(t, time.Unix(1590418792, 0), fi.ModTime())

	// fetch file content
	f, err := catfs.Open("/etc/ssh/sshd_config")
	require.NoError(t, err)
	defer f.Close()

	data, err := io.ReadAll(f)
	require.NoError(t, err)

	expected := `X11Forwarding no
PermitRootLogin no
PasswordAuthentication yes
MaxAuthTries 4
UsePAM yes
`
	assert.Equal(t, expected, string(data))

	dir, err := catfs.Open("/etc/ssh")
	require.NoError(t, err)
	defer dir.Close()

	stat, err := dir.Stat()
	require.NoError(t, err)
	assert.Equal(t, true, stat.IsDir())
	files, err := dir.Readdirnames(-1)
	require.NoError(t, err)
	assert.Equal(t, []string{"ssh_config", "ssh_config.d", "ssh_host_ecdsa_key", "ssh_host_ecdsa_key.pub", "ssh_host_ed25519_key", "ssh_host_ed25519_key.pub", "ssh_host_rsa_key", "ssh_host_rsa_key.pub", "sshd_config", "sshd_config.rpmnew"}, files)

	_, err = catfs.Open("/etc/not-there")
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

func TestCatFsReusesStatHelper(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/cat.toml")
	p, err := mock.New(0, &inventory.Asset{}, mock.WithPath(filepath))
	require.NoError(t, err)

	flags := map[string]*llx.Primitive{
		"sudo": llx.BoolPrimitive(true),
	}

	cw := &CommandWrapper{
		commandRunner: p,
		sudo:          shared.ParseSudo(flags),
	}

	catfs := cat.New(cw)

	_, err = catfs.Stat("/etc/ssh/sshd_config")
	require.NoError(t, err)

	f, err := catfs.Open("/etc/ssh/sshd_config")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	assert.Equal(t, 1, countCommands(cw.commands, "sudo uname -s"))
}

func TestCatFsReaddirnamesQuotesPath(t *testing.T) {
	fixture, _ := filepath.Abs("./testdata/cat.toml")
	p, err := mock.New(0, &inventory.Asset{}, mock.WithPath(fixture))
	require.NoError(t, err)

	cw := &CommandWrapper{
		commandRunner: p,
		sudo:          shared.ParseSudo(map[string]*llx.Primitive{"sudo": llx.BoolPrimitive(true)}),
	}

	// directory names are read off the target and fed back into the listing
	// command, so they have to survive as a single argument no matter what
	// characters they contain
	dir := `/home/vagrant/.ssh/od'd dir$(x)`

	f := cat.NewFile(cat.New(cw), dir, false)
	// the mock has no entry for this directory, only the command matters
	_, _ = f.Readdirnames(-1)

	require.Len(t, cw.commands, 1)
	args, err := shellquote.Split(cw.commands[0])
	require.NoError(t, err)
	assert.Equal(t, []string{"sudo", "ls", "-1A", dir}, args)
}

func countCommands(commands []string, target string) int {
	count := 0
	for _, command := range commands {
		if command == target {
			count++
		}
	}
	return count
}

type CommandWrapper struct {
	commandRunner cat.CommandRunner
	sudo          *inventory.Sudo
	commands      []string
}

func (cw *CommandWrapper) RunCommand(command string) (*shared.Command, error) {
	cmd := shared.BuildSudoCommand(cw.sudo, command)
	cw.commands = append(cw.commands, cmd)
	return cw.commandRunner.RunCommand(cmd)
}
