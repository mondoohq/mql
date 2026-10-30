// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package scp

import (
	"errors"
	"os"
	"strings"
	"time"

	scp_client "github.com/hnakamur/go-scp"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/local/statutil"
	"go.mondoo.com/mql/providers/os/connection/ssh/cat"
	"golang.org/x/crypto/ssh"
)

func NewFs(commandRunner cat.CommandRunner, client *ssh.Client) *Fs {
	return &Fs{
		sshClient:     client,
		scpClient:     scp_client.NewSCP(client),
		commandRunner: commandRunner,
		catFs:         cat.New(commandRunner),
	}
}

type Fs struct {
	sshClient     *ssh.Client
	scpClient     *scp_client.SCP
	commandRunner cat.CommandRunner
	catFs         *cat.Fs
}

func (s Fs) Name() string { return "scpfs" }

func (s Fs) Create(name string) (afero.File, error) {
	return nil, errors.New("create not implemented")
}

func (s Fs) Mkdir(name string, perm os.FileMode) error {
	return errors.New("mkdir not implemented")
}

func (s Fs) MkdirAll(path string, perm os.FileMode) error {
	return errors.New("mkdirall not implemented")
}

func (s Fs) Open(path string) (afero.File, error) {
	// NOTE: procfs cannot be read via scp, so we fall-back to catfs all paths there
	if strings.HasPrefix(path, "/proc") {
		return s.catFs.Open(path)
	}

	return FileOpen(s.scpClient, path)
}

func (s Fs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	return nil, errors.New("openfile not implemented")
}

func (s Fs) Remove(name string) error {
	return errors.New("remove not implemented")
}

func (s Fs) RemoveAll(path string) error {
	return errors.New("removeall not implemented")
}

func (s Fs) Rename(oldname, newname string) error {
	return errors.New("rename not implemented")
}

func (s Fs) Stat(path string) (os.FileInfo, error) {
	// NOTE we cannot use s.scpClient.Receive(path, io.Discard) since it would not work with directories
	return statutil.New(s.commandRunner).Stat(path)
}

// NOTE: deliberately no Lstat. Connection.FileInfo probes for an Lstat method
// and uses it as the primary call, so declaring one that always errors makes
// every stat fail instead of falling through to Stat above, which works. Symlink
// detection on this filesystem is handled by statutil's compound command.

func (s Fs) Chmod(name string, mode os.FileMode) error {
	return errors.New("chmod not implemented")
}

func (s Fs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return errors.New("chtimes not implemented")
}

func (s Fs) Chown(name string, uid, gid int) error {
	return errors.New("chown not implemented")
}
