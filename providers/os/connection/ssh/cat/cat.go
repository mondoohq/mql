// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat

import (
	"os"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/local/statutil"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type CommandRunner interface {
	RunCommand(command string) (*shared.Command, error)
}

func New(cmdRunner CommandRunner) *Fs {
	return &Fs{
		commandRunner: cmdRunner,
		statter:       statutil.New(cmdRunner),
	}
}

type statter interface {
	Stat(name string) (os.FileInfo, error)
}

type Fs struct {
	commandRunner CommandRunner
	statter       statter
	base64        *bool
}

func (cat *Fs) Name() string {
	return "Cat FS"
}

func (cat *Fs) useBase64encoding() bool {
	if cat.base64 != nil {
		return *cat.base64
	}

	b := cat.base64available()
	cat.base64 = &b
	return b
}

func (cat *Fs) base64available() bool {
	cmd, err := cat.commandRunner.RunCommand("command -v base64")
	if err != nil {
		log.Debug().Msg("base64 command not found on target system")
		return false
	}
	log.Debug().Msg("use base64 encoding for data transfer")
	return cmd.ExitStatus == 0
}

func (cat *Fs) Open(name string) (afero.File, error) {
	_, err := cat.statter.Stat(name)
	if err != nil {
		return nil, err
	}

	return NewFile(cat, name, cat.useBase64encoding()), nil
}

var NotImplemented = errors.New("not implemented")

func (cat *Fs) Stat(name string) (os.FileInfo, error) {
	return cat.statter.Stat(name)
}

func (cat *Fs) Create(name string) (afero.File, error) {
	return nil, NotImplemented
}

func (cat *Fs) Mkdir(name string, perm os.FileMode) error {
	return NotImplemented
}

func (cat *Fs) MkdirAll(path string, perm os.FileMode) error {
	return NotImplemented
}

func (cat *Fs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	return nil, NotImplemented
}

func (cat *Fs) Remove(name string) error {
	return NotImplemented
}

func (cat *Fs) RemoveAll(path string) error {
	return NotImplemented
}

func (cat *Fs) Rename(oldname, newname string) error {
	return NotImplemented
}

func (cat *Fs) Chmod(name string, mode os.FileMode) error {
	return NotImplemented
}

func (cat *Fs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return NotImplemented
}

func (cat *Fs) Chown(name string, uid, gid int) error {
	return NotImplemented
}

func (cat *Fs) ReadDir(name string) ([]os.FileInfo, error) {
	file := NewFile(cat, name, false)
	defer file.Close()
	return file.Readdir(-1) // -1 is ignored, we read all files
}
