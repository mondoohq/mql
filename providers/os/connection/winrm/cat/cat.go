// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

type CommandRunner interface {
	RunCommand(command string) (*shared.Command, error)
}

func New(cmdRunner CommandRunner) *Fs {
	return &Fs{
		commandRunner: cmdRunner,
	}
}

type Fs struct {
	commandRunner CommandRunner
}

func (cat *Fs) Name() string {
	return "Winrm Cat FS"
}

// The two scripts below are handed to powershell as an encoded command
// rather than as a quoted command line. A plain `powershell -c "... '<name>'"`
// nests two parsers, the command line and then powershell itself, so a name
// has to survive both. Encoding removes the outer layer entirely and
// SingleQuote covers the inner one.

// dirExitStatus is the exit status openScript ends with when the path is a
// directory. Get-Content cannot read a directory, so without it a directory
// failed to open as if it did not exist, and nothing could be listed.
const dirExitStatus = 64

// openScript reads a file, or reports a directory through dirExitStatus, in
// one round trip. A missing path still fails in Get-Content, as before.
func openScript(name string) string {
	quoted := powershell.SingleQuote(name)
	return powershell.Encode("if (Test-Path -LiteralPath " + quoted + " -PathType Container) { exit " +
		strconv.Itoa(dirExitStatus) + " }; Get-Content -LiteralPath " + quoted)
}

func getItemScript(name string) string {
	return powershell.Encode("Get-Item -LiteralPath " + powershell.SingleQuote(name) + " | ConvertTo-JSON")
}

// listDirScript lists a directory as a JSON array, one object per entry, with
// what a FileInfo needs so that no entry has to be stat'ed separately. Times
// are Unix milliseconds, which reads the same on Windows PowerShell and
// PowerShell 7, whose ConvertTo-Json format dates differently. Output is UTF-8
// because the console code page would turn a name like über.txt into one that
// no longer exists. An entry that cannot be read is skipped; the errors are
// written to stderr and fail the script only when nothing could be listed.
func listDirScript(name string) string {
	return powershell.Encode("[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ev = $null; " +
		"$e = @(Get-ChildItem -LiteralPath " + powershell.SingleQuote(name) + " -Force -ErrorAction SilentlyContinue -ErrorVariable ev | ForEach-Object { " +
		"[pscustomobject]@{ " +
		"Name = $_.Name; " +
		"Length = $(if ($_.PSIsContainer) { 0 } else { $_.Length }); " +
		"Attributes = [int]$_.Attributes; " +
		"CreationTime = [DateTimeOffset]::new($_.CreationTimeUtc).ToUnixTimeMilliseconds(); " +
		"LastAccessTime = [DateTimeOffset]::new($_.LastAccessTimeUtc).ToUnixTimeMilliseconds(); " +
		"LastWriteTime = [DateTimeOffset]::new($_.LastWriteTimeUtc).ToUnixTimeMilliseconds() } }); " +
		"ConvertTo-Json -InputObject $e -Compress; " +
		"if ($ev -and $e.Count -eq 0) { [Console]::Error.WriteLine((($ev | ForEach-Object { $_.FullyQualifiedErrorId }) -join ' ')); exit 1 }")
}

func (cat *Fs) Open(name string) (afero.File, error) {
	// NOTE: do not use type here since it does not work well with file names like 'C:\Program Files\New Text Document.txt'
	cmd, err := cat.commandRunner.RunCommand(openScript(name))
	if err != nil {
		return nil, err
	}

	if cmd.ExitStatus == dirExitStatus {
		return newDir(cat, name), nil
	}
	if cmd.ExitStatus != 0 {
		return nil, os.ErrNotExist
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	return NewFile(name, bytes.NewBuffer(data)), nil
}

func (cat *Fs) Stat(name string) (os.FileInfo, error) {
	cmd, err := cat.commandRunner.RunCommand(getItemScript(name))
	if err != nil {
		return nil, err
	}

	if cmd.ExitStatus != 0 {
		return nil, os.ErrNotExist
	}

	item, err := ParseGetItem(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	return &fileStat{
		name:           item.Name,
		FileSize:       item.Length,
		FileAttributes: item.Attributes,
		CreationTime:   powershell.PSJsonTimestamp(item.CreationTime),
		LastAccessTime: powershell.PSJsonTimestamp(item.LastAccessTime),
		LastWriteTime:  powershell.PSJsonTimestamp(item.LastWriteTime),
	}, nil
}

var NotImplemented = errors.New("not implemented")

func (cat *Fs) Create(name string) (afero.File, error) {
	return nil, errors.New("not implemented")
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
