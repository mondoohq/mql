// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"strconv"
	"strings"
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

// tooLargeExitStatus is the exit status openScript ends with when the file is
// larger than maxOpenSize.
const tooLargeExitStatus = 65

// maxOpenSize is the largest file Open reads. WinRM returns a file whole, in
// the command's output: a 105 MB model file had not finished after ten
// minutes. Past this a read fails at once with ErrFileTooLarge instead of
// stalling the scan.
const maxOpenSize = 32 << 20

// ErrFileTooLarge is returned by Open for a file larger than maxOpenSize.
var ErrFileTooLarge = errors.New("file is too large to read over WinRM")

// notFoundExitStatus and accessDeniedExitStatus are the exit statuses
// openScript ends with when the file cannot be opened because it is missing
// or because the account may not read it. Any other failure, such as a file
// another process holds open without sharing it, ends with exit status 1 and
// the reason on stderr.
const (
	notFoundExitStatus     = 66
	accessDeniedExitStatus = 67
)

// readChunkSize is how many bytes openScript reads and writes out at a time,
// so that PowerShell never holds a whole large file as one base64 string.
const readChunkSize = 3 << 20

// openScript reads a file, or reports a directory through dirExitStatus or a
// file over maxOpenSize through tooLargeExitStatus, in one round trip.
//
// The file's bytes are written as base64, one line per chunk. Get-Content
// would decode them as text in the console code page and write each line
// back with CRLF, so UTF-8 without a BOM came back garbled, LF line endings
// turned into CRLF, a CRLF was added at the end and binary files were
// corrupted. The file is opened with the sharing Get-Content uses, so a log
// another process is writing to still reads.
func openScript(name string) string {
	quoted := powershell.SingleQuote(name)
	return powershell.Encode("if (Test-Path -LiteralPath " + quoted + " -PathType Container) { exit " +
		strconv.Itoa(dirExitStatus) + " }; " +
		"$i = Get-Item -LiteralPath " + quoted + " -Force -ErrorAction SilentlyContinue; " +
		"if ($i -and $i.Length -gt " + strconv.Itoa(maxOpenSize) + ") { exit " + strconv.Itoa(tooLargeExitStatus) + " }; " +
		"$s = $null; try { " +
		"$s = [IO.File]::Open(" + quoted + ", [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete'); " +
		"$b = New-Object byte[] " + strconv.Itoa(readChunkSize) + "; " +
		"while (($n = $s.Read($b, 0, $b.Length)) -gt 0) { [Console]::Out.WriteLine([Convert]::ToBase64String($b, 0, $n)) } " +
		"} catch { " +
		"$x = $_.Exception; while ($x.InnerException) { $x = $x.InnerException }; " +
		"[Console]::Error.WriteLine($x.Message); " +
		"if ($x -is [IO.FileNotFoundException] -or $x -is [IO.DirectoryNotFoundException]) { exit " + strconv.Itoa(notFoundExitStatus) + " }; " +
		"if ($x -is [UnauthorizedAccessException]) { exit " + strconv.Itoa(accessDeniedExitStatus) + " }; " +
		"exit 1 " +
		"} finally { if ($s) { $s.Dispose() } }")
}

// decodeContent turns openScript's output back into the file's bytes.
func decodeContent(out []byte) ([]byte, error) {
	var data []byte
	for line := range bytes.FieldsSeq(out) {
		chunk := make([]byte, base64.StdEncoding.DecodedLen(len(line)))
		n, err := base64.StdEncoding.Decode(chunk, line)
		if err != nil {
			return nil, errors.Wrap(err, "could not decode file content read over WinRM")
		}
		data = append(data, chunk[:n]...)
	}
	return data, nil
}

// openError reports why openScript could not read a file.
func openError(name string, cmd *shared.Command) error {
	var reason error
	switch cmd.ExitStatus {
	case notFoundExitStatus:
		reason = os.ErrNotExist
	case accessDeniedExitStatus:
		reason = os.ErrPermission
	default:
		msg := ""
		if cmd.Stderr != nil {
			if stderr, err := io.ReadAll(cmd.Stderr); err == nil {
				msg = strings.TrimSpace(string(stderr))
			}
		}
		if msg == "" {
			msg = "exit status " + strconv.Itoa(cmd.ExitStatus)
		}
		reason = errors.New(msg)
	}
	return &os.PathError{Op: "open", Path: name, Err: reason}
}

// getItemScript stats one path. -Force is required: without it Get-Item does
// not return hidden or system items (C:\ProgramData, the "Application Data"
// junctions), so they would read as missing. Windows PowerShell 5.1 still
// reports a file the system holds open exclusively, such as pagefile.sys, as
// missing even with -Force.
func getItemScript(name string) string {
	return powershell.Encode("Get-Item -LiteralPath " + powershell.SingleQuote(name) + " -Force | ConvertTo-JSON")
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
		"LastWriteTime = [DateTimeOffset]::new($_.LastWriteTimeUtc).ToUnixTimeMilliseconds(); " +
		"LinkType = $_.LinkType } }); " +
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
	if cmd.ExitStatus == tooLargeExitStatus {
		return nil, &os.PathError{Op: "open", Path: name, Err: ErrFileTooLarge}
	}
	if cmd.ExitStatus != 0 {
		return nil, openError(name, cmd)
	}

	out, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	data, err := decodeContent(out)
	if err != nil {
		return nil, err
	}

	file := NewFile(name, bytes.NewBuffer(data))
	file.catfs = cat
	return file, nil
}

func (cat *Fs) Stat(name string) (os.FileInfo, error) {
	return cat.stat(name, false)
}

// LstatIfPossible reports a junction or symbolic link as the link itself, as
// os.Lstat does, where Stat describes what it points to. afero.Walk uses it
// when the filesystem has it, so a walk does not descend into a link: a user
// profile holds junctions such as AppData\Local\Application Data that point
// back at their own parent, and following one walks the same tree forever.
func (cat *Fs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	fi, err := cat.stat(name, true)
	return fi, true, err
}

func (cat *Fs) stat(name string, lstat bool) (os.FileInfo, error) {
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

	fs := &fileStat{
		name:           item.Name,
		FileSize:       item.Length,
		FileAttributes: item.Attributes,
		CreationTime:   powershell.PSJsonTimestamp(item.CreationTime),
		LastAccessTime: powershell.PSJsonTimestamp(item.LastAccessTime),
		LastWriteTime:  powershell.PSJsonTimestamp(item.LastWriteTime),
	}
	if lstat {
		fs.Reserved0 = reparseTag(item.LinkType)
	}
	return fs, nil
}

// reparseTag maps PowerShell's LinkType to the reparse tag fileStat reads to
// report a link. A hard link is an ordinary file, and so is a reparse point
// of any other kind, such as a OneDrive placeholder.
func reparseTag(linkType string) uint32 {
	switch linkType {
	case "Junction":
		return IO_REPARSE_TAG_MOUNT_POINT
	case "SymbolicLink":
		return IO_REPARSE_TAG_SYMLINK
	}
	return 0
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
