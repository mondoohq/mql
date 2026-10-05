// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/kballard/go-shellquote"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func NewFile(catfs *Fs, path string, useBase64encoding bool) *File {
	return &File{catfs: catfs, path: path, useBase64encoding: useBase64encoding}
}

// File is a file read through `cat` on the target. The first Read, ReadAt or
// Seek reads the whole file into memory; all later calls are served from that
// copy. Holding the content makes the file seekable, which decoders such as
// the binary plist one need: they read the header, seek back to the start and
// read again.
type File struct {
	catfs             *Fs
	content           *bytes.Reader
	path              string
	useBase64encoding bool
}

// load reads the file content on first use.
func (f *File) load() (*bytes.Reader, error) {
	if f.content != nil {
		return f.content, nil
	}
	data, err := f.readContent()
	if err != nil {
		return nil, err
	}
	f.content = bytes.NewReader(data)
	return f.content, nil
}

func (f *File) readContent() ([]byte, error) {
	// we need shellquote to escape filenames with spaces
	catCmd := shellquote.Join("cat", argPath(f.path))
	if f.useBase64encoding {
		catCmd = catCmd + " | base64"
	}

	cmd, err := f.catfs.commandRunner.RunCommand(catCmd)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	if f.useBase64encoding {
		data, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, errors.Wrap(err, "could not decode base64 data stream")
		}
	}

	return data, nil
}

func (f *File) Close() error {
	return nil
}

func (f *File) Name() string {
	return f.path
}

func (f *File) Stat() (os.FileInfo, error) {
	return f.catfs.Stat(f.path)
}

func (f *File) Sync() error {
	return nil
}

func (f *File) Truncate(size int64) error {
	return nil
}

func (f *File) Read(b []byte) (n int, err error) {
	content, err := f.load()
	if err != nil {
		return 0, err
	}
	return content.Read(b)
}

func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	content, err := f.load()
	if err != nil {
		return 0, err
	}
	return content.ReadAt(b, off)
}

func (f *File) Readdir(count int) (res []os.FileInfo, err error) {
	names, err := f.Readdirnames(count)
	if err != nil {
		return nil, err
	}

	res = []os.FileInfo{}
	for _, name := range names {
		var statPath string
		if filepath.IsAbs(name) {
			statPath = name
		} else {
			statPath = filepath.Join(f.path, name)
		}
		fi, err := f.catfs.Stat(statPath)
		if err != nil {
			// An entry can vanish between the listing and the stat (a process
			// leaving /proc, a rotated log), and a name containing a newline
			// arrives split across lines. Skip it like os.File.Readdir does for
			// vanished entries, instead of dropping the whole directory.
			log.Debug().Err(err).Str("path", statPath).Msg("cat> skip directory entry that cannot be stat'ed")
			continue
		}
		res = append(res, fi)
	}

	return res, nil
}

func (f *File) Readdirnames(n int) (names []string, err error) {
	// TODO: input n is ignored

	cmd, err := f.catfs.commandRunner.RunCommand(listDirCommand(f.path))
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	names = parseDirListing(data)
	if cmd.ExitStatus != 0 && len(names) == 0 {
		var stderr []byte
		if cmd.Stderr != nil {
			stderr, _ = io.ReadAll(cmd.Stderr)
		}
		err = listDirError(f.path, string(stderr))
		if errors.Is(err, os.ErrPermission) && !plugin.StructuredErrors() {
			return []string{}, nil
		}
		return nil, err
	}

	return names, nil
}

// listDirCommand builds the command that lists the entries of a directory,
// one per line. -A includes dotfiles (but not . and ..), which plain ls
// hides. The path is quoted so it survives as a single argument.
func listDirCommand(path string) string {
	return shellquote.Join("ls", "-1A", argPath(path))
}

// argPath keeps a path that starts with a dash from being parsed as an
// option. "./" is used instead of "--" because the same commands also run
// through PowerShell on WinRM connections.
func argPath(path string) string {
	if strings.HasPrefix(path, "-") {
		return "./" + path
	}
	return path
}

// parseDirListing splits the output of listDirCommand into entry names. Only
// line breaks separate entries: a name may start or end with a space.
func parseDirListing(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	names := []string{}
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || line == "." || line == ".." {
			continue
		}
		names = append(names, line)
	}
	return names
}

// listDirError turns the stderr of a failed listing into an error that
// errors.Is recognizes as os.ErrNotExist or os.ErrPermission, matching
// what the sftp and local filesystems return.
func listDirError(path string, stderr string) error {
	msg := strings.TrimSpace(stderr)
	var cause error
	switch {
	case strings.Contains(msg, "No such file or directory"):
		cause = os.ErrNotExist
	case strings.Contains(msg, "Permission denied"):
		cause = os.ErrPermission
	default:
		if msg == "" {
			msg = "could not list directory"
		}
		cause = errors.New(msg)
	}
	return &os.PathError{Op: "readdir", Path: path, Err: cause}
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	content, err := f.load()
	if err != nil {
		return 0, err
	}
	return content.Seek(offset, whence)
}

func (f *File) Write(b []byte) (n int, err error) {
	return 0, errors.New("not implemented")
}

func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	return 0, errors.New("not implemented")
}

func (f *File) WriteString(s string) (ret int, err error) {
	return 0, errors.New("not implemented")
}
