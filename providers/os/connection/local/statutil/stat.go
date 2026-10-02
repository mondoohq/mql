// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package statutil

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type CommandRunner interface {
	RunCommand(command string) (*shared.Command, error)
}

// linuxStatScript detects symlinks, verifies existence, and stats in one
// round-trip. SL=1 if symlink. Falls back to stat without -L for dangling
// symlinks. Captures stat -L stdout before checking exit code so SELinux
// %C errors don't trigger a spurious fallback. Path is passed as $1.
const linuxStatScript = `sh -c '` +
	`SL=0; test -L "$1" && SL=1; ` +
	`test -e "$1" -o $SL -eq 1 || exit 1; ` +
	`r=$(stat -L "$1" -c "$SL.%s.%f.%u.%g.%X.%Y.%C" 2>/dev/null) ` +
	`&& printf "%s\n" "$r" ` +
	`|| { [ -n "$r" ] && printf "%s\n" "$r" ` +
	`|| stat "$1" -c "$SL.%s.%f.%u.%g.%X.%Y.%C" 2>/dev/null; }` +
	`' _ `

// bsdStatScript detects symlinks and stats in one round-trip. Falls back
// to stat without -L for dangling symlinks. Path is passed as $1.
const bsdStatScript = `sh -c '` +
	`SL=0; test -L "$1" && SL=1; ` +
	`test -e "$1" -o $SL -eq 1 || exit 1; ` +
	`stat -L -f "$SL:%z:%p:%u:%g:%a:%m" "$1" 2>/dev/null ` +
	`|| stat -f "$SL:%z:%p:%u:%g:%a:%m" "$1"` +
	`' _ `

type statParser func(name string) (os.FileInfo, error)

func New(cmdRunner CommandRunner) *statHelper {
	return &statHelper{
		commandRunner: cmdRunner,
	}
}

// Stat helper implements the stat command for various unix systems
// since this helper is used by transports itself, we cannot rely on the
// platform detection mechanism (since it may rely on stat to determine the system)
// therefore we implement the minimum required to detect the right stat parser
type statHelper struct {
	commandRunner CommandRunner
	detected      bool
	statParser    statParser
}

var bsdunix = map[string]bool{
	"openbsd":   true,
	"dragonfly": true,
	"freebsd":   true,
	"netbsd":    true,
	"darwin":    true, // use bsd stat for macOS
}

func (s *statHelper) Stat(name string) (os.FileInfo, error) {
	// detect stat version
	if !s.detected {
		cmd, err := s.commandRunner.RunCommand("uname -s")
		if err != nil {
			log.Debug().Err(err).Str("file", name).Msg("could not detect platform for file stat")
			return nil, err
		}

		data, err := io.ReadAll(cmd.Stdout)
		if err != nil {
			return nil, err
		}

		// only switch to unix if we properly detected it, otherwise fallback to linux
		val := strings.ToLower(strings.TrimSpace(string(data)))

		isUnix, ok := bsdunix[val]
		if ok && isUnix {
			s.statParser = s.unix
		} else if val == "aix" {
			s.statParser = s.aix
		} else {
			s.statParser = s.linux
		}
		s.detected = true
	}

	return s.statParser(name)
}

func (s *statHelper) linux(name string) (os.FileInfo, error) {
	path := shared.ShellEscape(name)

	command := linuxStatScript + path

	cmd, err := s.commandRunner.RunCommand(command)
	if err != nil {
		log.Debug().Str("path", path).Str("command", command).Err(err).Send()
	}

	if cmd == nil {
		return nil, errors.New("could not parse file stat: " + path)
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	// Output format: SL.size.mode.uid.gid.atime.mtime.selinux
	// where SL is 1 (symlink) or 0 (not a symlink).
	// Take only the first line in case stderr leaked into the output.
	output := strings.TrimSpace(string(data))
	if output == "" {
		return nil, os.ErrNotExist
	}
	if idx := strings.IndexByte(output, '\n'); idx >= 0 {
		output = output[:idx]
	}
	statsData := strings.Split(output, ".")
	if len(statsData) != 8 {
		log.Debug().Str("path", path).Msg("could not parse file stat information")
		return nil, errors.New("could not parse file stat: " + path)
	}

	isSymlink := statsData[0] == "1"

	// Note: The SElinux context may not be supported by stats on all OSs.
	// For example: Alpine does not support it, resulting in statsData[7] == "C"

	size, err := strconv.Atoi(statsData[1])
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	uid, err := strconv.ParseInt(statsData[3], 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	gid, err := strconv.ParseInt(statsData[4], 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	mask, err := strconv.ParseUint(statsData[2], 16, 32)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	// statsData[5] is the access time (%X), statsData[6] the modification time (%Y)
	mtime, err := strconv.ParseInt(statsData[6], 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	mapMode := toFileMode(mask)
	if isSymlink {
		mapMode |= fs.ModeSymlink
	}

	return &shared.FileInfo{
		FName:    filepath.Base(path),
		FSize:    int64(size),
		FMode:    mapMode,
		FIsDir:   mapMode.IsDir(),
		FModTime: time.Unix(mtime, 0),
		Uid:      uid,
		Gid:      gid,
	}, nil
}

func (s *statHelper) unix(name string) (os.FileInfo, error) {
	path := shared.ShellEscape(name)

	cmd, err := s.commandRunner.RunCommand(bsdStatScript + path)
	if err != nil {
		log.Debug().Err(err).Send()
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	// Output format: SL:size:mode:uid:gid:atime:mtime
	statsData := strings.Split(strings.TrimSpace(string(data)), ":")
	if len(statsData) != 7 {
		return nil, os.ErrNotExist
	}

	isSymlink := statsData[0] == "1"

	size, err := strconv.Atoi(statsData[1])
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	uid, err := strconv.ParseInt(statsData[3], 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	gid, err := strconv.ParseInt(statsData[4], 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	// NOTE: the base is 8 instead of 16 on linux systems
	mask, err := strconv.ParseUint(statsData[2], 8, 32)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	mode := toFileMode(mask)
	if isSymlink {
		mode |= fs.ModeSymlink
	}

	// statsData[5] is the access time (%a), statsData[6] the modification time (%m)
	mtime, err := strconv.ParseInt(statsData[6], 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	return &shared.FileInfo{
		FName:    filepath.Base(path),
		FSize:    int64(size),
		FMode:    mode,
		FIsDir:   mode.IsDir(),
		FModTime: time.Unix(mtime, 0),
		Uid:      uid,
		Gid:      gid,
	}, nil
}

func (s *statHelper) aix(name string) (os.FileInfo, error) {
	path := shared.ShellEscape(name)
	var sb strings.Builder

	// AIX does not ship with stat, therefore we use perl stat function to retrieve the same information as on linux.
	// perl's -l operator detects symlinks; the result is prepended as the first colon-separated field.
	// Codes are taken from https://perldoc.perl.org/functions/stat
	//0 dev      device number of filesystem
	//1 ino      inode number
	//2 mode     file mode  (type and permissions)
	//3 nlink    number of (hard) links to the file
	//4 uid      numeric user ID of file's owner
	//5 gid      numeric group ID of file's owner
	//6 rdev     the device identifier (special files only)
	//7 size     total size of file, in bytes
	//8 atime    last access time since the epoch
	//9 mtime    last modify time since the epoch
	//10 ctime    inode change time (NOT creation time!) since the epoch
	//11 blksize  preferred block size for file system I/O
	//12 blocks   actual number of blocks allocated
	// perl stat() follows symlinks; lstat() fallback handles dangling symlinks
	script := `perl -e '$p = shift; $l = -l $p ? 1 : 0; @a = stat($p); @a = lstat($p) if !@a && $l; exit 2 if !@a; $u = getpwuid($a[4]); $g = getgrgid($a[5]); printf("%d:0%o:%s:%d:%s:%d:%d:%d", $l, $a[2], $u, $a[4], $g, $a[5], $a[7], $a[9])'`
	sb.WriteString(script)
	sb.WriteString(" ")
	sb.WriteString(path)

	cmd, err := s.commandRunner.RunCommand(sb.String())
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	statsData := strings.Split(string(data), ":")
	if len(statsData) != 8 {
		return nil, os.ErrNotExist
	}

	isSymlink := statsData[0] == "1"

	size, err := strconv.Atoi(statsData[6])
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	uid, err := strconv.ParseInt(statsData[3], 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	gid, err := strconv.ParseInt(statsData[5], 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	// NOTE: the base is 8 instead of 16 on linux systems
	mask, err := strconv.ParseUint(statsData[1], 8, 32)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	mode := toFileMode(mask)
	if isSymlink {
		mode |= fs.ModeSymlink
	}

	mtime, err := strconv.ParseInt(statsData[7], 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat "+name)
	}

	return &shared.FileInfo{
		FName:    filepath.Base(path),
		FSize:    int64(size),
		FMode:    mode,
		FIsDir:   mode.IsDir(),
		FModTime: time.Unix(mtime, 0),
		Uid:      uid,
		Gid:      gid,
	}, nil
}

const (
	S_IFMT  = 0o170000
	S_IFBLK = 0o60000
	S_IFCHR = 0o20000
	S_IFDIR = 0o40000
	S_IFIFO = 10000
	S_ISUID = 0o4000
	S_ISGID = 0o2000
	S_ISVTX = 0o1000
)

func toFileMode(mask uint64) os.FileMode {
	mode := os.FileMode(uint32(mask) & 0o0777)

	// taken from https://github.com/golang/go/blob/2ebe77a2fda1ee9ff6fd9a3e08933ad1ebaea039/src/os/stat_linux.go
	switch mask & S_IFMT {
	case S_IFBLK:
		mode |= fs.ModeDevice
	case S_IFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case S_IFDIR:
		mode |= fs.ModeDir
	case S_IFIFO:
		mode |= fs.ModeNamedPipe
	case syscall.S_IFLNK:
		mode |= fs.ModeSymlink
	case syscall.S_IFREG:
		// nothing to do
	case syscall.S_IFSOCK:
		mode |= fs.ModeSocket
	}
	if mask&syscall.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if mask&syscall.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if mask&syscall.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}
