// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style

// This implementation is derived from golang's internal stat implementation
// Golang licensed BSD-style license https://github.com/golang/go/blob/master/LICENSE
// see  https://github.com/golang/go/blob/5d1a95175e693f5be0bc31ae9e6a7873318925eb/src/syscall/types_windows.go

package cat

import (
	"os"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	FILE_SHARE_READ              = 0x00000001
	FILE_SHARE_WRITE             = 0x00000002
	FILE_SHARE_DELETE            = 0x00000004
	FILE_ATTRIBUTE_READONLY      = 0x00000001
	FILE_ATTRIBUTE_HIDDEN        = 0x00000002
	FILE_ATTRIBUTE_SYSTEM        = 0x00000004
	FILE_ATTRIBUTE_DIRECTORY     = 0x00000010
	FILE_ATTRIBUTE_ARCHIVE       = 0x00000020
	FILE_ATTRIBUTE_NORMAL        = 0x00000080
	FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400

	INVALID_FILE_ATTRIBUTES = 0xffffffff

	CREATE_NEW        = 1
	CREATE_ALWAYS     = 2
	OPEN_EXISTING     = 3
	OPEN_ALWAYS       = 4
	TRUNCATE_EXISTING = 5

	FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
	FILE_FLAG_BACKUP_SEMANTICS   = 0x02000000
	FILE_FLAG_OVERLAPPED         = 0x40000000
)

const (
	FSCTL_GET_REPARSE_POINT          = 0x900A8
	MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16 * 1024
	_IO_REPARSE_TAG_MOUNT_POINT      = 0xA0000003
	IO_REPARSE_TAG_SYMLINK           = 0xA000000C
	SYMBOLIC_LINK_FLAG_DIRECTORY     = 0x1
	_SYMLINK_FLAG_RELATIVE           = 1
)

const (
	FILE_TYPE_CHAR    = 0x0002
	FILE_TYPE_DISK    = 0x0001
	FILE_TYPE_PIPE    = 0x0003
	FILE_TYPE_REMOTE  = 0x8000
	FILE_TYPE_UNKNOWN = 0x0000
)

const (
	FSCTL_SET_REPARSE_POINT    = 0x000900A4
	IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
	SYMLINK_FLAG_RELATIVE      = 1
)

type Win32FileAttributeData struct {
	FileAttributes uint32
	CreationTime   *time.Time
	LastAccessTime *time.Time
	LastWriteTime  *time.Time
	FileSize       int64
}

// A fileStat is the implementation of FileInfo returned by Stat and Lstat.
type fileStat struct {
	name string

	// from ByHandleFileInformation, Win32FileAttributeData and Win32finddata
	FileAttributes uint32
	CreationTime   *time.Time
	LastAccessTime *time.Time
	LastWriteTime  *time.Time
	FileSize       int64

	// from Win32finddata
	Reserved0 uint32

	// what syscall.GetFileType returns
	filetype uint32
}

// devNullStat is fileStat structure describing DevNull file ("NUL").
var devNullStat = fileStat{
	name: os.DevNull,
}

func (fs *fileStat) Name() string { return fs.name }
func (fs *fileStat) IsDir() bool  { return fs.Mode().IsDir() }

func (fs *fileStat) isSymlink() bool {
	// Use instructions described at
	// https://devblogs.microsoft.com/oldnewthing/20100212-00/?p=14963
	// to recognize whether it's a symlink.
	if fs.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return false
	}
	return fs.Reserved0 == IO_REPARSE_TAG_SYMLINK ||
		fs.Reserved0 == IO_REPARSE_TAG_MOUNT_POINT
}

func (fs *fileStat) Size() int64 {
	return fs.FileSize
}

func (fs *fileStat) Mode() (m os.FileMode) {
	if fs == &devNullStat {
		return os.ModeDevice | os.ModeCharDevice | 0666
	}
	if fs.FileAttributes&FILE_ATTRIBUTE_READONLY != 0 {
		m |= 0444
	} else {
		m |= 0666
	}
	if fs.isSymlink() {
		return m | os.ModeSymlink
	}
	if fs.FileAttributes&FILE_ATTRIBUTE_DIRECTORY != 0 {
		m |= os.ModeDir | 0111
	}
	switch fs.filetype {
	case FILE_TYPE_PIPE:
		m |= os.ModeNamedPipe
	case FILE_TYPE_CHAR:
		m |= os.ModeDevice | os.ModeCharDevice
	}
	return m
}

func (fs *fileStat) ModTime() time.Time {
	if fs.LastWriteTime != nil {
		return *fs.LastWriteTime
	}
	log.Error().Str("file", fs.name).Msg("could not determine mod time")
	return time.Time{}
}

// Sys returns Win32FileAttributeData for file fs.
func (fs *fileStat) Sys() any {
	return &Win32FileAttributeData{
		FileAttributes: fs.FileAttributes,
		CreationTime:   fs.CreationTime,
		LastAccessTime: fs.LastAccessTime,
		LastWriteTime:  fs.LastWriteTime,
		FileSize:       fs.FileSize,
	}
}
