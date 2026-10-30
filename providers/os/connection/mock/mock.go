// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gobwas/glob"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// Data holds the mocked data entries
type TomlData struct {
	Commands map[string]*Command      `toml:"commands"`
	Files    map[string]*MockFileData `toml:"files"`
}

type Command struct {
	PlatformID string `toml:"platform_id"`
	Command    string `toml:"command"`
	Stdout     string `toml:"stdout"`
	Stderr     string `toml:"stderr"`
	ExitStatus int    `toml:"exit_status"`
}

type MockProviderInfo struct {
	ID      string `toml:"id"`
	Runtime string `toml:"runtime"`
}

type FileInfo struct {
	Mode    os.FileMode `toml:"mode"`
	ModTime time.Time   `toml:"time"`
	IsDir   bool        `toml:"isdir"`
	Uid     int64       `toml:"uid"`
	Gid     int64       `toml:"gid"`
	Size    int64       `toml:"size"`
}

type MockFileData struct {
	Path string `toml:"path"`

	StatData FileInfo `toml:"stat"`
	Enoent   bool     `toml:"enoent"`
	// Holds the file content
	Data []byte `toml:"data"`
	// Plain String response (simpler user usage, will not be used for automated recording)
	Content string `toml:"content"`
}

type Connection struct {
	plugin.Connection
	data    *TomlData
	asset   *inventory.Asset
	mutex   sync.Mutex
	missing map[string]map[string]bool
}

type mockConfigOptions struct {
	path     string
	tomlData *TomlData
}

type Option func(cfg *mockConfigOptions) error

func WithPath(path string) func(cfg *mockConfigOptions) error {
	return func(cfg *mockConfigOptions) error {
		cfg.path = path
		return nil
	}
}

func WithData(data *TomlData) func(cfg *mockConfigOptions) error {
	return func(cfg *mockConfigOptions) error {
		cfg.tomlData = data
		return nil
	}
}

func New(id uint32, asset *inventory.Asset, opts ...Option) (*Connection, error) {
	res := &Connection{
		Connection: plugin.NewConnection(id, asset),
		data:       &TomlData{},
		asset:      asset,
		missing: map[string]map[string]bool{
			"file":    {},
			"command": {},
		},
	}

	var cfg mockConfigOptions
	for _, o := range opts {
		if err := o(&cfg); err != nil {
			return nil, err
		}
	}

	res.data.Commands = map[string]*Command{}
	res.data.Files = map[string]*MockFileData{}

	// load provided toml data from file
	if cfg.path != "" {
		data, err := os.ReadFile(cfg.path)
		if err != nil {
			return nil, errors.New("could not open: " + cfg.path)
		}

		if _, err := toml.Decode(string(data), &res.data); err != nil {
			return nil, errors.New("could not decode toml: " + err.Error())
		}

		// just for sanitization, make sure the path is set correctly
		for path, f := range res.data.Files {
			f.Path = path
		}

		log.Debug().Int("commands", len(res.data.Commands)).Int("files", len(res.data.Files)).Msg("mock> loaded data successfully")

		for k := range res.data.Commands {
			log.Trace().Str("cmd", k).Msg("load command")
		}

		for k := range res.data.Files {
			log.Trace().Str("file", k).Msg("load file")
		}
	}

	if cfg.tomlData != nil {
		// merge commands
		maps.Copy(res.data.Commands, cfg.tomlData.Commands)
		// merge files
		maps.Copy(res.data.Files, cfg.tomlData.Files)
	}

	return res, nil
}

func (c *Connection) Type() shared.ConnectionType {
	return "mock"
}

func (c *Connection) Asset() *inventory.Asset {
	return c.asset
}

func (p *Connection) UpdateAsset(asset *inventory.Asset) {
	p.asset = asset
}

func (c *Connection) Capabilities() shared.Capabilities {
	return shared.Capability_File | shared.Capability_RunCommand
}

func hashCmd(message string) string {
	hash := sha256.New()
	hash.Write([]byte(message))
	return hex.EncodeToString(hash.Sum(nil))
}

func (c *Connection) RunCommand(command string) (*shared.Command, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	found, ok := c.data.Commands[command]
	if !ok {
		// try to fetch command by hash (more reliable for whitespace)
		hash := hashCmd(command)
		log.Debug().Str("hash", hash).Str("command", command).Msg("fetching command by hash")
		found, ok = c.data.Commands[hash]
	}
	if !ok {
		c.missing["command"][command] = true
		return &shared.Command{
			Command:    command,
			Stdout:     bytes.NewBuffer([]byte{}),
			Stderr:     bytes.NewBufferString("command not found: " + command),
			ExitStatus: 1,
		}, nil
	}

	return &shared.Command{
		Command:    command,
		Stdout:     bytes.NewBufferString(found.Stdout),
		Stderr:     bytes.NewBufferString(found.Stderr),
		ExitStatus: found.ExitStatus,
	}, nil
}

func (c *Connection) FileInfo(path string) (shared.FileInfoDetails, error) {
	found, ok := c.data.Files[path]
	if !ok {
		return shared.FileInfoDetails{}, os.ErrNotExist
	}

	stat := found.StatData
	return shared.FileInfoDetails{
		Size: stat.Size,
		Mode: shared.FileModeDetails{
			FileMode: stat.Mode,
		},
		Uid: stat.Uid,
		Gid: stat.Gid,
	}, nil
}

func (c *Connection) FileSystem() afero.Fs {
	return c
}

func (c *Connection) Name() string {
	return "mockfs"
}

func (c *Connection) Create(name string) (afero.File, error) {
	return nil, errors.New("not implemented")
}

func (c *Connection) Mkdir(name string, perm os.FileMode) error {
	return errors.New("not implemented")
}

func (c *Connection) MkdirAll(path string, perm os.FileMode) error {
	return errors.New("not implemented")
}

func (c *Connection) Open(name string) (afero.File, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	data, ok := c.data.Files[name]
	if !ok || data.Enoent {
		return nil, os.ErrNotExist
	}

	return &MockFile{
		data: data,
		fs:   c,
	}, nil
}

func (c *Connection) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	return nil, errors.New("not implemented")
}

func (c *Connection) Remove(name string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.data.Files, name)
	return nil
}

func (c *Connection) RemoveAll(path string) error {
	return errors.New("not implemented")
}

func (c *Connection) Rename(oldname, newname string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if oldname == newname {
		return nil
	}

	f, ok := c.data.Files[oldname]
	if !ok {
		return os.ErrNotExist
	}

	c.data.Files[newname] = f
	return nil
}

func (c *Connection) Stat(name string) (os.FileInfo, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	data, ok := c.data.Files[name]
	if !ok {
		return nil, os.ErrNotExist
	}

	f := &MockFile{
		data: data,
		fs:   c,
	}

	return f.Stat()
}

func (c *Connection) Lstat(name string) (os.FileInfo, error) {
	return c.Stat(name)
}

func (c *Connection) Chmod(name string, mode os.FileMode) error {
	return errors.New("not implemented")
}

func (c *Connection) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return errors.New("not implemented")
}

func (c *Connection) Glob(pattern string) ([]string, error) {
	matches := []string{}

	g, err := glob.Compile(pattern)
	if err != nil {
		return matches, err
	}

	for k := range c.data.Files {
		if g.Match(k) {
			matches = append(matches, k)
		}
	}

	return matches, nil
}

func (c *Connection) Chown(name string, uid, gid int) error {
	return errors.New("not implemented")
}

type ReadAtSeeker interface {
	io.Reader
	io.Seeker
	io.ReaderAt
}

type MockFile struct {
	data       *MockFileData
	dataReader ReadAtSeeker
	fs         *Connection
}

func (mf *MockFile) Name() string {
	return mf.data.Path
}

func (mf *MockFile) Stat() (os.FileInfo, error) {
	if mf.data.Enoent {
		return nil, os.ErrNotExist
	}

	// fallback in case the size information is missing, eg. older mock files
	var size int64
	if mf.data.StatData.Size > 0 {
		size = mf.data.StatData.Size
	} else if mf.data.StatData.Size == 0 && len(mf.data.Data) > 0 {
		size = int64(len(mf.data.Data))
	} else if mf.data.StatData.Size == 0 && len(mf.data.Content) > 0 {
		size = int64(len(mf.data.Content))
	}

	return &shared.FileInfo{
		FName:    filepath.Base(mf.data.Path),
		FSize:    size,
		FModTime: mf.data.StatData.ModTime,
		FMode:    mf.data.StatData.Mode,
		FIsDir:   mf.data.StatData.IsDir,
		Uid:      mf.data.StatData.Uid,
		Gid:      mf.data.StatData.Gid,
	}, nil
}

func (mf *MockFile) reader() ReadAtSeeker {
	// if binary data was provided, we ignore the string data
	if mf.dataReader == nil && len(mf.data.Data) > 0 {
		mf.dataReader = bytes.NewReader(mf.data.Data)
	} else if mf.dataReader == nil {
		mf.dataReader = strings.NewReader(mf.data.Content)
	}
	return mf.dataReader
}

func (mf *MockFile) Read(p []byte) (n int, err error) {
	return mf.reader().Read(p)
}

func (mf *MockFile) ReadAt(p []byte, off int64) (n int, err error) {
	return mf.reader().ReadAt(p, off)
}

func (mf *MockFile) Seek(offset int64, whence int) (int64, error) {
	return mf.reader().Seek(offset, whence)
}

func (mf *MockFile) Sync() error {
	return nil
}

func (mf *MockFile) Truncate(size int64) error {
	return errors.New("not implemented")
}

func (mf *MockFile) Write(p []byte) (n int, err error) {
	return 0, errors.New("not implemented")
}

func (mf *MockFile) WriteAt(p []byte, off int64) (n int, err error) {
	return 0, errors.New("not implemented")
}

func (mf *MockFile) WriteString(s string) (ret int, err error) {
	return 0, errors.New("not implemented")
}

func (mf *MockFile) Exists() bool {
	return !mf.data.Enoent
}

func (f *MockFile) Delete() error {
	return errors.New("not implemented")
}

func (f *MockFile) Readdir(n int) ([]os.FileInfo, error) {
	children := []os.FileInfo{}
	path := f.data.Path
	// searches for direct childs of this file
	for k := range f.fs.data.Files {
		if after, ok := strings.CutPrefix(k, path); ok {
			// check if it is only one layer down
			filename := after

			// path-separator is still included, remove it
			filename = strings.TrimPrefix(filename, "/")
			filename = strings.TrimPrefix(filename, "\\")

			if filename == "" || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
				continue
			}

			// fetch file stats
			fsInfo, err := f.fs.Stat(k)
			if err != nil {
				return nil, errors.New("cannot find file in mock index: " + k)
			}

			children = append(children, fsInfo)
		}
		if n > 0 && len(children) > n {
			return children, nil
		}
	}
	return children, nil
}

func (f *MockFile) Readdirnames(n int) ([]string, error) {
	children := []string{}
	path := f.data.Path
	// searches for direct childs of this file
	for k := range f.fs.data.Files {
		if after, ok := strings.CutPrefix(k, path); ok {
			// check if it is only one layer down
			filename := after

			// path-separator is still included, remove it
			filename = strings.TrimPrefix(filename, "/")
			filename = strings.TrimPrefix(filename, "\\")

			if filename == "" || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
				continue
			}
			children = append(children, filename)
		}
		if n > 0 && len(children) > n {
			return children, nil
		}
	}
	return children, nil
}

func (f *MockFile) Close() error {
	// nothing to do
	return nil
}
