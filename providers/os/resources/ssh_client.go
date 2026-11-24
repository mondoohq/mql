// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	pathpkg "path"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/sshclient"
	"go.mondoo.com/mql/types"
)

const (
	defaultSshClientConfig        = "/etc/ssh/ssh_config"
	windowsDefaultSshClientConfig = windowsSshdDir + `\ssh_config`
	defaultSshKnownHosts          = "/etc/ssh/ssh_known_hosts"
	windowsDefaultSshKnownHosts   = windowsSshdDir + `\ssh_known_hosts`
)

// initSshPathArg turns an optional `path` argument into the `file` the
// resource reads.
func initSshPathArg(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path', it must be a string")
		}
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")
		delete(args, "path")
	}
	return args, nil, nil
}

func sshDefaultFile(runtime *plugin.Runtime, unixPath, windowsPath string) (*mqlFile, error) {
	path := unixPath
	if conn, ok := runtime.Connection.(shared.Connection); ok && conn.Asset() != nil && conn.Asset().Platform != nil &&
		conn.Asset().Platform.IsFamily(inventory.FAMILY_WINDOWS) {
		path = windowsPath
	}
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// fileContext is the file.context of a line range in a file.
func fileContext(runtime *plugin.Runtime, path string, r llx.Range) (plugin.Resource, error) {
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return CreateResource(runtime, "file.context", map[string]*llx.RawData{
		"file":  llx.ResourceData(f, "file"),
		"range": llx.RangeData(r),
	})
}

type mqlSshConfigInternal struct {
	lock sync.Mutex
}

func initSshConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initSshPathArg(runtime, args)
}

func (s *mqlSshConfig) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	return "ssh.config/" + file.Data.Path.Data, nil
}

func (s *mqlSshConfig) file() (*mqlFile, error) {
	return sshDefaultFile(s.MqlRuntime, defaultSshClientConfig, windowsDefaultSshClientConfig)
}

// sshHomeOf returns the home directory a user's ~/.ssh/config lives in, so an
// Include of ~/... resolves; empty for any other configuration.
func sshHomeOf(path string) string {
	dir := pathpkg.Dir(path)
	if pathpkg.Base(dir) == ".ssh" {
		return pathpkg.Dir(dir)
	}
	return ""
}

func (s *mqlSshConfig) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if file == nil {
		return errors.New("no ssh client config file to read")
	}

	files := map[string]*mqlFile{file.Path.Data: file}
	content := func(path string) (string, error) {
		f, ok := files[path]
		if !ok {
			raw, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return "", err
			}
			f = raw.(*mqlFile)
			files[path] = f
		}
		c, err := fileRequiredContent(f)
		if err != nil {
			return "", sshdIncludeReadError(path, err)
		}
		return c, nil
	}
	glob := func(pattern string) ([]string, error) {
		conn, ok := s.MqlRuntime.Connection.(shared.Connection)
		if !ok {
			return []string{pattern}, nil
		}
		paths, err := expandSshdGlob(&afero.Afero{Fs: conn.FileSystem()}, pattern)
		if err != nil {
			return nil, sshdIncludeReadError(pattern, err)
		}
		return paths, nil
	}

	cfg, err := sshclient.Parse(file.Path.Data, sshHomeOf(file.Path.Data), content, glob)
	if err != nil {
		s.Files = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Params = plugin.TValue[map[string]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Blocks = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Hosts = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		return err
	}

	fileList := make([]any, 0, len(cfg.Files))
	for _, p := range cfg.Files {
		if f, ok := files[p]; ok {
			fileList = append(fileList, f)
		}
	}

	blocks := []any{}
	for _, b := range cfg.Blocks {
		if b.Kind == "" {
			continue
		}
		ctx, err := fileContext(s.MqlRuntime, b.Path, b.Range)
		if err != nil {
			return err
		}
		patterns := make([]any, len(b.Patterns))
		for i, p := range b.Patterns {
			patterns[i] = p
		}
		// File and line: the same Host can be declared more than once, and
		// each declaration is a separate block.
		obj, err := CreateResource(s.MqlRuntime, "ssh.config.block", map[string]*llx.RawData{
			"__id":     llx.StringData(s.__id + "/" + b.Path + ":" + strconv.Itoa(b.Line)),
			"kind":     llx.StringData(b.Kind),
			"criteria": llx.StringData(b.Criteria),
			"patterns": llx.ArrayData(patterns, types.String),
			"params":   llx.MapData(stringMap(b.Params), types.String),
			"context":  llx.ResourceData(ctx, "file.context"),
		})
		if err != nil {
			return err
		}
		blocks = append(blocks, obj)
	}

	hosts := []any{}
	for _, h := range cfg.LiteralHosts() {
		hosts = append(hosts, h)
	}

	s.Files = plugin.TValue[[]any]{Data: fileList, State: plugin.StateIsSet}
	s.Params = plugin.TValue[map[string]any]{Data: stringMap(cfg.Global()), State: plugin.StateIsSet}
	s.Blocks = plugin.TValue[[]any]{Data: blocks, State: plugin.StateIsSet}
	s.Hosts = plugin.TValue[[]any]{Data: hosts, State: plugin.StateIsSet}
	return nil
}

func (s *mqlSshConfig) files(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSshConfig) params(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSshConfig) blocks(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSshConfig) hosts(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

type mqlSshKnownHostsInternal struct {
	lock sync.Mutex
}

func initSshKnownHosts(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initSshPathArg(runtime, args)
}

func (s *mqlSshKnownHosts) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	return "ssh.knownHosts/" + file.Data.Path.Data, nil
}

func (s *mqlSshKnownHosts) file() (*mqlFile, error) {
	return sshDefaultFile(s.MqlRuntime, defaultSshKnownHosts, windowsDefaultSshKnownHosts)
}

func (s *mqlSshKnownHosts) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if file == nil {
		return errors.New("no known_hosts file to read")
	}
	content, err := fileRequiredContent(file)
	if err != nil {
		s.Entries = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.UnreadableLines = plugin.TValue[int64]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		return err
	}
	res := sshclient.ParseKnownHosts(content)
	path := file.Path.Data

	entries := make([]any, 0, len(res.Entries))
	for _, e := range res.Entries {
		ctx, err := fileContext(s.MqlRuntime, path, llx.NewRange().AddLineRange(uint32(e.Line), uint32(e.Line)))
		if err != nil {
			return err
		}
		hosts := make([]any, len(e.Hosts))
		for i, h := range e.Hosts {
			hosts[i] = h
		}
		// The line: the same host and key may legitimately appear twice.
		obj, err := CreateResource(s.MqlRuntime, "ssh.knownHosts.entry", map[string]*llx.RawData{
			"__id":    llx.StringData(s.__id + ":" + strconv.Itoa(e.Line)),
			"hosts":   llx.ArrayData(hosts, types.String),
			"hashed":  llx.BoolData(e.Hashed),
			"marker":  llx.StringData(e.Marker),
			"keyType": llx.StringData(e.KeyType),
			"key":     llx.StringData(e.Key),
			"comment": llx.StringData(strings.TrimSpace(e.Comment)),
			"context": llx.ResourceData(ctx, "file.context"),
		})
		if err != nil {
			return err
		}
		entries = append(entries, obj)
	}
	s.Entries = plugin.TValue[[]any]{Data: entries, State: plugin.StateIsSet}
	s.UnreadableLines = plugin.TValue[int64]{Data: int64(res.Unreadable), State: plugin.StateIsSet}
	return nil
}

func (s *mqlSshKnownHosts) entries(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSshKnownHosts) unreadableLines(file *mqlFile) (int64, error) {
	return 0, s.parse(file)
}

// The context is always set when a block or entry is created.
func (s *mqlSshConfigBlock) context() (*mqlFileContext, error) {
	return nil, errors.New("context of an ssh config block is set when it is read")
}

func (s *mqlSshKnownHostsEntry) context() (*mqlFileContext, error) {
	return nil, errors.New("context of a known_hosts entry is set when it is read")
}
