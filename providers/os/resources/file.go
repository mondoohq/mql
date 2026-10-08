// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"os"
	"path"
	"sort"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// newFile creates a new file resource
func newFile(runtime *plugin.Runtime, path string) (*mqlFile, error) {
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	file := f.(*mqlFile)
	return file, nil
}

// classifyFsError marks a filesystem refusal (EACCES/EPERM) as forbidden and
// returns any other error unchanged.
func classifyFsError(err error) error {
	if err != nil && errors.Is(err, os.ErrPermission) {
		return llx.Forbidden(err)
	}
	return err
}

// globDir returns the paths of the entries in dir whose names match pattern,
// sorted. A directory that does not exist has no matches. Unlike afero.Glob,
// which drops directory read errors, a directory that exists but cannot be
// listed is an error, so an unreadable directory never reads as an empty one.
// With dirsOnly set, only subdirectories match.
func globDir(fs afero.Fs, dir string, pattern string, dirsOnly bool) ([]string, error) {
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, classifyFsError(err)
	}

	matches := []string{}
	for _, entry := range entries {
		if dirsOnly && !entry.IsDir() {
			continue
		}
		ok, err := path.Match(pattern, entry.Name())
		if err != nil {
			return nil, err
		}
		if ok {
			matches = append(matches, path.Join(dir, entry.Name()))
		}
	}
	sort.Strings(matches)
	return matches, nil
}

func fileContentOrEmpty(file *mqlFile) (string, error) {
	if file == nil {
		return "", nil
	}

	content := file.GetContent()
	if content.Error != nil {
		var notFound resources.NotFoundError
		if errors.As(content.Error, &notFound) {
			return "", nil
		}
		return "", content.Error
	}

	return content.Data, nil
}

func fileRequiredContent(file *mqlFile) (string, error) {
	if file == nil {
		return "", resources.NotFoundError{Resource: "file"}
	}

	exists := file.GetExists()
	if exists.Error != nil {
		return "", exists.Error
	}
	if !exists.Data {
		return "", resources.NotFoundError{Resource: "file", ID: file.Path.Data}
	}

	content := file.GetContent()
	if content.Error != nil {
		return "", content.Error
	}
	if content.IsNull() {
		return "", resources.NotFoundError{Resource: "file", ID: file.Path.Data}
	}

	return content.Data, nil
}

type mqlFileInternal struct {
	statInfo *shared.FileInfoDetails
}

func (s *mqlFile) id() (string, error) {
	return s.Path.Data, nil
}

func (s *mqlFile) content(path string, exists bool) (string, error) {
	if !exists {
		s.Content = plugin.TValue[string]{
			State: plugin.StateIsSet | plugin.StateIsNull,
		}
		return "", nil
	}

	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}
	res, err := afs.ReadFile(path)
	return string(res), err
}

func (s *mqlFile) cacheStatFields(stat shared.FileInfoDetails) error {
	mode := stat.Mode.UnixMode()
	res, err := CreateResource(s.MqlRuntime, "file.permissions", map[string]*llx.RawData{
		"mode":             llx.IntData(int64(uint32(mode) & 0o7777)),
		"user_readable":    llx.BoolData(stat.Mode.UserReadable()),
		"user_writeable":   llx.BoolData(stat.Mode.UserWriteable()),
		"user_executable":  llx.BoolData(stat.Mode.UserExecutable()),
		"group_readable":   llx.BoolData(stat.Mode.GroupReadable()),
		"group_writeable":  llx.BoolData(stat.Mode.GroupWriteable()),
		"group_executable": llx.BoolData(stat.Mode.GroupExecutable()),
		"other_readable":   llx.BoolData(stat.Mode.OtherReadable()),
		"other_writeable":  llx.BoolData(stat.Mode.OtherWriteable()),
		"other_executable": llx.BoolData(stat.Mode.OtherExecutable()),
		"suid":             llx.BoolData(stat.Mode.Suid()),
		"sgid":             llx.BoolData(stat.Mode.Sgid()),
		"sticky":           llx.BoolData(stat.Mode.Sticky()),
		"isDirectory":      llx.BoolData(stat.Mode.IsDir()),
		"isFile":           llx.BoolData(stat.Mode.IsRegular()),
		"isSymlink":        llx.BoolData(stat.Mode.FileMode&os.ModeSymlink != 0),
	})
	if err != nil {
		return err
	}

	s.Exists = plugin.TValue[bool]{
		Data:  true,
		State: plugin.StateIsSet,
	}
	s.Permissions = plugin.TValue[*mqlFilePermissions]{
		Data:  res.(*mqlFilePermissions),
		State: plugin.StateIsSet,
	}
	s.Size = plugin.TValue[int64]{
		Data:  stat.Size,
		State: plugin.StateIsSet,
	}

	statCopy := stat
	s.statInfo = &statCopy

	return nil
}

func (s *mqlFile) loadStatFields(path string) (*shared.FileInfoDetails, bool, error) {
	if s.Exists.IsSet() {
		if !s.Exists.Data {
			return nil, false, s.Exists.Error
		}
		if s.statInfo != nil {
			return s.statInfo, true, nil
		}
		if s.Permissions.IsSet() && s.Size.IsSet() {
			return nil, true, nil
		}
	}

	conn := s.MqlRuntime.Connection.(shared.Connection)
	stat, err := conn.FileInfo(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.Exists = plugin.TValue[bool]{
				Data:  false,
				State: plugin.StateIsSet,
			}
			return nil, false, nil
		}
		return nil, false, err
	}
	if err := s.cacheStatFields(stat); err != nil {
		return nil, false, err
	}

	return s.statInfo, true, nil
}

func (s *mqlFile) cacheOwnership(stat shared.FileInfoDetails) error {
	raw, err := CreateResource(s.MqlRuntime, "users", nil)
	if err != nil {
		return errors.New("cannot get users info for file: " + err.Error())
	}
	users := raw.(*mqlUsers)

	user, err := users.findID(stat.Uid)
	if err != nil {
		// A file owned by a uid with no passwd entry (a deleted user, or a
		// minimal container image) resolves the owner to null and fails
		// cleanly, rather than erroring the whole check. Other errors (e.g. the
		// users list could not be loaded) still propagate.
		var notFound resources.NotFoundError
		if !errors.As(err, &notFound) {
			return err
		}
		s.User = plugin.TValue[*mqlUser]{
			State: plugin.StateIsSet | plugin.StateIsNull,
		}
	} else {
		s.User = plugin.TValue[*mqlUser]{
			Data:  user,
			State: plugin.StateIsSet,
		}
	}

	raw, err = CreateResource(s.MqlRuntime, "groups", nil)
	if err != nil {
		return errors.New("cannot get groups info for file: " + err.Error())
	}
	groups := raw.(*mqlGroups)

	group, err := groups.findID(stat.Gid)
	if err != nil {
		// See the user lookup above: an unknown gid resolves to a null group
		// rather than erroring the whole check.
		var notFound resources.NotFoundError
		if !errors.As(err, &notFound) {
			return err
		}
		s.Group = plugin.TValue[*mqlGroup]{
			State: plugin.StateIsSet | plugin.StateIsNull,
		}
	} else {
		s.Group = plugin.TValue[*mqlGroup]{
			Data:  group,
			State: plugin.StateIsSet,
		}
	}

	return nil
}

func (s *mqlFile) loadOwnership(path string) error {
	stat, exists, err := s.loadStatFields(path)
	if err != nil {
		return err
	}
	if !exists {
		s.User = plugin.TValue[*mqlUser]{
			State: plugin.StateIsSet | plugin.StateIsNull,
		}
		s.Group = plugin.TValue[*mqlGroup]{
			State: plugin.StateIsSet | plugin.StateIsNull,
		}
		return nil
	}
	if s.User.IsSet() && s.Group.IsSet() {
		return nil
	}
	if stat == nil {
		conn := s.MqlRuntime.Connection.(shared.Connection)
		statValue, err := conn.FileInfo(path)
		if err != nil {
			return err
		}
		stat = &statValue
	}

	return s.cacheOwnership(*stat)
}

func (s *mqlFile) size(path string) (int64, error) {
	_, exists, err := s.loadStatFields(path)
	if err != nil {
		return 0, err
	}
	if !exists {
		s.Size = plugin.TValue[int64]{
			State: plugin.StateIsSet | plugin.StateIsNull,
		}
		return 0, nil
	}
	return 0, nil
}

func (s *mqlFile) permissions(path string) (*mqlFilePermissions, error) {
	_, exists, err := s.loadStatFields(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		s.Permissions = plugin.TValue[*mqlFilePermissions]{
			State: plugin.StateIsSet | plugin.StateIsNull,
		}
		return nil, nil
	}
	return nil, nil
}

func (s *mqlFile) user() (*mqlUser, error) {
	return nil, s.loadOwnership(s.Path.Data)
}

func (s *mqlFile) group() (*mqlGroup, error) {
	return nil, s.loadOwnership(s.Path.Data)
}

func (s *mqlFile) empty(path string) (bool, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}
	return afs.IsEmpty(path)
}

func (s *mqlFile) basename(fullPath string) (string, error) {
	return path.Base(fullPath), nil
}

func (s *mqlFile) dirname(fullPath string) (string, error) {
	return path.Dir(fullPath), nil
}

func (s *mqlFile) exists(path string) (bool, error) {
	_, exists, err := s.loadStatFields(path)
	return exists, err
}

func (l *mqlFilePermissions) id() (string, error) {
	res := []byte("----------")

	if l.IsSymlink.Data {
		res[0] = 'l'
	} else if l.IsDirectory.Data {
		res[0] = 'd'
	}

	if l.User_readable.Data {
		res[1] = 'r'
	}
	if l.User_writeable.Data {
		res[2] = 'w'
	}
	if l.User_executable.Data {
		res[3] = 'x'
		if l.Suid.Data {
			res[3] = 's'
		}
	} else {
		if l.Suid.Data {
			res[3] = 'S'
		}
	}

	if l.Group_readable.Data {
		res[4] = 'r'
	}
	if l.Group_writeable.Data {
		res[5] = 'w'
	}
	if l.Group_executable.Data {
		res[6] = 'x'
		if l.Sgid.Data {
			res[6] = 's'
		}
	} else {
		if l.Sgid.Data {
			res[6] = 'S'
		}
	}

	if l.Other_readable.Data {
		res[7] = 'r'
	}
	if l.Other_writeable.Data {
		res[8] = 'w'
	}
	if l.Other_executable.Data {
		res[9] = 'x'
		if l.Sticky.Data {
			res[9] = 't'
		}
	} else {
		if l.Sticky.Data {
			res[9] = 'T'
		}
	}

	return string(res), nil
}

func (l *mqlFilePermissions) string() (string, error) {
	return l.__id, nil
}

func (r *mqlFileContext) id() (string, error) {
	if r.File.Data == nil {
		return "", errors.New("need file to exist for file.context ID")
	}

	fileID, err := r.File.Data.id()
	if err != nil {
		return "", err
	}

	rng := r.Range.Data.String()
	return fileID + ":" + rng, nil
}

func (r *mqlFileContext) content(file *mqlFile, rnge llx.Range) (string, error) {
	if file == nil {
		return "", errors.New("no file information for file.context")
	}

	fileContent := file.GetContent()
	if fileContent.Error != nil {
		return "", fileContent.Error
	}

	return rnge.ExtractString(fileContent.Data, llx.DefaultExtractConfig), nil
}

// maxSmallFileSize is the most readSmallRegularFile reads. The files it is
// for (a seccomp profile, a container's config.json) are a few KB.
const maxSmallFileSize = 4 << 20

// readSmallRegularFile reads a file whose path comes from a container's or an
// engine's settings rather than from the provider: only an absolute path to a
// regular file of at most maxSize bytes, after following links, so a path to
// a device, FIFO, socket or huge file cannot hang the scan or exhaust its
// memory. False when the file is missing, refused, or cannot be read.
func readSmallRegularFile(runtime *plugin.Runtime, p string, maxSize int64) (string, bool) {
	if !path.IsAbs(p) {
		return "", false
	}
	p = path.Clean(p)
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return "", false
	}
	fs := conn.FileSystem()
	fi, err := fs.Stat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxSize {
		return "", false
	}
	f, err := fs.Open(p)
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil || int64(len(b)) > maxSize {
		return "", false
	}
	return string(b), true
}
