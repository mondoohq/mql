// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path"

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
		"__id":             llx.StringData(s.Path.Data),
		"string":           llx.StringData(lsModeString(stat.Mode.FileMode, mode)),
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

// id is the fallback for a file.permissions created without an explicit
// __id. A file's permissions are keyed by the file's path (see
// cacheStatFields), because two files with the same mode must not share one
// cached instance.
func (l *mqlFilePermissions) id() (string, error) {
	return l.lsString(), nil
}

func (l *mqlFilePermissions) string() (string, error) {
	return l.lsString(), nil
}

// lsString renders the permission booleans in ls -l form. It only knows the
// file types that have a field (directory, symlink); permissions created from
// a stat carry the full string, including the type character.
func (l *mqlFilePermissions) lsString() string {
	var typ os.FileMode
	if l.IsSymlink.Data {
		typ = os.ModeSymlink
	} else if l.IsDirectory.Data {
		typ = os.ModeDir
	}

	var bits uint32
	for _, b := range []struct {
		set bool
		bit uint32
	}{
		{l.User_readable.Data, 0o400}, {l.User_writeable.Data, 0o200}, {l.User_executable.Data, 0o100},
		{l.Group_readable.Data, 0o040}, {l.Group_writeable.Data, 0o020}, {l.Group_executable.Data, 0o010},
		{l.Other_readable.Data, 0o004}, {l.Other_writeable.Data, 0o002}, {l.Other_executable.Data, 0o001},
		{l.Suid.Data, 0o4000}, {l.Sgid.Data, 0o2000}, {l.Sticky.Data, 0o1000},
	} {
		if b.set {
			bits |= b.bit
		}
	}
	return lsModeString(typ, bits)
}

// lsFileTypeChar returns the file type character that ls -l prints first.
func lsFileTypeChar(m os.FileMode) byte {
	switch {
	case m&os.ModeSymlink != 0:
		return 'l'
	case m.IsDir():
		return 'd'
	case m&os.ModeNamedPipe != 0:
		return 'p'
	case m&os.ModeSocket != 0:
		return 's'
	case m&os.ModeCharDevice != 0:
		return 'c'
	case m&os.ModeDevice != 0:
		return 'b'
	}
	return '-'
}

// lsModeString renders a file type and the Unix permission bits (including
// setuid, setgid and sticky, as in 0o7777) the way ls -l prints them.
func lsModeString(typ os.FileMode, bits uint32) string {
	res := []byte("----------")
	res[0] = lsFileTypeChar(typ)

	rwx := func(i int, r, w, x, special uint32, set, unset byte) {
		if bits&r != 0 {
			res[i] = 'r'
		}
		if bits&w != 0 {
			res[i+1] = 'w'
		}
		switch {
		case bits&x != 0 && bits&special != 0:
			res[i+2] = set
		case bits&x != 0:
			res[i+2] = 'x'
		case bits&special != 0:
			res[i+2] = unset
		}
	}
	rwx(1, 0o400, 0o200, 0o100, 0o4000, 's', 'S')
	rwx(4, 0o040, 0o020, 0o010, 0o2000, 's', 'S')
	rwx(7, 0o004, 0o002, 0o001, 0o1000, 't', 'T')

	return string(res)
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
