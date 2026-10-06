// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/masterpasswd"
)

const defaultMasterPasswdPath = "/etc/master.passwd"

// initFileArg turns an optional `path` init argument into the resource's
// `file` field.
func initFileArg(runtime *plugin.Runtime, resource string, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	x, ok := args["path"]
	if !ok {
		return args, nil, nil
	}
	path, ok := x.Value.(string)
	if !ok {
		return nil, nil, errors.New("wrong type for 'path' in " + resource + " initialization, it must be a string")
	}
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, nil, err
	}
	args["file"] = llx.ResourceData(f, "file")
	delete(args, "path")
	return args, nil, nil
}

// readSystemFile returns a file's content. A missing file is a NotFound
// error and a file the scan may not read is a Forbidden one, so neither reads
// as an empty file.
func readSystemFile(f *mqlFile, hint string) (string, error) {
	path := f.Path.Data
	exists := f.GetExists()
	if exists.Error != nil {
		return "", classifyReadError(path, exists.Error, hint)
	}
	if !exists.Data {
		return "", llx.NotFound(fmt.Errorf("%s does not exist", path))
	}
	content := f.GetContent()
	if content.Error != nil {
		return "", classifyReadError(path, content.Error, hint)
	}
	return content.Data, nil
}

func classifyReadError(path string, err error, hint string) error {
	if errors.Is(err, fs.ErrPermission) {
		return llx.Forbidden(fmt.Errorf("cannot read %s%s: %w", path, hint, err))
	}
	return fmt.Errorf("cannot read %s: %w", path, err)
}

type mqlMasterpasswdInternal struct {
	invalidLineCount int64
}

func initMasterpasswd(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFileArg(runtime, "masterpasswd", args)
}

func (m *mqlMasterpasswd) id() (string, error) {
	f := m.GetFile()
	if f.Error != nil {
		return "", f.Error
	}
	if f.Data == nil {
		return "", errors.New("no file for masterpasswd")
	}
	return f.Data.Path.Data, nil
}

func (m *mqlMasterpasswd) file() (*mqlFile, error) {
	f, err := CreateResource(m.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(defaultMasterPasswdPath),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (m *mqlMasterpasswd) list(file *mqlFile) ([]any, error) {
	content, err := readSystemFile(file, " (only root may read it, scan as root or with --sudo)")
	if err != nil {
		return nil, err
	}

	path := file.Path.Data
	entries, invalid, err := masterpasswd.Parse(strings.NewReader(content))
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse %s: %w", path, err))
	}
	for _, e := range invalid {
		log.Warn().Str("file", path).Int("line", e.Line).Str("reason", e.Reason).Msg("masterpasswd> skipping a line that cannot be parsed")
	}
	m.invalidLineCount = int64(len(invalid))

	res := make([]any, 0, len(entries))
	for i := range entries {
		e := entries[i]
		change := llx.NilData
		if e.Change != nil {
			change = llx.TimeData(*e.Change)
		}
		expire := llx.NilData
		if e.Expire != nil {
			expire = llx.TimeData(*e.Expire)
		}
		o, err := CreateResource(m.MqlRuntime, "masterpasswd.entry", map[string]*llx.RawData{
			"__id":        llx.StringData(path + ":" + strconv.Itoa(e.Line)),
			"name":        llx.StringData(e.User),
			"password":    llx.StringData(e.Password),
			"hasPassword": llx.BoolData(e.HasPassword()),
			"locked":      llx.BoolData(e.Locked()),
			"uid":         llx.IntData(e.UID),
			"gid":         llx.IntData(e.GID),
			"class":       llx.StringData(e.Class),
			"change":      change,
			"expire":      expire,
			"gecos":       llx.StringData(e.Gecos),
			"home":        llx.StringData(e.Home),
			"shell":       llx.StringData(e.Shell),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (m *mqlMasterpasswd) invalidLines() (int64, error) {
	if list := m.GetList(); list.Error != nil {
		return 0, list.Error
	}
	return m.invalidLineCount, nil
}

func (e *mqlMasterpasswdEntry) user(name string) (*mqlUser, error) {
	raw, err := CreateResource(e.MqlRuntime, "users", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := raw.(*mqlUsers).GetList()
	if list.Error != nil {
		return nil, list.Error
	}
	for i := range list.Data {
		u := list.Data[i].(*mqlUser)
		if u.Name.Data == name {
			return u, nil
		}
	}
	e.User.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (e *mqlMasterpasswdEntry) group(gid int64) (*mqlGroup, error) {
	raw, err := CreateResource(e.MqlRuntime, "groups", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	g, err := raw.(*mqlGroups).findID(gid)
	if err != nil {
		var notFound resources.NotFoundError
		if errors.As(err, &notFound) {
			e.Group.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return g, nil
}

// loginClassName is the class login_getpwclass(3) looks up first for an
// account. FreeBSD and DragonFly use `root` for uid 0 when the class field
// is empty; every BSD uses `default` otherwise.
func loginClassName(class string, uid int64, freebsdLike bool) string {
	if class != "" {
		return class
	}
	if freebsdLike && uid == 0 {
		return "root"
	}
	return "default"
}

// isFreeBSDLike reports whether the asset follows FreeBSD's libutil, where
// an unknown login class falls back to `default` and an empty class on uid 0
// means `root`.
func isFreeBSDLike(runtime *plugin.Runtime) bool {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return false
	}
	pf := conn.Asset().GetPlatform()
	return pf != nil && (pf.Name == "freebsd" || pf.Name == "dragonflybsd")
}

func (e *mqlMasterpasswdEntry) loginClass(class string, uid int64) (*mqlLoginconfClass, error) {
	raw, err := CreateResource(e.MqlRuntime, "loginconf", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	lc := raw.(*mqlLoginconf)
	if list := lc.GetList(); list.Error != nil {
		return nil, list.Error
	}

	freebsdLike := isFreeBSDLike(e.MqlRuntime)
	name := loginClassName(class, uid, freebsdLike)
	if c := lc.lookup(name); c != nil {
		return c, nil
	}
	// login_getclassbyname(3) on FreeBSD and DragonFly falls back to the
	// default class for a class it cannot find (including `root` for uid 0).
	// OpenBSD and NetBSD refuse the login instead.
	if freebsdLike && name != "default" {
		if c := lc.lookup("default"); c != nil {
			return c, nil
		}
	}
	e.LoginClass.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
