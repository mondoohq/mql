// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/dconf"
	"go.mondoo.com/mql/types"
)

func dconfFs(runtime *plugin.Runtime) (afero.Fs, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("dconf requires a connection with a file system")
	}
	return conn.FileSystem(), nil
}

func (s *mqlDconf) id() (string, error) {
	return "dconf", nil
}

func (s *mqlDconf) profiles() ([]any, error) {
	fs, err := dconfFs(s.MqlRuntime)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var names []string
	for _, dir := range dconf.ProfileDirs {
		files, err := dconfDirFiles(fs, dir)
		if err != nil {
			return nil, err
		}
		for _, name := range files {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)

	res := make([]any, 0, len(names))
	for _, name := range names {
		p, err := NewResource(s.MqlRuntime, "dconf.profile", map[string]*llx.RawData{"name": llx.StringData(name)})
		if err != nil {
			return nil, err
		}
		res = append(res, p)
	}
	return res, nil
}

func (s *mqlDconf) databases() ([]any, error) {
	fs, err := dconfFs(s.MqlRuntime)
	if err != nil {
		return nil, err
	}
	entries, err := afero.ReadDir(fs, dconf.SystemDbDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list %s: %w", dconf.SystemDbDir, err)
	}
	seen := map[string]bool{}
	var names []string
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".d")
		if name == "" || strings.HasPrefix(e.Name(), ".") || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)

	res := make([]any, 0, len(names))
	for _, name := range names {
		db, err := newDconfDatabase(s.MqlRuntime, fs, dconf.Source{Type: dconf.SourceSystem, Name: name})
		if err != nil {
			return nil, err
		}
		res = append(res, db)
	}
	return res, nil
}

// dconfDirFiles lists the names of the regular files in dir, following
// symbolic links, skipping names that start with a dot. A missing directory
// has none.
func dconfDirFiles(fs afero.Fs, dir string) ([]string, error) {
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list %s: %w", dir, err)
	}
	var res []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		st, err := fs.Stat(path.Join(dir, e.Name()))
		if err != nil || !isRegularTarget(st) {
			continue
		}
		res = append(res, e.Name())
	}
	sort.Strings(res)
	return res, nil
}

func initDconfProfile(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	raw, ok := args["name"]
	if !ok {
		return nil, nil, errors.New("dconf.profile requires a name")
	}
	name, ok := raw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New("dconf.profile requires a name")
	}
	fs, err := dconfFs(runtime)
	if err != nil {
		return nil, nil, err
	}

	// A profile name is looked up in each profile directory; dconf opens a
	// name starting with a slash as a path.
	candidates := []string{name}
	if !strings.HasPrefix(name, "/") {
		candidates = nil
		for _, dir := range dconf.ProfileDirs {
			candidates = append(candidates, path.Join(dir, name))
		}
	}
	profilePath := ""
	for _, c := range candidates {
		st, err := fs.Stat(c)
		if err == nil && isRegularTarget(st) {
			profilePath = c
			break
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("failed to read %s: %w", c, err)
		}
	}

	var sources []dconf.Source
	fileArg := llx.NilData
	switch {
	case profilePath != "":
		content, err := afero.ReadFile(fs, profilePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read %s: %w", profilePath, err)
		}
		if sources, err = dconf.ParseProfile(bytes.NewReader(content)); err != nil {
			return nil, nil, fmt.Errorf("failed to parse %s: %w", profilePath, err)
		}
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{"path": llx.StringData(profilePath)})
		if err != nil {
			return nil, nil, err
		}
		fileArg = llx.ResourceData(f, "file")
	case name == dconf.UserProfile:
		// without a user profile, dconf uses a single user database
		sources = dconf.DefaultSources
	}

	dbs := make([]any, 0, len(sources))
	contents := make([]*dconf.Database, 0, len(sources))
	for _, src := range sources {
		db, err := newDconfDatabase(runtime, fs, src)
		if err != nil {
			return nil, nil, err
		}
		dbs = append(dbs, db)
		contents = append(contents, db.compiled)
	}
	values, locks := dconf.Resolve(contents)

	return map[string]*llx.RawData{
		"__id":      llx.StringData("dconf.profile/" + name),
		"name":      llx.StringData(name),
		"file":      fileArg,
		"databases": llx.ArrayData(dbs, types.Resource("dconf.database")),
		"settings":  llx.MapData(values, types.Dict),
		"locks":     llx.ArrayData(llx.TArr2Raw(locks), types.String),
	}, nil, nil
}

type mqlDconfDatabaseInternal struct {
	// compiled is what the compiled database holds, nil for a user or service
	// database or one dconf cannot read
	compiled *dconf.Database
}

func (s *mqlDconfDatabase) id() (string, error) {
	return "dconf.database/" + s.Type.Data + "/" + s.Name.Data, nil
}

// newDconfDatabase reads one database of a profile: the compiled database
// and, for a system database, its keyfile directory.
func newDconfDatabase(runtime *plugin.Runtime, fs afero.Fs, src dconf.Source) (*mqlDconfDatabase, error) {
	id := "dconf.database/" + src.Type + "/" + src.Name
	if cached, ok := runtime.Resources.Get("dconf.database\x00" + id); ok {
		return cached.(*mqlDconfDatabase), nil
	}

	dbPath := src.Path()
	args := map[string]*llx.RawData{
		"__id":            llx.StringData(id),
		"type":            llx.StringData(src.Type),
		"name":            llx.StringData(src.Name),
		"path":            llx.StringData(dbPath),
		"exists":          llx.BoolData(false),
		"settings":        llx.MapData(map[string]any{}, types.Dict),
		"locks":           llx.ArrayData([]any{}, types.String),
		"keyfiles":        llx.ArrayData([]any{}, types.Resource("file")),
		"keyfileSettings": llx.MapData(map[string]any{}, types.Dict),
		"keyfileLocks":    llx.ArrayData([]any{}, types.String),
		"upToDate":        llx.NilData,
	}

	var compiled *dconf.Database
	if dbPath != "" {
		data, err := afero.ReadFile(fs, dbPath)
		switch {
		case err == nil:
			db, err := dconf.ReadDatabase(data)
			if err != nil && !errors.Is(err, dconf.ErrNotDatabase) {
				return nil, fmt.Errorf("failed to read dconf database %s: %w", dbPath, err)
			}
			if err == nil {
				compiled = db
				sort.Strings(compiled.Locks)
				args["exists"] = llx.BoolData(true)
				args["settings"] = llx.MapData(db.Values, types.Dict)
				args["locks"] = llx.ArrayData(llx.TArr2Raw(db.Locks), types.String)
			}
		case errors.Is(err, os.ErrNotExist):
		default:
			// a directory or an unreadable file: dconf cannot open it either
			if st, serr := fs.Stat(dbPath); serr != nil || !st.IsDir() {
				return nil, fmt.Errorf("failed to read dconf database %s: %w", dbPath, err)
			}
		}
	}

	if src.Type == dconf.SourceSystem {
		if err := dconfKeyfileArgs(runtime, fs, dbPath+".d", compiled, args); err != nil {
			return nil, err
		}
	}

	res, err := CreateResource(runtime, "dconf.database", args)
	if err != nil {
		return nil, err
	}
	db := res.(*mqlDconfDatabase)
	db.compiled = compiled
	return db, nil
}

// dconfKeyfileArgs reads the keyfile directory of a system database and
// compares it with the compiled database.
func dconfKeyfileArgs(runtime *plugin.Runtime, fs afero.Fs, dir string, compiled *dconf.Database, args map[string]*llx.RawData) error {
	st, err := fs.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", dir, err)
	}
	if !st.IsDir() {
		return nil
	}

	names, err := dconfDirFiles(fs, dir)
	if err != nil {
		return err
	}
	files := make([]any, 0, len(names))
	keyfiles := make([]dconf.Keyfile, 0, len(names))
	var parseErr error
	for _, name := range names {
		p := path.Join(dir, name)
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
		if err != nil {
			return err
		}
		files = append(files, f)
		content, err := afero.ReadFile(fs, p)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", p, err)
		}
		entries, err := dconf.ParseKeyfile(p, bytes.NewReader(content))
		if err != nil && parseErr == nil {
			parseErr = err
		}
		keyfiles = append(keyfiles, dconf.Keyfile{Name: name, Entries: entries})
	}
	args["keyfiles"] = llx.ArrayData(files, types.Resource("file"))

	locksDir := path.Join(dir, "locks")
	lockNames, err := dconfDirFiles(fs, locksDir)
	if err != nil {
		return err
	}
	var locks []string
	for _, name := range lockNames {
		p := path.Join(locksDir, name)
		content, err := afero.ReadFile(fs, p)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", p, err)
		}
		l, _ := dconf.ParseLocks(bytes.NewReader(content))
		locks = append(locks, l...)
	}

	var source *dconf.Database
	if parseErr == nil {
		source, _, parseErr = dconf.Compile(keyfiles, locks)
	}
	if parseErr != nil {
		args["keyfileSettings"] = &llx.RawData{Type: types.Map(types.String, types.Dict), Error: parseErr}
		sort.Strings(locks)
		args["keyfileLocks"] = llx.ArrayData(llx.TArr2Raw(locks), types.String)
		args["upToDate"] = llx.BoolData(false)
		return nil
	}

	args["keyfileSettings"] = llx.MapData(source.Values, types.Dict)
	args["keyfileLocks"] = llx.ArrayData(llx.TArr2Raw(source.Locks), types.String)
	upToDate := compiled != nil &&
		reflect.DeepEqual(compiled.Values, source.Values) &&
		slices.Equal(compiled.Locks, source.Locks)
	args["upToDate"] = llx.BoolData(upToDate)
	return nil
}
