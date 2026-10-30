// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/logindefs"
	"go.mondoo.com/mql/providers/os/resources/umask"
	"go.mondoo.com/mql/types"
)

// sources of a umask setting, the values of umask.setting.source
const (
	umaskSourceLoginDefs    = "login.defs"
	umaskSourceDefaultLogin = "default-login"
	umaskSourcePam          = "pam"
	umaskSourceShell        = "shell"
	umaskSourceUser         = "user"
)

const (
	// defaultLoginFile is the file pam_umask reads UMASK from when login.defs
	// does not set it
	defaultLoginFile = "/etc/default/login"
	// profileDropInDir holds the *.sh files /etc/profile sources
	profileDropInDir = "/etc/profile.d"
	// vendorProfileDropInDir is SUSE's packaged /etc/profile.d
	vendorProfileDropInDir = "/usr/etc/profile.d"
)

// umaskUserFiles are the startup files in a user's home directory that the
// shell reads, as the CIS benchmarks list them for the root user.
var umaskUserFiles = []string{".bash_profile", ".bash_login", ".profile", ".bashrc"}

type mqlUmaskInternal struct {
	lock           sync.Mutex
	loaded         bool
	loadErr        error
	cachedSources  []umaskSourceFile
	cachedSettings []*mqlUmaskSetting
	// pamSettings are the settings of pam_umask umask= arguments, keyed by
	// service and line number
	pamSettings map[string]*mqlUmaskSetting
}

// umaskSourceFile is a file that may set the umask.
type umaskSourceFile struct {
	path   string
	source string
}

func initUmask(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if raw, ok := args["user"]; ok {
		if _, ok := raw.Value.(string); !ok {
			return nil, nil, errors.New("wrong type for 'user' in umask initialization, it must be a string")
		}
	} else {
		args["user"] = llx.StringData("")
	}
	return args, nil, nil
}

func (u *mqlUmask) id() (string, error) {
	if u.User.Data == "" {
		return "umask", nil
	}
	return "umask/" + u.User.Data, nil
}

func (u *mqlUmask) files() ([]any, error) {
	if err := u.load(); err != nil {
		return nil, err
	}
	res := make([]any, 0, len(u.cachedSources))
	for _, src := range u.cachedSources {
		f, err := CreateResource(u.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(src.path)})
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}
	return res, nil
}

func (u *mqlUmask) settings(files []any) ([]any, error) {
	if err := u.load(); err != nil {
		return nil, err
	}
	res := make([]any, 0, len(u.cachedSettings))
	for _, s := range u.cachedSettings {
		res = append(res, s)
	}
	return res, nil
}

func (u *mqlUmask) loginDefs(settings []any) (*mqlUmaskSetting, error) {
	if s := u.lastSetting(umaskSourceLoginDefs); s != nil {
		return s, nil
	}
	u.LoginDefs.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// lastSetting returns the last setting from source, the one the tools that
// read that source apply.
func (u *mqlUmask) lastSetting(source string) *mqlUmaskSetting {
	if err := u.load(); err != nil {
		return nil
	}
	for _, v := range slices.Backward(u.cachedSettings) {
		if v.Source.Data == source {
			return v
		}
	}
	return nil
}

func (u *mqlUmask) pam() ([]any, error) {
	if err := u.load(); err != nil {
		return nil, err
	}
	entries, err := umaskPamEntries(u.MqlRuntime)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, entry := range entries {
		args := make([]string, 0, len(entry.Options.Data))
		for _, o := range entry.Options.Data {
			if str, ok := o.(string); ok {
				args = append(args, str)
			}
		}
		_, usergroups := umaskPamOptions(args)

		// the umask= argument, else UMASK of login.defs, else UMASK of
		// /etc/default/login, as pam_umask looks them up
		setting := u.pamSettings[umaskPamKey(entry.Service.Data, entry.LineNumber.Data)]
		if setting == nil {
			setting = u.lastSetting(umaskSourceLoginDefs)
		}
		if setting == nil {
			setting = u.lastSetting(umaskSourceDefaultLogin)
		}
		settingData := llx.NilData
		if setting != nil {
			settingData = llx.ResourceData(setting, "umask.setting")
		}

		mod, err := CreateResource(u.MqlRuntime, "umask.pamModule", map[string]*llx.RawData{
			"__id":       llx.StringData("umask.pamModule/" + umaskPamKey(entry.Service.Data, entry.LineNumber.Data)),
			"service":    llx.StringData(entry.Service.Data),
			"lineNumber": llx.IntData(entry.LineNumber.Data),
			"control":    llx.StringData(entry.Control.Data),
			"arguments":  llx.ArrayData(llx.TArr2Raw(args), types.String),
			"setting":    settingData,
			"usergroups": llx.BoolData(usergroups),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mod)
	}
	return res, nil
}

func umaskPamKey(service string, line int64) string {
	return service + "/" + strconv.FormatInt(line, 10)
}

// umaskPamOptions reads the umask= argument and the usergroups switch of a
// pam_umask line. A later argument replaces an earlier one, as pam_umask
// parses them in order.
func umaskPamOptions(args []string) (value string, usergroups bool) {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "umask="); ok {
			value = v
		} else if strings.EqualFold(a, "usergroups") {
			usergroups = true
		} else if strings.EqualFold(a, "nousergroups") {
			usergroups = false
		}
	}
	return value, usergroups
}

// isUmaskModule reports whether a PAM module path names pam_umask, with or
// without a directory.
func isUmaskModule(module string) bool {
	return path.Base(module) == "pam_umask.so"
}

// umaskPamEntries lists the session lines that load pam_umask, sorted by
// service and line.
func umaskPamEntries(runtime *plugin.Runtime) ([]*mqlPamConfServiceEntry, error) {
	obj, err := CreateResource(runtime, "pam.conf", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	exists := obj.(*mqlPamConf).GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}
	if !exists.Data {
		return nil, nil
	}
	entries := obj.(*mqlPamConf).GetEntries()
	if entries.Error != nil {
		return nil, entries.Error
	}

	services := make([]string, 0, len(entries.Data))
	for service := range entries.Data {
		services = append(services, service)
	}
	sort.Strings(services)

	var res []*mqlPamConfServiceEntry
	for _, service := range services {
		list, _ := entries.Data[service].([]any)
		for _, raw := range list {
			entry, ok := raw.(*mqlPamConfServiceEntry)
			if !ok || entry.PamType.Data != "session" || !isUmaskModule(entry.Module.Data) {
				continue
			}
			res = append(res, entry)
		}
	}
	return res, nil
}

// load finds the files that may set the umask and reads their settings once.
func (u *mqlUmask) load() error {
	u.lock.Lock()
	defer u.lock.Unlock()
	if u.loaded {
		return u.loadErr
	}
	u.loaded = true
	u.loadErr = u.read()
	return u.loadErr
}

func (u *mqlUmask) read() error {
	conn, ok := u.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return errors.New("umask requires a connection with a file system")
	}
	fs := conn.FileSystem()

	sources, err := u.findSources(fs)
	if err != nil {
		return err
	}

	var settings []*mqlUmaskSetting
	add := func(src umaskSourceFile, line int, ordinal int, value string, mask umask.Mask, maskErr error, conditional bool) error {
		s, err := newUmaskSetting(u.MqlRuntime, src, line, ordinal, value, mask, maskErr, conditional)
		if err != nil {
			return err
		}
		settings = append(settings, s)
		return nil
	}

	var shell []umaskSourceFile
	for _, src := range sources {
		switch src.source {
		case umaskSourceLoginDefs, umaskSourceDefaultLogin:
			content, err := umaskReadFile(u.MqlRuntime, src.path)
			if err != nil {
				return err
			}
			var values []umask.Assignment
			if src.source == umaskSourceLoginDefs {
				for _, e := range logindefs.Entries(strings.NewReader(content)) {
					if e.Key == "UMASK" {
						values = append(values, umask.Assignment{Line: e.Line, Value: e.Value})
					}
				}
			} else {
				values = umask.ParseKey(strings.NewReader(content), "UMASK")
			}
			for _, v := range values {
				mask, maskErr := umask.ParseOctal(v.Value)
				if err := add(src, v.Line, 0, v.Value, mask, maskErr, false); err != nil {
					return err
				}
			}
		default:
			shell = append(shell, src)
		}
	}

	// pam_umask umask= arguments come after the files pam_umask falls back to
	u.pamSettings = map[string]*mqlUmaskSetting{}
	entries, err := umaskPamEntries(u.MqlRuntime)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		var args []string
		for _, o := range entry.Options.Data {
			if str, ok := o.(string); ok {
				args = append(args, str)
			}
		}
		value, _ := umaskPamOptions(args)
		if value == "" {
			continue
		}
		file := entry.Service.Data
		if !strings.HasPrefix(file, "/") {
			// a service of the single-file /etc/pam.conf
			file = "/etc/pam.conf"
		}
		mask, maskErr := umask.ParseOctal(value)
		src := umaskSourceFile{path: file, source: umaskSourcePam}
		s, err := newUmaskSetting(u.MqlRuntime, src, int(entry.LineNumber.Data)+1, 0, value, mask, maskErr, false)
		if err != nil {
			return err
		}
		settings = append(settings, s)
		u.pamSettings[umaskPamKey(entry.Service.Data, entry.LineNumber.Data)] = s
	}

	for _, src := range shell {
		content, err := umaskReadFile(u.MqlRuntime, src.path)
		if err != nil {
			return err
		}
		ordinals := map[int]int{}
		for _, st := range umask.ParseShell(strings.NewReader(content)) {
			mask, maskErr := umask.Parse(st.Value)
			if err := add(src, st.Line, ordinals[st.Line], st.Value, mask, maskErr, st.Conditional); err != nil {
				return err
			}
			ordinals[st.Line]++
		}
	}

	u.cachedSources = sources
	u.cachedSettings = settings
	return nil
}

// findSources lists the files that may set the umask and exist, in the order
// umask.files documents.
func (u *mqlUmask) findSources(fs afero.Fs) ([]umaskSourceFile, error) {
	var candidates []umaskSourceFile

	// login.defs and the drop-ins the shadow tools read
	obj, err := CreateResource(u.MqlRuntime, "logindefs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	ld := obj.(*mqlLogindefs)
	if f := ld.GetFile(); f.Error != nil {
		return nil, f.Error
	} else if f.Data != nil {
		candidates = append(candidates, umaskSourceFile{path: f.Data.Path.Data, source: umaskSourceLoginDefs})
	}
	dropIns, err := ld.dropIns()
	if err != nil {
		return nil, err
	}
	for _, p := range dropIns {
		candidates = append(candidates, umaskSourceFile{path: p, source: umaskSourceLoginDefs})
	}

	candidates = append(candidates, umaskSourceFile{path: defaultLoginFile, source: umaskSourceDefaultLogin})

	shell := func(p string) {
		candidates = append(candidates, umaskSourceFile{path: p, source: umaskSourceShell})
	}
	shell(resolveVendorConfigPath(fs, "/etc/profile"))
	shell("/etc/profile.local")
	profileD, err := umaskProfileDropIns(fs)
	if err != nil {
		return nil, err
	}
	for _, p := range profileD {
		shell(p)
	}
	shell("/etc/profile.d/sh.local")
	shell("/etc/bashrc")
	shell(resolveVendorConfigPath(fs, "/etc/bash.bashrc"))
	shell("/etc/bash.bashrc.local")

	if name := u.User.Data; name != "" {
		home, err := umaskUserHome(u.MqlRuntime, name)
		if err != nil {
			return nil, err
		}
		if home != "" {
			for _, f := range umaskUserFiles {
				candidates = append(candidates, umaskSourceFile{path: path.Join(home, f), source: umaskSourceUser})
			}
		}
	}

	var res []umaskSourceFile
	seen := map[string]bool{}
	for _, c := range candidates {
		if seen[c.path] {
			continue
		}
		seen[c.path] = true
		ok, err := umaskFileExists(fs, c.path)
		if err != nil {
			return nil, err
		}
		if ok {
			res = append(res, c)
		}
	}
	return res, nil
}

// umaskProfileDropIns lists the *.sh files /etc/profile sources: SUSE's
// /usr/etc/profile.d files that /etc/profile.d does not shadow, then those of
// /etc/profile.d, each directory sorted by name as the shell expands the glob.
func umaskProfileDropIns(fs afero.Fs) ([]string, error) {
	etc, err := umaskShFiles(fs, profileDropInDir)
	if err != nil {
		return nil, err
	}
	vendor, err := umaskShFiles(fs, vendorProfileDropInDir)
	if err != nil {
		return nil, err
	}
	shadowed := make(map[string]bool, len(etc))
	for _, name := range etc {
		shadowed[name] = true
	}

	var res []string
	for _, name := range vendor {
		if !shadowed[name] {
			res = append(res, path.Join(vendorProfileDropInDir, name))
		}
	}
	for _, name := range etc {
		res = append(res, path.Join(profileDropInDir, name))
	}
	return res, nil
}

// umaskShFiles lists the names of the *.sh entries of dir, sorted. A missing
// directory has none; one that cannot be read is an error, since its files may
// set the umask.
func umaskShFiles(fs afero.Fs, dir string) ([]string, error) {
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list %s: %w", dir, err)
	}
	var res []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sh") && !e.IsDir() {
			res = append(res, e.Name())
		}
	}
	sort.Strings(res)
	return res, nil
}

func umaskFileExists(fs afero.Fs, p string) (bool, error) {
	st, err := fs.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read %s: %w", p, err)
	}
	return isRegularTarget(st), nil
}

func umaskReadFile(runtime *plugin.Runtime, p string) (string, error) {
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
	if err != nil {
		return "", err
	}
	content := f.(*mqlFile).GetContent()
	if content.Error != nil {
		return "", fmt.Errorf("failed to read %s: %w", p, content.Error)
	}
	return content.Data, nil
}

// umaskUserHome returns the home directory of the user name.
func umaskUserHome(runtime *plugin.Runtime, name string) (string, error) {
	obj, err := NewResource(runtime, "user", map[string]*llx.RawData{"name": llx.StringData(name)})
	if err != nil {
		return "", err
	}
	home := obj.(*mqlUser).GetHome()
	if home.Error != nil {
		return "", home.Error
	}
	return home.Data, nil
}

// newUmaskSetting creates the umask.setting for one setting. maskErr is set
// when value is not a mode, such as $UMASK; every field that describes the
// mask is then null.
func newUmaskSetting(runtime *plugin.Runtime, src umaskSourceFile, line int, ordinal int, value string, mask umask.Mask, maskErr error, conditional bool) (*mqlUmaskSetting, error) {
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{"path": llx.StringData(src.path)})
	if err != nil {
		return nil, err
	}

	id := "umask.setting/" + src.source + "/" + src.path + "/" + strconv.Itoa(line)
	if ordinal > 0 {
		id += "/" + strconv.Itoa(ordinal)
	}
	args := map[string]*llx.RawData{
		"__id":        llx.StringData(id),
		"source":      llx.StringData(src.source),
		"file":        llx.ResourceData(f, "file"),
		"line":        llx.IntData(line),
		"value":       llx.StringData(value),
		"conditional": llx.BoolData(conditional),
	}
	perms := map[string]uint32{
		"userReadable":    0o400,
		"userWriteable":   0o200,
		"userExecutable":  0o100,
		"groupReadable":   0o040,
		"groupWriteable":  0o020,
		"groupExecutable": 0o010,
		"otherReadable":   0o004,
		"otherWriteable":  0o002,
		"otherExecutable": 0o001,
	}
	if maskErr != nil {
		args["mode"] = llx.IntDataPtr[int64](nil)
		args["octal"] = llx.StringDataPtr(nil)
		args["relative"] = llx.BoolDataPtr(nil)
		for name := range perms {
			args[name] = llx.BoolDataPtr(nil)
		}
	} else {
		args["mode"] = llx.IntData(int64(mask.Bits))
		args["octal"] = llx.StringData(mask.String())
		args["relative"] = llx.BoolData(mask.Relative)
		for name, bit := range perms {
			args[name] = llx.BoolData(mask.Bits&bit == 0)
		}
	}

	res, err := CreateResource(runtime, "umask.setting", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlUmaskSetting), nil
}
