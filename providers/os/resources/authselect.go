// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/authselect"
	"go.mondoo.com/mql/providers/os/resources/pam"
)

const (
	authselectConfigDir  = "/etc/authselect"
	authselectConfigFile = authselectConfigDir + "/authselect.conf"
	authselectCustomDir  = authselectConfigDir + "/custom"
	authselectVendorDir  = "/usr/share/authselect/vendor"
	authselectDefaultDir = "/usr/share/authselect/default"
	// authselectMaxFileSize caps a template or generated file; stock ones are
	// a few kilobytes
	authselectMaxFileSize = 1 << 20
)

// authselectTemplates are the files authselect generates from a profile, in
// its order, with the path that links to each generated file.
var authselectTemplates = []struct {
	name string
	link string
	pam  bool
}{
	{"system-auth", "/etc/pam.d/system-auth", true},
	{"password-auth", "/etc/pam.d/password-auth", true},
	{"fingerprint-auth", "/etc/pam.d/fingerprint-auth", true},
	{"smartcard-auth", "/etc/pam.d/smartcard-auth", true},
	{"postlogin", "/etc/pam.d/postlogin", true},
	{"nsswitch.conf", "/etc/nsswitch.conf", false},
	{"dconf-db", "/etc/dconf/db/distro.d/20-authselect", false},
	{"dconf-locks", "/etc/dconf/db/distro.d/locks/20-authselect", false},
}

type mqlAuthselectInternal struct {
	lock      sync.Mutex
	loaded    bool
	loadError error
	// config is nil when authselect does not manage the system
	config *authselect.Config

	linksLoaded bool
	linksError  error
	// links maps each link path to its target; a path that is not a link
	// has no entry
	links map[string]string

	userNsswitchLoaded bool
	userNsswitchError  error
	// userNsswitch is the user-nsswitch.conf to merge into nsswitch.conf,
	// nil when authselect does not merge one
	userNsswitch *string
}

func (a *mqlAuthselect) id() (string, error) {
	return "authselect", nil
}

// load reads authselect.conf once.
func (a *mqlAuthselect) load() (*authselect.Config, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.loaded {
		return a.config, a.loadError
	}
	a.loaded = true

	conn := a.MqlRuntime.Connection.(shared.Connection)
	content, err := readAuthselectFile(conn.FileSystem(), authselectConfigFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			a.loadError = err
		}
		return nil, a.loadError
	}
	if cfg, ok := authselect.ParseConfig(content); ok {
		a.config = &cfg
	}
	return a.config, nil
}

func (a *mqlAuthselect) configured() (bool, error) {
	cfg, err := a.load()
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

func (a *mqlAuthselect) profileId() (string, error) {
	cfg, err := a.load()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		a.ProfileId.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return cfg.ProfileID, nil
}

func (a *mqlAuthselect) isCustom() (bool, error) {
	cfg, err := a.load()
	if err != nil {
		return false, err
	}
	if cfg == nil {
		a.IsCustom.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return authselect.IsCustom(cfg.ProfileID), nil
}

func (a *mqlAuthselect) features() ([]any, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		a.Features.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := []any{}
	for _, f := range cfg.Features {
		res = append(res, f)
	}
	return res, nil
}

// profilePath returns the directory of the selected profile, looked up the
// way authselect does, and whether it exists.
func (a *mqlAuthselect) profilePath(cfg *authselect.Config) (string, bool, error) {
	fs := a.MqlRuntime.Connection.(shared.Connection).FileSystem()
	if name, ok := strings.CutPrefix(cfg.ProfileID, authselect.CustomPrefix); ok {
		dir := path.Join(authselectCustomDir, name)
		exists, err := isAuthselectDir(fs, dir)
		return dir, exists, err
	}
	for _, base := range []string{authselectVendorDir, authselectDefaultDir} {
		dir := path.Join(base, cfg.ProfileID)
		exists, err := isAuthselectDir(fs, dir)
		if err != nil || exists {
			return dir, exists, err
		}
	}
	return path.Join(authselectDefaultDir, cfg.ProfileID), false, nil
}

func isAuthselectDir(fs afero.Fs, p string) (bool, error) {
	info, err := fs.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

func (a *mqlAuthselect) profileDir() (*mqlFile, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		a.ProfileDir.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	dir, _, err := a.profilePath(cfg)
	if err != nil {
		return nil, err
	}
	f, err := CreateResource(a.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(dir),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (a *mqlAuthselect) templates() ([]any, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		a.Templates.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	dir, exists, err := a.profilePath(cfg)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, llx.NotFound(fmt.Errorf("authselect profile %s not found at %s", cfg.ProfileID, dir))
	}

	res := make([]any, 0, len(authselectTemplates))
	for _, t := range authselectTemplates {
		templatePath := path.Join(dir, t.name)
		r, err := CreateResource(a.MqlRuntime, "authselect.template", map[string]*llx.RawData{
			"__id": llx.StringData("authselect.template/" + templatePath),
			"name": llx.StringData(t.name),
		})
		if err != nil {
			return nil, err
		}
		tmpl := r.(*mqlAuthselectTemplate)
		tmpl.parent = a
		tmpl.path = templatePath
		tmpl.link = t.link
		tmpl.pam = t.pam
		tmpl.features = cfg.Features
		res = append(res, tmpl)
	}
	return res, nil
}

func (a *mqlAuthselect) intact() (bool, error) {
	cfg, err := a.load()
	if err != nil {
		return false, err
	}
	if cfg == nil {
		a.Intact.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	if _, exists, err := a.profilePath(cfg); err != nil || !exists {
		return false, err
	}

	templates := a.GetTemplates()
	if templates.Error != nil {
		return false, templates.Error
	}
	for _, t := range templates.Data {
		ok, err := t.(*mqlAuthselectTemplate).intact()
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// linkTargets reads the target of every path that links to a generated
// file, once for all templates.
func (a *mqlAuthselect) linkTargets() (map[string]string, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if !a.linksLoaded {
		a.linksLoaded = true
		paths := make([]string, len(authselectTemplates))
		for i := range authselectTemplates {
			paths[i] = authselectTemplates[i].link
		}
		a.links, a.linksError = readSymlinkTargets(a.MqlRuntime.Connection.(shared.Connection), paths)
	}
	return a.links, a.linksError
}

// authselectLibraries are where libauthselect is installed on the
// distributions that ship authselect.
var authselectLibraries = []string{"/usr/lib64/libauthselect.so.*", "/usr/lib/libauthselect.so.*"}

// userNsswitchContent returns the user-nsswitch.conf authselect merges into
// the nsswitch.conf it generates, or nil when it merges none. Whether this
// authselect merges one at all is a build option (on for RHEL before 10 and
// Fedora before 36), read from the library; without a readable library, a
// user-nsswitch.conf that exists is taken to be merged.
func (a *mqlAuthselect) userNsswitchContent() (*string, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.userNsswitchLoaded {
		return a.userNsswitch, a.userNsswitchError
	}
	a.userNsswitchLoaded = true

	fs := a.MqlRuntime.Connection.(shared.Connection).FileSystem()
	if merges, found := authselectMergesUserNsswitch(fs); found && !merges {
		return nil, nil
	}
	content, err := readAuthselectFile(fs, authselect.UserNsswitchPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		a.userNsswitchError = err
		return nil, err
	}
	a.userNsswitch = &content
	return a.userNsswitch, nil
}

// authselectMergesUserNsswitch reads whether the installed libauthselect
// merges user-nsswitch.conf. found is false when no library can be read.
func authselectMergesUserNsswitch(fs afero.Fs) (merges, found bool) {
	for _, pattern := range authselectLibraries {
		matches, err := afero.Glob(fs, pattern)
		if err != nil {
			continue
		}
		for _, p := range matches {
			f, err := fs.Open(p)
			if err != nil {
				continue
			}
			data, err := io.ReadAll(io.LimitReader(f, 16<<20))
			f.Close()
			if err != nil {
				continue
			}
			return authselect.MergesUserNsswitch(data), true
		}
	}
	return false, false
}

// readSymlinkTargets returns the target each path links to, as written in
// the link. A path that is not a link has no entry. A filesystem that can
// read links is asked directly; otherwise (SSH, sudo through cat) one shell
// loop runs readlink for all of them.
func readSymlinkTargets(conn shared.Connection, paths []string) (map[string]string, error) {
	if lr, ok := conn.FileSystem().(afero.LinkReader); ok {
		res := make(map[string]string, len(paths))
		for _, p := range paths {
			if target, err := lr.ReadlinkIfPossible(p); err == nil {
				res[p] = target
			}
		}
		return res, nil
	}

	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, errors.New("cannot read symbolic links on this connection")
	}
	var script strings.Builder
	script.WriteString("for p in")
	for _, p := range paths {
		script.WriteString(" " + shellQuote(p))
	}
	script.WriteString(`; do printf '%s\t%s\n' "$p" "$(readlink "$p" 2>/dev/null)"; done`)
	// Run through sh -c so that --sudo elevates the loop as one command rather
	// than prefixing only its first word.
	cmd, err := conn.RunCommand("sh -c " + shellQuote(script.String()))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, fmt.Errorf("reading symbolic links failed with exit status %d", cmd.ExitStatus)
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	return parseReadlinkOutput(string(data)), nil
}

// readAuthselectFile reads a file of at most authselectMaxFileSize bytes.
func readAuthselectFile(fs afero.Fs, p string) (string, error) {
	f, err := fs.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, authselectMaxFileSize+1))
	if err != nil {
		return "", err
	}
	if len(data) > authselectMaxFileSize {
		return "", fmt.Errorf("%s is larger than %d bytes", p, authselectMaxFileSize)
	}
	return string(data), nil
}

type mqlAuthselectTemplateInternal struct {
	parent *mqlAuthselect
	// path is the template file in the profile directory
	path string
	// link is the path that links to the generated file
	link     string
	pam      bool
	features []string

	lock      sync.Mutex
	generated bool
	lines     []authselect.Line
	// text is the content authselect generates, which for nsswitch.conf
	// includes the maps merged from user-nsswitch.conf
	text     string
	genError error
}

func (t *mqlAuthselectTemplate) generatedPath() string {
	return path.Join(authselectConfigDir, t.Name.Data)
}

// generate applies the profile's features to the template once, returning
// the generated lines of the template and the content authselect writes. A
// template the profile does not ship generates an empty file, as in
// authselect.
func (t *mqlAuthselectTemplate) generate() ([]authselect.Line, string, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.generated {
		return t.lines, t.text, t.genError
	}
	t.generated = true

	fs := t.MqlRuntime.Connection.(shared.Connection).FileSystem()
	content, err := readAuthselectFile(fs, t.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.genError = err
		return nil, "", err
	}
	lines, err := authselect.Generate(content, t.features)
	if err != nil {
		t.genError = fmt.Errorf("%s: %w", t.path, err)
		return nil, "", t.genError
	}
	text := authselect.Text(lines)
	if t.Name.Data == "nsswitch.conf" {
		user, err := t.parent.userNsswitchContent()
		if err != nil {
			t.genError = err
			return nil, "", err
		}
		if user != nil {
			text = authselect.MergeUserNsswitch(text, *user)
		}
	}
	t.lines, t.text = lines, text
	return t.lines, t.text, nil
}

func (t *mqlAuthselectTemplate) file() (*mqlFile, error) {
	f, err := CreateResource(t.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(t.path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (t *mqlAuthselectTemplate) generatedFile() (*mqlFile, error) {
	f, err := CreateResource(t.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(t.generatedPath()),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (t *mqlAuthselectTemplate) content() (string, error) {
	_, text, err := t.generate()
	return text, err
}

func (t *mqlAuthselectTemplate) entries() ([]any, error) {
	if !t.pam {
		return []any{}, nil
	}
	lines, _, err := t.generate()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, line := range lines {
		entry, err := pam.ParseLine(line.Text)
		if err != nil {
			log.Warn().Err(err).Str("path", t.path).Int("line", line.Source+1).Msg("skipping malformed PAM line")
			continue
		}
		if entry == nil {
			continue
		}
		args := pamServiceEntryArgs(t.path, line.Source, entry)
		// distinct from the entries pam.conf reads from the template file
		// itself, whose options still hold the template operators
		args["__id"] = llx.StringData("authselect.template/" + t.path + "/" + strconv.Itoa(line.Source))
		r, err := CreateResource(t.MqlRuntime, "pam.conf.serviceEntry", args)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (t *mqlAuthselectTemplate) intact() (bool, error) {
	_, text, err := t.generate()
	if err != nil {
		return false, err
	}

	conn := t.MqlRuntime.Connection.(shared.Connection)
	generatedPath := t.generatedPath()
	mode, err := lstatMode(conn, generatedPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !mode.IsRegular() || mode.Perm() != 0o644 {
		return false, nil
	}

	written, err := readAuthselectFile(conn.FileSystem(), generatedPath)
	if err != nil {
		return false, err
	}
	if !authselect.SameContent(written, text) {
		return false, nil
	}

	links, err := t.parent.linkTargets()
	if err != nil {
		return false, err
	}
	return links[t.link] == generatedPath, nil
}

// lstatMode returns the mode of p, without following p itself when it is a
// symbolic link.
func lstatMode(conn shared.Connection, p string) (os.FileMode, error) {
	if l, ok := conn.FileSystem().(afero.Lstater); ok {
		info, _, err := l.LstatIfPossible(p)
		if err != nil {
			return 0, err
		}
		return info.Mode(), nil
	}
	info, err := conn.FileInfo(p)
	if err != nil {
		return 0, err
	}
	return info.Mode.FileMode, nil
}
