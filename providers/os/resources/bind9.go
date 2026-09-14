// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"github.com/spf13/afero"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/bind9"
	"go.mondoo.com/mql/types"
)

// bind9ConfPaths are the entry points distributions use. Debian and its
// derivatives keep the configuration in a directory of fragments; the Red Hat
// and SUSE families put the entry point directly in /etc.
var bind9ConfPaths = map[string]string{
	"debian":        "/etc/bind/named.conf",
	"ubuntu":        "/etc/bind/named.conf",
	"redhat":        "/etc/named.conf",
	"fedora":        "/etc/named.conf",
	"centos":        "/etc/named.conf",
	"centos-stream": "/etc/named.conf",
	"suse":          "/etc/named.conf",
	"alpine":        "/etc/bind/named.conf",
}

// bind9ConfCandidates is the probe order when the platform is unknown or its
// package puts the file somewhere else. A host running BIND from a different
// layout still answers rather than reporting nothing configured.
var bind9ConfCandidates = []string{
	"/etc/bind/named.conf",
	"/etc/named.conf",
	"/usr/local/etc/namedb/named.conf",
	"/usr/local/etc/named.conf",
}

type mqlBind9Internal struct {
	lock   sync.Mutex
	parsed bool
	cfg    *bind9.Config
	// baseDir is the options directory statement, which relative zone paths
	// resolve against. Named apart from the directory() field so the generated
	// accessor and the cached value do not collide.
	baseDir string
	// confPath is the file the configuration was read from, used to build the
	// ids of everything below it.
	confPath string
}

type mqlBind9ZoneInternal struct {
	// resolvedPath is the zone file made absolute against the directory
	// option, empty when the zone declares no file.
	resolvedPath string
}

func initBind9(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in bind9 initialization, it must be a string")
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

func (b *mqlBind9) id() (string, error) {
	file := b.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "bind9", nil
	}
	return "bind9/" + file.Data.Path.Data, nil
}

// bind9ConfPath picks the entry point for the asset's platform, falling back to
// the first candidate that exists so an unrecognized platform still reports.
func bind9ConfPath(conn shared.Connection) string {
	preferred := ""
	asset := conn.Asset()
	if asset != nil && asset.Platform != nil {
		if p, ok := bind9ConfPaths[asset.Platform.Name]; ok {
			preferred = p
		} else {
			for _, family := range asset.Platform.Family {
				if p, ok := bind9ConfPaths[family]; ok {
					preferred = p
					break
				}
			}
		}
	}

	fs := conn.FileSystem()
	if preferred != "" {
		if _, err := fs.Stat(preferred); err == nil {
			return preferred
		}
	}
	for _, candidate := range bind9ConfCandidates {
		if _, err := fs.Stat(candidate); err == nil {
			return candidate
		}
	}
	if preferred != "" {
		return preferred
	}
	return bind9ConfCandidates[0]
}

func (b *mqlBind9) file() (*mqlFile, error) {
	conn := b.MqlRuntime.Connection.(shared.Connection)
	f, err := CreateResource(b.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(bind9ConfPath(conn)),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// parse reads the configuration once, expanding includes through the
// connection's filesystem so this works against an image or a remote host.
func (b *mqlBind9) parse() error {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.parsed {
		return nil
	}

	file := b.GetFile()
	if file.Error != nil {
		return file.Error
	}
	if file.Data == nil {
		return errors.New("no bind9 configuration file to read")
	}
	path := file.Data.Path.Data

	conn := b.MqlRuntime.Connection.(shared.Connection)
	fs := conn.FileSystem()
	open := func(p string) (io.ReadCloser, error) {
		return fs.Open(p)
	}

	cfg := bind9.ParseFiles(path, open)
	// The root file failing to open is the one case worth surfacing as an
	// error: everything else is a partial configuration, which still answers.
	if len(cfg.Files) == 0 {
		if len(cfg.Errors) > 0 {
			return cfg.Errors[0]
		}
		return errors.New("could not read the bind9 configuration at " + path)
	}

	b.cfg = cfg
	b.confPath = path
	if opts := bind9.First(cfg.Statements, "options"); opts != nil {
		b.baseDir = bind9.Value(opts.Block, "directory")
	}
	b.parsed = true
	return nil
}

func (b *mqlBind9) files() ([]any, error) {
	if err := b.parse(); err != nil {
		return nil, err
	}

	paths := bind9.SortedFiles(b.cfg.Files)
	out := make([]any, 0, len(paths))
	for _, p := range paths {
		f, err := CreateResource(b.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(p),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// optionsBlock returns the statements of the options block, or nil when the
// configuration declares none.
func (b *mqlBind9) optionsBlock() ([]bind9.Statement, error) {
	if err := b.parse(); err != nil {
		return nil, err
	}
	opts := bind9.First(b.cfg.Statements, "options")
	if opts == nil {
		return nil, nil
	}
	return opts.Block, nil
}

// optionValue reads a scalar statement of the options block.
func (b *mqlBind9) optionValue(name string) (string, error) {
	block, err := b.optionsBlock()
	if err != nil {
		return "", err
	}
	return bind9.Value(block, name), nil
}

// optionList reads an address-match list of the options block.
func (b *mqlBind9) optionList(name string) ([]any, error) {
	block, err := b.optionsBlock()
	if err != nil {
		return nil, err
	}
	return bind9StringList(block, name), nil
}

func (b *mqlBind9) recursion() (bool, error) {
	block, err := b.optionsBlock()
	if err != nil {
		return false, err
	}
	// BIND answers recursive queries unless told otherwise, so an absent
	// statement is recursion on rather than unknown.
	v := bind9.Value(block, "recursion")
	if v == "" {
		return true, nil
	}
	return bind9IsYes(v), nil
}

func (b *mqlBind9) dnssecValidation() (string, error) { return b.optionValue("dnssec-validation") }
func (b *mqlBind9) directory() (string, error)        { return b.optionValue("directory") }
func (b *mqlBind9) version() (string, error)          { return b.optionValue("version") }
func (b *mqlBind9) minimalResponses() (string, error) { return b.optionValue("minimal-responses") }

func (b *mqlBind9) allowQuery() ([]any, error)     { return b.optionList("allow-query") }
func (b *mqlBind9) allowRecursion() ([]any, error) { return b.optionList("allow-recursion") }
func (b *mqlBind9) allowTransfer() ([]any, error)  { return b.optionList("allow-transfer") }
func (b *mqlBind9) allowUpdate() ([]any, error)    { return b.optionList("allow-update") }
func (b *mqlBind9) listenOn() ([]any, error)       { return b.optionList("listen-on") }
func (b *mqlBind9) listenOnV6() ([]any, error)     { return b.optionList("listen-on-v6") }
func (b *mqlBind9) forwarders() ([]any, error)     { return b.optionList("forwarders") }
func (b *mqlBind9) alsoNotify() ([]any, error)     { return b.optionList("also-notify") }

// optionPort reads the port modifier of a listen statement. 0 means the
// statement does not set one, which leaves BIND on 53.
func (b *mqlBind9) optionPort(name string) (int64, error) {
	block, err := b.optionsBlock()
	if err != nil {
		return 0, err
	}
	s := bind9.First(block, name)
	if s == nil {
		return 0, nil
	}
	return bind9.ParseCount(s.ArgValue("port")), nil
}

func (b *mqlBind9) listenOnPort() (int64, error)   { return b.optionPort("listen-on") }
func (b *mqlBind9) listenOnV6Port() (int64, error) { return b.optionPort("listen-on-v6") }

func (b *mqlBind9) params() (map[string]any, error) {
	block, err := b.optionsBlock()
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range bind9.Params(block) {
		out[k] = v
	}
	return out, nil
}

// bind9Views walks the top level and every view, handing each zone to fn with
// the view it belongs to. Zones inside a view are the normal shape for a server
// that answers differently by client, and a reader that only looks at the top
// level reports such a server as serving nothing.
func bind9EachZone(stmts []bind9.Statement, fn func(view string, zone bind9.Statement)) {
	for i := range stmts {
		s := stmts[i]
		switch {
		case strings.EqualFold(s.Name, "zone"):
			fn("", s)
		case strings.EqualFold(s.Name, "view") && s.IsBlock():
			view := s.Arg(0)
			for j := range s.Block {
				if strings.EqualFold(s.Block[j].Name, "zone") {
					fn(view, s.Block[j])
				}
			}
		}
	}
}

func (b *mqlBind9) zones() ([]any, error) {
	if err := b.parse(); err != nil {
		return nil, err
	}

	var out []any
	var walkErr error
	bind9EachZone(b.cfg.Statements, func(view string, z bind9.Statement) {
		if walkErr != nil {
			return
		}

		name := z.Arg(0)
		class := "IN"
		// `zone "example.com" IN { ... }` — the class is optional and only the
		// three real classes are classes; anything else is not one.
		if c := strings.ToUpper(z.Arg(1)); c == "IN" || c == "CH" || c == "HS" {
			class = c
		}

		path := bind9.Value(z.Block, "file")
		params := map[string]any{}
		for k, v := range bind9.Params(z.Block) {
			params[k] = v
		}

		primaries := bind9StringList(z.Block, "primaries")
		if len(primaries) == 0 {
			primaries = bind9StringList(z.Block, "masters")
		}

		res, err := CreateResource(b.MqlRuntime, "bind9.zone", map[string]*llx.RawData{
			"__id":          llx.StringData(b.confPath + "/zone/" + view + "/" + class + "/" + name),
			"name":          llx.StringData(name),
			"class":         llx.StringData(class),
			"view":          llx.StringData(view),
			"type":          llx.StringData(bind9.Value(z.Block, "type")),
			"path":          llx.StringData(path),
			"allowTransfer": llx.ArrayData(bind9StringList(z.Block, "allow-transfer"), types.String),
			"allowUpdate":   llx.ArrayData(bind9StringList(z.Block, "allow-update"), types.String),
			"allowQuery":    llx.ArrayData(bind9StringList(z.Block, "allow-query"), types.String),
			"primaries":     llx.ArrayData(primaries, types.String),
			"alsoNotify":    llx.ArrayData(bind9StringList(z.Block, "also-notify"), types.String),
			"params":        llx.MapData(params, types.String),
		})
		if err != nil {
			walkErr = err
			return
		}

		zone := res.(*mqlBind9Zone)
		zone.resolvedPath = bind9ResolveZonePath(path, b.baseDir, z.File)
		out = append(out, zone)
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return out, nil
}

// bind9ResolveZonePath makes a zone file absolute the way named does: relative
// paths resolve against the directory option, and against the directory of the
// declaring file when the configuration sets no directory.
func bind9ResolveZonePath(path, directory, declaredIn string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	if directory != "" {
		return filepath.Join(directory, path)
	}
	if declaredIn != "" {
		return filepath.Join(filepath.Dir(declaredIn), path)
	}
	return path
}

func (z *mqlBind9Zone) file() (*mqlFile, error) {
	if z.resolvedPath == "" {
		// A forward or stub zone has no file of its own. The field has to be
		// marked resolved, or the runtime keeps asking.
		z.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	f, err := CreateResource(z.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(z.resolvedPath),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (b *mqlBind9) acls() ([]any, error) {
	if err := b.parse(); err != nil {
		return nil, err
	}

	var out []any
	for _, acl := range bind9.Find(b.cfg.Statements, "acl") {
		name := acl.Arg(0)
		entries := make([]any, 0, len(acl.Block))
		for i := range acl.Block {
			entry := acl.Block[i].Name
			if args := acl.Block[i].Args; len(args) > 0 {
				entry = entry + " " + strings.Join(args, " ")
			}
			entries = append(entries, entry)
		}

		res, err := CreateResource(b.MqlRuntime, "bind9.acl", map[string]*llx.RawData{
			"__id":    llx.StringData(b.confPath + "/acl/" + name),
			"name":    llx.StringData(name),
			"entries": llx.ArrayData(entries, types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (b *mqlBind9) keys() ([]any, error) {
	if err := b.parse(); err != nil {
		return nil, err
	}

	var out []any
	// Keys are declared at the top level and inside views. Two views may
	// declare different keys under the same name, so the view belongs in the
	// id: without it the second key resolves to the cached first one and
	// reports its algorithm, which reads as the stronger of the two when a
	// view is the one using the weaker.
	collect := func(stmts []bind9.Statement, view string) error {
		for _, k := range bind9.Find(stmts, "key") {
			name := k.Arg(0)
			res, err := CreateResource(b.MqlRuntime, "bind9.key", map[string]*llx.RawData{
				"__id": llx.StringData(b.confPath + "/key/" + view + "/" + name),
				"name": llx.StringData(name),
				"view": llx.StringData(view),
				// The secret statement is deliberately left behind: reading it
				// would copy key material into scan results.
				"algorithm": llx.StringData(bind9.Value(k.Block, "algorithm")),
			})
			if err != nil {
				return err
			}
			// The parser records which file every statement came from, after
			// include expansion, so a key kept in its own included file can be
			// checked for ownership and mode.
			res.(*mqlBind9Key).declaredIn = k.File
			out = append(out, res)
		}
		return nil
	}

	if err := collect(b.cfg.Statements, ""); err != nil {
		return nil, err
	}
	for _, view := range bind9.Find(b.cfg.Statements, "view") {
		if err := collect(view.Block, view.Arg(0)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (b *mqlBind9) channels() ([]any, error) {
	if err := b.parse(); err != nil {
		return nil, err
	}

	logging := bind9.First(b.cfg.Statements, "logging")
	if logging == nil {
		return []any{}, nil
	}

	var out []any
	for _, ch := range bind9.Find(logging.Block, "channel") {
		name := ch.Arg(0)

		path := ""
		target := ""
		versions := int64(0)
		sizeLimit := int64(0)
		if f := bind9.First(ch.Block, "file"); f != nil {
			path = f.Arg(0)
			// `file "audit.log" versions 3 size 5m;` carries retention as
			// modifiers of the file statement rather than statements of
			// their own.
			versions = bind9.ParseCount(f.ArgValue("versions"))
			sizeLimit = bind9.ParseSize(f.ArgValue("size"))
		}
		for _, t := range []string{"syslog", "stderr", "null"} {
			if bind9.First(ch.Block, t) != nil {
				target = t
				break
			}
		}
		syslogFacility := ""
		if s := bind9.First(ch.Block, "syslog"); s != nil {
			syslogFacility = s.Arg(0)
		}

		res, err := CreateResource(b.MqlRuntime, "bind9.channel", map[string]*llx.RawData{
			"__id":           llx.StringData(b.confPath + "/channel/" + name),
			"name":           llx.StringData(name),
			"path":           llx.StringData(path),
			"target":         llx.StringData(target),
			"versions":       llx.IntData(versions),
			"sizeLimit":      llx.IntData(sizeLimit),
			"severity":       llx.StringData(bind9.Value(ch.Block, "severity")),
			"syslogFacility": llx.StringData(syslogFacility),
			"printTime":      llx.BoolData(bind9IsYes(bind9.Value(ch.Block, "print-time"))),
			"printCategory":  llx.BoolData(bind9IsYes(bind9.Value(ch.Block, "print-category"))),
			"printSeverity":  llx.BoolData(bind9IsYes(bind9.Value(ch.Block, "print-severity"))),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (b *mqlBind9) logCategories() (map[string]any, error) {
	if err := b.parse(); err != nil {
		return nil, err
	}

	out := map[string]any{}
	logging := bind9.First(b.cfg.Statements, "logging")
	if logging == nil {
		return out, nil
	}

	for _, cat := range bind9.Find(logging.Block, "category") {
		name := cat.Arg(0)
		channels := make([]any, 0, len(cat.Block))
		for i := range cat.Block {
			channels = append(channels, cat.Block[i].Name)
		}
		out[name] = channels
	}
	return out, nil
}

// bind9StringList reads an address-match list as []any for llx.
func bind9StringList(stmts []bind9.Statement, name string) []any {
	entries := bind9.List(stmts, name)
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, e)
	}
	return out
}

// bind9IsYes reads the several spellings BIND accepts for a boolean.
func bind9IsYes(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1":
		return true
	}
	return false
}

// mqlBind9KeyInternal carries the file the key statement was read from, which
// the parser records but the resource fields do not otherwise expose.
type mqlBind9KeyInternal struct {
	declaredIn string
}

func (k *mqlBind9Key) file() (*mqlFile, error) {
	if k.declaredIn == "" {
		k.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	f, err := CreateResource(k.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(k.declaredIn),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// dnssecKeyDirs are where a key pair is looked for when the configuration does
// not say. `key-directory` and the working directory come first; these are the
// locations a distribution uses when neither is set.
var dnssecKeyDirs = []string{
	"/etc/bind/keys",
	"/var/cache/bind",
	"/etc/named/keys",
	"/var/named",
	"/etc/bind",
}

func (b *mqlBind9) dnssecKeys() ([]any, error) {
	if err := b.parse(); err != nil {
		return nil, err
	}

	conn := b.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	// The configuration's own answer wins over the well-known locations: a
	// server told to keep its keys somewhere is keeping them there.
	opts, err := b.optionsBlock()
	if err != nil {
		return nil, err
	}
	var dirs []string
	if d := bind9.Value(opts, "key-directory"); d != "" {
		dirs = append(dirs, strings.Trim(d, `"`))
	}
	if d := bind9.Value(opts, "directory"); d != "" {
		dirs = append(dirs, strings.Trim(d, `"`))
	}
	dirs = append(dirs, dnssecKeyDirs...)

	seen := map[string]bool{}
	out := []any{}

	for _, dir := range dirs {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true

		entries, err := afs.ReadDir(dir)
		if err != nil {
			// A directory that is not there is not an error: most of the list
			// is a guess. A directory that exists but cannot be read is left
			// to the file resource to report per key.
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !bind9.IsDNSSECKeyFile(entry.Name()) {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if seen[path] {
				continue
			}
			seen[path] = true

			content, err := afs.ReadFile(path)
			if err != nil {
				continue
			}
			parsed := bind9.ParseDNSSECKeyFile(entry.Name(), string(content))
			if parsed == nil {
				continue
			}

			created := llx.NilData
			if !parsed.Created.IsZero() {
				at := parsed.Created
				created = llx.TimeData(at)
			}

			res, err := CreateResource(b.MqlRuntime, "bind9.dnssecKey", map[string]*llx.RawData{
				"__id":            llx.StringData(path),
				"zone":            llx.StringData(parsed.Zone),
				"keyTag":          llx.IntData(int64(parsed.KeyTag)),
				"algorithm":       llx.IntData(int64(parsed.Algorithm)),
				"isKeySigningKey": llx.BoolData(parsed.KeySigningKey),
				"created":         created,
			})
			if err != nil {
				return nil, err
			}
			key := res.(*mqlBind9DnssecKey)
			key.publicPath = path
			key.privatePath = bind9.PrivateKeyPath(path)
			out = append(out, key)
		}
	}

	return out, nil
}

// mqlBind9DnssecKeyInternal carries the two paths, so the file resources are
// created only if a check asks for them.
type mqlBind9DnssecKeyInternal struct {
	publicPath  string
	privatePath string
}

func (k *mqlBind9DnssecKey) file() (*mqlFile, error) {
	f, err := CreateResource(k.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(k.publicPath),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (k *mqlBind9DnssecKey) privateFile() (*mqlFile, error) {
	f, err := CreateResource(k.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(k.privatePath),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}
