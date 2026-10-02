// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path"
	"strconv"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/tomcat"
	"go.mondoo.com/mql/types"
)

type mqlTomcatInternal struct {
	lock       sync.Mutex
	discovered bool
	homePath   string
	basePath   string
}

// mqlTomcatWebappInternal keeps the installation paths on each webapp so that
// ${catalina.base} inside an application's own configuration resolves the same
// way it does for the global files.
type mqlTomcatWebappInternal struct {
	paths tomcat.Paths
}

func initTomcat(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	for _, key := range []string{"home", "base"} {
		if x, ok := args[key]; ok {
			if _, ok := x.Value.(string); !ok {
				return nil, nil, errors.New("wrong type for '" + key + "' in tomcat initialization, it must be a string")
			}
		}
	}
	return args, nil, nil
}

// The resource names tomcat.server, tomcat.context and tomcat.webxml collide
// with the tomcat fields of the same name: writing `tomcat.server.services`
// resolves to the *resource* rather than to the `server` field of `tomcat`.
// These init functions make both spellings mean the same thing by handing back
// the instance the tomcat resource already built. Each returns the resource
// itself, which NewResource uses directly in place of creating a bare one.

func initTomcatServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	installation, err := tomcatInstallation(runtime)
	if err != nil {
		return nil, nil, err
	}
	server := installation.GetServer()
	if server.Error != nil {
		return nil, nil, server.Error
	}
	if server.Data == nil {
		// No installation, or no server.xml in it. An empty configuration built
		// through the same constructor keeps `tomcat.server.services` an empty
		// list rather than an error, and cannot drift out of step with the
		// resource's fields the way a hand-written argument list would.
		res, err := newTomcatServer(runtime, &tomcat.Server{}, nil, "tomcat.server", tomcat.Paths{})
		if err != nil {
			return nil, nil, err
		}
		return args, res, nil
	}
	return args, server.Data, nil
}

func initTomcatContext(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	installation, err := tomcatInstallation(runtime)
	if err != nil {
		return nil, nil, err
	}
	ctx := installation.GetContext()
	if ctx.Error != nil {
		return nil, nil, ctx.Error
	}
	if ctx.Data == nil {
		res, err := newTomcatContext(runtime, &tomcat.Context{}, nil, "tomcat.context")
		if err != nil {
			return nil, nil, err
		}
		return args, res, nil
	}
	return args, ctx.Data, nil
}

func initTomcatWebxml(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	installation, err := tomcatInstallation(runtime)
	if err != nil {
		return nil, nil, err
	}
	webXml := installation.GetWebXml()
	if webXml.Error != nil {
		return nil, nil, webXml.Error
	}
	if webXml.Data == nil {
		res, err := newTomcatWebxml(runtime, &tomcat.WebXML{}, nil, "tomcat.webxml")
		if err != nil {
			return nil, nil, err
		}
		return args, res, nil
	}
	return args, webXml.Data, nil
}

func tomcatInstallation(runtime *plugin.Runtime) (*mqlTomcat, error) {
	raw, err := CreateResource(runtime, "tomcat", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlTomcat), nil
}

func (t *mqlTomcat) id() (string, error) {
	p := t.installPaths()
	if p.Home == "" && p.Base == "" {
		return "tomcat", nil
	}
	return "tomcat/" + p.Home + "/" + p.Base, nil
}

// installPaths resolves CATALINA_HOME and CATALINA_BASE once and caches the
// result for every other field on the resource.
func (t *mqlTomcat) installPaths() tomcat.Paths {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.discovered {
		return tomcat.Paths{Home: t.homePath, Base: t.basePath}
	}
	t.discovered = true

	// 1. Explicit init(home:, base:) always wins.
	home, base := "", ""
	if t.Home.IsSet() {
		home = t.Home.Data
	}
	if t.Base.IsSet() {
		base = t.Base.Data
	}

	if home == "" || base == "" {
		discoveredHome, discoveredBase := t.discoverInstallPaths()
		if home == "" {
			home = discoveredHome
		}
		if base == "" {
			base = discoveredBase
		}
	}

	// Catalina's own rule: a single-instance install has one directory playing
	// both roles, so whichever of the two is known stands in for the other.
	if home == "" {
		home = base
	}
	if base == "" {
		base = home
	}

	t.homePath = home
	t.basePath = base
	return tomcat.Paths{Home: home, Base: base}
}

// discoverInstallPaths walks the discovery order: the running Catalina
// process, then the places a distribution declares the paths, then the
// well-known layouts on disk.
//
// Every step after the first is filesystem-only on purpose. An installation
// scanned as a container image or a snapshot has no running JVM, and every
// field of this resource is readable without one — so the process steps
// contribute when they can and are skipped when they cannot.
func (t *mqlTomcat) discoverInstallPaths() (string, string) {
	conn, ok := t.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return "", ""
	}
	fs := conn.FileSystem()
	afs := &afero.Afero{Fs: fs}

	// 2. + 3. The environment and command line of a running Catalina process.
	home, base := t.pathsFromProcesses(afs)

	// 4. A systemd unit that runs Catalina, plus any EnvironmentFile it names.
	if home == "" || base == "" {
		unitHome, unitBase := tomcat.PathsFromSystemd(fs)
		home = firstNonEmpty(home, unitHome)
		base = firstNonEmpty(base, unitBase)
	}

	// 5. The distribution's own environment files, for packages whose unit
	// does not carry the paths directly.
	if home == "" || base == "" {
		cfgHome, cfgBase := tomcat.PathsFromEnvConfigs(fs)
		home = firstNonEmpty(home, cfgHome)
		base = firstNonEmpty(base, cfgBase)
	}

	// 6. Well-known layouts. An installation directory is recognized by its
	// jars, an instance directory by owning a conf/server.xml.
	if home == "" {
		home = tomcat.ProbeHome(fs)
	}
	if base == "" {
		base = tomcat.ProbeBase(fs, home)
	}

	// A multi-instance layout states which installation it belongs to in the
	// instance's own bin/setenv.sh, which is the only declaration left when
	// there is neither a running JVM nor a unit file.
	if home == "" || base == "" {
		setenvHome, setenvBase := tomcat.PathsFromSetenv(fs, base, home)
		home = firstNonEmpty(home, setenvHome)
		base = firstNonEmpty(base, setenvBase)
	}

	return home, base
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (t *mqlTomcat) pathsFromProcesses(afs *afero.Afero) (string, string) {
	raw, err := CreateResource(t.MqlRuntime, "processes", map[string]*llx.RawData{})
	if err != nil {
		return "", ""
	}
	procs, ok := raw.(*mqlProcesses)
	if !ok {
		return "", ""
	}
	list := procs.GetList()
	if list.Error != nil {
		return "", ""
	}

	for i := range list.Data {
		proc, ok := list.Data[i].(*mqlProcess)
		if !ok {
			continue
		}
		cmd := proc.GetCommand()
		if cmd.Error != nil || !tomcat.IsCatalinaCommand(cmd.Data) {
			continue
		}

		// The process environment is authoritative where it is readable.
		pid := proc.GetPid()
		if pid.Error == nil {
			environ, err := afs.ReadFile(path.Join("/proc", strconv.FormatInt(pid.Data, 10), "environ"))
			if err == nil {
				if home, base := tomcat.PathsFromEnviron(string(environ)); home != "" || base != "" {
					return home, base
				}
			}
		}

		if home, base := tomcat.PathsFromCommand(cmd.Data); home != "" || base != "" {
			return home, base
		}
	}

	return "", ""
}

func fileExistsOn(afs *afero.Afero, filePath string) bool {
	stat, err := afs.Stat(filePath)
	return err == nil && !stat.IsDir()
}

// confPath resolves a file under conf/ the way Catalina does: CATALINA_BASE
// owns instance configuration, CATALINA_HOME is the fallback. It returns the
// path that actually exists, or the empty string when neither does.
func (t *mqlTomcat) confPath(name string) string {
	conn, ok := t.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return ""
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}
	p := t.installPaths()

	candidates := []string{}
	if p.Base != "" {
		candidates = append(candidates, path.Join(p.Base, "conf", name))
	}
	if p.Home != "" && p.Home != p.Base {
		candidates = append(candidates, path.Join(p.Home, "conf", name))
	}

	for _, candidate := range candidates {
		if fileExistsOn(afs, candidate) {
			return candidate
		}
	}
	return ""
}

func (t *mqlTomcat) home() (string, error) {
	return t.installPaths().Home, nil
}

func (t *mqlTomcat) base() (string, error) {
	return t.installPaths().Base, nil
}

func (t *mqlTomcat) version() (string, error) {
	p := t.installPaths()
	if p.Home == "" {
		t.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}

	conn, ok := t.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		t.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}

	// RELEASE-NOTES states the version in plain text, which keeps this cheap.
	// The version recorded inside catalina.jar is deliberately not consulted:
	// cracking open an archive costs far more than the answer is worth.
	for _, dir := range []string{p.Home, p.Base} {
		if dir == "" {
			continue
		}
		content, err := afs.ReadFile(path.Join(dir, "RELEASE-NOTES"))
		if err != nil {
			continue
		}
		if version := tomcat.VersionFromReleaseNotes(string(content)); version != "" {
			return version, nil
		}
	}

	// An unpacked distribution keeps its version in the directory name.
	if version := tomcat.VersionFromInstallDir(p.Home); version != "" {
		return version, nil
	}

	// Distribution packages ship neither RELEASE-NOTES nor a versioned
	// directory, and the version they do record lives inside the jar. Report
	// nothing rather than guess; the packages resource knows the answer.
	//
	// Null rather than "", and for the same reason as the two paths above:
	// every route out of this method that could not determine a version says
	// so the same way. An empty string would be indistinguishable from a
	// version that really is empty, and a caller testing `version != ""`
	// would read "unknown" as "present but blank".
	t.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	return "", nil
}

// readFileResource creates a file resource for an absolute path and reads its
// content. The resource is returned as well so that each parsed configuration
// can expose the file it actually came from, which is what lets a permission
// or ownership check compose onto it.
func readFileResource(runtime *plugin.Runtime, filePath string) (*mqlFile, string, error) {
	raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(filePath),
	})
	if err != nil {
		return nil, "", err
	}
	f := raw.(*mqlFile)
	content := f.GetContent()
	if content.Error != nil {
		return f, "", content.Error
	}
	return f, content.Data, nil
}

func (t *mqlTomcat) server() (*mqlTomcatServer, error) {
	serverPath := t.confPath("server.xml")
	if serverPath == "" {
		t.Server = plugin.TValue[*mqlTomcatServer]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	f, content, err := readFileResource(t.MqlRuntime, serverPath)
	if err != nil {
		return nil, err
	}

	p := t.installPaths()
	parsed, err := tomcat.ParseServerXML([]byte(content), p)
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		t.Server = plugin.TValue[*mqlTomcatServer]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	return newTomcatServer(t.MqlRuntime, parsed, f, serverPath, p)
}

func (t *mqlTomcat) webXml() (*mqlTomcatWebxml, error) {
	webXmlPath := t.confPath("web.xml")
	if webXmlPath == "" {
		return nil, t.setWebXmlNull()
	}

	res, err := newTomcatWebxmlFromPath(t.MqlRuntime, webXmlPath)
	if err != nil {
		return nil, err
	}
	if res == nil {
		// The file is on disk but holds no descriptor — it is empty, or its
		// root is not <web-app>. That is a resolved answer of "nothing", and
		// the state has to say so; a bare nil leaves the field unresolved.
		return nil, t.setWebXmlNull()
	}
	return res, nil
}

func (t *mqlTomcat) setWebXmlNull() error {
	t.WebXml = plugin.TValue[*mqlTomcatWebxml]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}

func (t *mqlTomcat) context() (*mqlTomcatContext, error) {
	contextPath := t.confPath("context.xml")
	if contextPath == "" {
		return nil, t.setContextNull()
	}

	res, err := newTomcatContextFromPath(t.MqlRuntime, contextPath, t.installPaths())
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, t.setContextNull()
	}
	return res, nil
}

func (t *mqlTomcat) setContextNull() error {
	t.Context = plugin.TValue[*mqlTomcatContext]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}

func (t *mqlTomcat) properties() (map[string]any, error) {
	return t.readConfProperties("catalina.properties")
}

func (t *mqlTomcat) logging() (map[string]any, error) {
	return t.readConfProperties("logging.properties")
}

func (t *mqlTomcat) readConfProperties(name string) (map[string]any, error) {
	filePath := t.confPath(name)
	if filePath == "" {
		return map[string]any{}, nil
	}

	_, content, err := readFileResource(t.MqlRuntime, filePath)
	if err != nil {
		return nil, err
	}

	return propertiesToDict(tomcat.ParseProperties(content, t.installPaths())), nil
}

func propertiesToDict(props map[string]string) map[string]any {
	res := make(map[string]any, len(props))
	for k, v := range props {
		res[k] = v
	}
	return res
}

func (t *mqlTomcat) users() ([]any, error) {
	usersPath := t.confPath("tomcat-users.xml")
	if usersPath == "" {
		return []any{}, nil
	}

	_, content, err := readFileResource(t.MqlRuntime, usersPath)
	if err != nil {
		return nil, err
	}

	parsed, err := tomcat.ParseUsersXML([]byte(content))
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(parsed))
	for i := range parsed {
		user := parsed[i]
		obj, err := CreateResource(t.MqlRuntime, "tomcat.user", map[string]*llx.RawData{
			"__id":     llx.StringData(usersPath + "/user/" + user.Username),
			"username": llx.StringData(user.Username),
			"password": llx.StringData(user.Password),
			"roles":    llx.ArrayData(convert.SliceAnyToInterface(user.Roles), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}

	return res, nil
}

// webapps enumerates the applications deployed under each Host's appBase.
//
// Deriving the directories from the Hosts rather than searching the install
// tree keeps the directory boundary exact: a sibling directory whose name
// merely starts with the appBase (the sample applications a container image
// parks next to webapps/, for instance) is not an application and is not
// reported as one.
func (t *mqlTomcat) webapps() ([]any, error) {
	conn, ok := t.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return []any{}, nil
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}

	server := t.GetServer()
	if server.Error != nil || server.Data == nil {
		return []any{}, nil
	}

	p := t.installPaths()
	res := []any{}
	seen := map[string]struct{}{}

	for _, host := range collectHosts(server.Data) {
		appBaseDir := host.GetAppBaseDir().Data
		if appBaseDir == "" {
			continue
		}
		hostName := host.GetName().Data

		entries, err := afs.ReadDir(appBaseDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			// Only exploded applications are enumerated. An undeployed WAR is
			// an archive, and reading configuration out of archives is not
			// something this resource does.
			appPath := path.Join(appBaseDir, entry.Name())
			if !isWebappDir(afs, appPath, entry) {
				continue
			}
			if _, ok := seen[appPath]; ok {
				continue
			}
			seen[appPath] = struct{}{}

			obj, err := CreateResource(t.MqlRuntime, "tomcat.webapp", map[string]*llx.RawData{
				"__id": llx.StringData("tomcat.webapp/" + appPath),
				"name": llx.StringData(entry.Name()),
				"path": llx.StringData(appPath),
				"host": llx.StringData(hostName),
			})
			if err != nil {
				return nil, err
			}
			obj.(*mqlTomcatWebapp).paths = p
			res = append(res, obj)
		}
	}

	return res, nil
}

// isWebappDir reports whether an appBase entry is an application directory.
// Tomcat deploys a symlink to a directory like the directory itself (SUSE's
// webapps packages ship ROOT, manager and examples that way), but ReadDir on
// the local filesystem describes the link, not its target, so a link is
// followed with Stat.
func isWebappDir(fs afero.Fs, appPath string, entry os.FileInfo) bool {
	if entry.IsDir() {
		return true
	}
	if entry.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := fs.Stat(appPath)
	return err == nil && target.IsDir()
}

func collectHosts(server *mqlTomcatServer) []*mqlTomcatHost {
	res := []*mqlTomcatHost{}
	for _, rawService := range server.GetServices().Data {
		service, ok := rawService.(*mqlTomcatService)
		if !ok {
			continue
		}
		for _, rawEngine := range service.GetEngines().Data {
			engine, ok := rawEngine.(*mqlTomcatEngine)
			if !ok {
				continue
			}
			for _, rawHost := range engine.GetHosts().Data {
				if host, ok := rawHost.(*mqlTomcatHost); ok {
					res = append(res, host)
				}
			}
		}
	}
	return res
}

// fileOrNull renders the file a configuration was parsed from. A resource
// built as a stand-in for an installation that is not there has no file, and
// the field has to read as null rather than as a typed nil pointer.
func fileOrNull(f *mqlFile) *llx.RawData {
	if f == nil {
		return &llx.RawData{Type: types.Resource("file")}
	}
	return llx.ResourceData(f, "file")
}

// stringMap converts attributes to the map the runtime expects, and is
// non-nil even for an element that declared none — a null map would make
// `params` unusable rather than empty.
func stringMap(params map[string]string) map[string]any {
	res := make(map[string]any, len(params))
	for k, v := range params {
		res[k] = v
	}
	return res
}

func dictOrEmpty(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

// --- server.xml resource construction ---------------------------------------

func newTomcatServer(runtime *plugin.Runtime, srv *tomcat.Server, f *mqlFile, id string, paths tomcat.Paths) (*mqlTomcatServer, error) {
	listeners, err := newTomcatListeners(runtime, srv.Listeners, id)
	if err != nil {
		return nil, err
	}

	services := make([]any, 0, len(srv.Services))
	for i := range srv.Services {
		service := srv.Services[i]
		serviceID := id + "/service/" + strconv.Itoa(i) + "/" + service.Name

		connectors, err := newTomcatConnectors(runtime, service.Connectors, serviceID)
		if err != nil {
			return nil, err
		}
		engines, err := newTomcatEngines(runtime, service.Engines, serviceID, f, paths)
		if err != nil {
			return nil, err
		}

		obj, err := CreateResource(runtime, "tomcat.service", map[string]*llx.RawData{
			"__id":       llx.StringData(serviceID),
			"name":       llx.StringData(service.Name),
			"connectors": llx.ArrayData(connectors, types.Resource("tomcat.connector")),
			"engines":    llx.ArrayData(engines, types.Resource("tomcat.engine")),
		})
		if err != nil {
			return nil, err
		}
		services = append(services, obj)
	}

	raw, err := CreateResource(runtime, "tomcat.server", map[string]*llx.RawData{
		"__id":      llx.StringData(id),
		"file":      fileOrNull(f),
		"port":      llx.IntData(srv.Port),
		"shutdown":  llx.StringData(srv.Shutdown),
		"listeners": llx.ArrayData(listeners, types.Resource("tomcat.listener")),
		"services":  llx.ArrayData(services, types.Resource("tomcat.service")),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlTomcatServer), nil
}

func newTomcatListeners(runtime *plugin.Runtime, listeners []tomcat.Listener, ownerID string) ([]any, error) {
	res := make([]any, 0, len(listeners))
	for i := range listeners {
		listener := listeners[i]
		obj, err := CreateResource(runtime, "tomcat.listener", map[string]*llx.RawData{
			"__id":      llx.StringData(ownerID + "/listener/" + strconv.Itoa(i) + "/" + listener.ClassName),
			"className": llx.StringData(listener.ClassName),
			"params":    llx.MapData(stringMap(listener.Params), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func newTomcatConnectors(runtime *plugin.Runtime, connectors []tomcat.Connector, ownerID string) ([]any, error) {
	res := make([]any, 0, len(connectors))
	for i := range connectors {
		c := connectors[i]
		sslHostConfigs := make([]any, 0, len(c.SSLHostConfigs))
		for j := range c.SSLHostConfigs {
			sslHostConfigs = append(sslHostConfigs, c.SSLHostConfigs[j])
		}

		obj, err := CreateResource(runtime, "tomcat.connector", map[string]*llx.RawData{
			"__id":                llx.StringData(ownerID + "/connector/" + strconv.Itoa(i) + "/" + strconv.FormatInt(c.Port, 10)),
			"port":                llx.IntData(c.Port),
			"address":             llx.StringData(c.Address),
			"protocol":            llx.StringData(c.Protocol),
			"sslEnabled":          llx.BoolData(c.SSLEnabled),
			"scheme":              llx.StringData(c.Scheme),
			"secure":              llx.BoolData(c.Secure),
			"allowTrace":          llx.BoolData(c.AllowTrace),
			"xpoweredBy":          llx.BoolData(c.XPoweredBy),
			"enableLookups":       llx.BoolData(c.EnableLookups),
			"connectionTimeout":   llx.IntData(c.ConnectionTimeout),
			"maxHttpHeaderSize":   llx.IntData(c.MaxHTTPHeaderSize),
			"server":              llx.StringData(c.Server),
			"ciphers":             llx.StringData(c.Ciphers),
			"sslProtocol":         llx.StringData(c.SSLProtocol),
			"sslEnabledProtocols": llx.StringData(c.SSLEnabledProtocols),
			"clientAuth":          llx.StringData(c.ClientAuth),
			"sslHostConfigs":      llx.ArrayData(sslHostConfigs, types.Dict),
			"params":              llx.MapData(stringMap(c.Params), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func newTomcatEngines(runtime *plugin.Runtime, engines []tomcat.Engine, ownerID string, f *mqlFile, paths tomcat.Paths) ([]any, error) {
	res := make([]any, 0, len(engines))
	for i := range engines {
		engine := engines[i]
		engineID := ownerID + "/engine/" + strconv.Itoa(i) + "/" + engine.Name

		hosts, err := newTomcatHosts(runtime, engine.Hosts, engineID, f, paths)
		if err != nil {
			return nil, err
		}
		realms, err := newTomcatRealms(runtime, engine.Realms, engineID)
		if err != nil {
			return nil, err
		}
		valves, err := newTomcatValves(runtime, engine.Valves, engineID)
		if err != nil {
			return nil, err
		}

		obj, err := CreateResource(runtime, "tomcat.engine", map[string]*llx.RawData{
			"__id":        llx.StringData(engineID),
			"name":        llx.StringData(engine.Name),
			"defaultHost": llx.StringData(engine.DefaultHost),
			"hosts":       llx.ArrayData(hosts, types.Resource("tomcat.host")),
			"realms":      llx.ArrayData(realms, types.Resource("tomcat.realm")),
			"valves":      llx.ArrayData(valves, types.Resource("tomcat.valve")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func newTomcatHosts(runtime *plugin.Runtime, hosts []tomcat.Host, ownerID string, f *mqlFile, paths tomcat.Paths) ([]any, error) {
	res := make([]any, 0, len(hosts))
	for i := range hosts {
		host := hosts[i]
		hostID := ownerID + "/host/" + strconv.Itoa(i) + "/" + host.Name

		valves, err := newTomcatValves(runtime, host.Valves, hostID)
		if err != nil {
			return nil, err
		}
		contexts, err := newTomcatContexts(runtime, host.Contexts, hostID, f, paths)
		if err != nil {
			return nil, err
		}

		obj, err := CreateResource(runtime, "tomcat.host", map[string]*llx.RawData{
			"__id":            llx.StringData(hostID),
			"name":            llx.StringData(host.Name),
			"appBase":         llx.StringData(host.AppBase),
			"appBaseDir":      llx.StringData(resolveAppBase(host.AppBase, paths)),
			"autoDeploy":      llx.BoolData(host.AutoDeploy),
			"deployOnStartup": llx.BoolData(host.DeployOnStartup),
			"deployXML":       llx.BoolData(host.DeployXML),
			"unpackWARs":      llx.BoolData(host.UnpackWARs),
			"valves":          llx.ArrayData(valves, types.Resource("tomcat.valve")),
			"contexts":        llx.ArrayData(contexts, types.Resource("tomcat.context")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

// resolveAppBase turns a Host's appBase into an absolute directory. Tomcat
// resolves a relative appBase against CATALINA_BASE.
func resolveAppBase(appBase string, paths tomcat.Paths) string {
	appBase = paths.Expand(appBase)
	if appBase == "" {
		return ""
	}
	if path.IsAbs(appBase) {
		return path.Clean(appBase)
	}
	if paths.Base == "" {
		return ""
	}
	return path.Join(paths.Base, appBase)
}

func newTomcatValves(runtime *plugin.Runtime, valves []tomcat.Valve, ownerID string) ([]any, error) {
	res := make([]any, 0, len(valves))
	for i := range valves {
		valve := valves[i]
		obj, err := CreateResource(runtime, "tomcat.valve", map[string]*llx.RawData{
			"__id":           llx.StringData(ownerID + "/valve/" + strconv.Itoa(i) + "/" + valve.ClassName),
			"className":      llx.StringData(valve.ClassName),
			"pattern":        llx.StringData(valve.Pattern),
			"directory":      llx.StringData(valve.Directory),
			"prefix":         llx.StringData(valve.Prefix),
			"suffix":         llx.StringData(valve.Suffix),
			"showServerInfo": llx.BoolData(valve.ShowServerInfo),
			"showReport":     llx.BoolData(valve.ShowReport),
			"allow":          llx.StringData(valve.Allow),
			"deny":           llx.StringData(valve.Deny),
			"params":         llx.MapData(stringMap(valve.Params), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func newTomcatRealms(runtime *plugin.Runtime, realms []tomcat.Realm, ownerID string) ([]any, error) {
	res := make([]any, 0, len(realms))
	for i := range realms {
		realm := realms[i]
		realmID := ownerID + "/realm/" + strconv.Itoa(i) + "/" + realm.ClassName

		nested, err := newTomcatRealms(runtime, realm.Realms, realmID)
		if err != nil {
			return nil, err
		}

		handlers := make([]any, 0, len(realm.CredentialHandlers))
		for j := range realm.CredentialHandlers {
			handlers = append(handlers, realm.CredentialHandlers[j])
		}

		obj, err := CreateResource(runtime, "tomcat.realm", map[string]*llx.RawData{
			"__id":               llx.StringData(realmID),
			"className":          llx.StringData(realm.ClassName),
			"digest":             llx.StringData(realm.Digest),
			"connectionURL":      llx.StringData(realm.ConnectionURL),
			"failureCount":       llx.IntData(realm.FailureCount),
			"lockOutTime":        llx.IntData(realm.LockOutTime),
			"realms":             llx.ArrayData(nested, types.Resource("tomcat.realm")),
			"credentialHandlers": llx.ArrayData(handlers, types.Dict),
			"params":             llx.MapData(stringMap(realm.Params), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func newTomcatContexts(runtime *plugin.Runtime, contexts []tomcat.Context, ownerID string, f *mqlFile, paths tomcat.Paths) ([]any, error) {
	res := make([]any, 0, len(contexts))
	for i := range contexts {
		ctx := contexts[i]
		obj, err := newTomcatContext(runtime, &ctx, f, ownerID+"/context/"+strconv.Itoa(i)+"/"+ctx.Path)
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func newTomcatContext(runtime *plugin.Runtime, ctx *tomcat.Context, f *mqlFile, id string) (*mqlTomcatContext, error) {
	valves, err := newTomcatValves(runtime, ctx.Valves, id)
	if err != nil {
		return nil, err
	}

	raw, err := CreateResource(runtime, "tomcat.context", map[string]*llx.RawData{
		"__id":               llx.StringData(id),
		"file":               fileOrNull(f),
		"path":               llx.StringData(ctx.Path),
		"privileged":         llx.BoolData(ctx.Privileged),
		"crossContext":       llx.BoolData(ctx.CrossContext),
		"logEffectiveWebXml": llx.BoolData(ctx.LogEffectiveWebXml),
		"allowLinking":       llx.BoolData(ctx.AllowLinking),
		"valves":             llx.ArrayData(valves, types.Resource("tomcat.valve")),
		"params":             llx.MapData(stringMap(ctx.Params), types.String),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlTomcatContext), nil
}

func newTomcatContextFromPath(runtime *plugin.Runtime, filePath string, paths tomcat.Paths) (*mqlTomcatContext, error) {
	f, content, err := readFileResource(runtime, filePath)
	if err != nil {
		return nil, err
	}

	parsed, err := tomcat.ParseContextXML([]byte(content), paths)
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, nil
	}

	return newTomcatContext(runtime, parsed, f, filePath)
}

func newTomcatWebxmlFromPath(runtime *plugin.Runtime, filePath string) (*mqlTomcatWebxml, error) {
	f, content, err := readFileResource(runtime, filePath)
	if err != nil {
		return nil, err
	}

	parsed, err := tomcat.ParseWebXML([]byte(content))
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, nil
	}

	return newTomcatWebxml(runtime, parsed, f, filePath)
}

func newTomcatWebxml(runtime *plugin.Runtime, parsed *tomcat.WebXML, f *mqlFile, id string) (*mqlTomcatWebxml, error) {
	errorPages := make([]any, 0, len(parsed.ErrorPages))
	for i := range parsed.ErrorPages {
		errorPages = append(errorPages, parsed.ErrorPages[i])
	}
	securityConstraints := make([]any, 0, len(parsed.SecurityConstraints))
	for i := range parsed.SecurityConstraints {
		securityConstraints = append(securityConstraints, parsed.SecurityConstraints[i])
	}
	servlets := make([]any, 0, len(parsed.Servlets))
	for i := range parsed.Servlets {
		servlets = append(servlets, parsed.Servlets[i])
	}
	filters := make([]any, 0, len(parsed.Filters))
	for i := range parsed.Filters {
		filters = append(filters, parsed.Filters[i])
	}

	raw, err := CreateResource(runtime, "tomcat.webxml", map[string]*llx.RawData{
		"__id":                llx.StringData(id),
		"file":                fileOrNull(f),
		"metadataComplete":    llx.BoolData(parsed.MetadataComplete),
		"errorPages":          llx.ArrayData(errorPages, types.Dict),
		"securityConstraints": llx.ArrayData(securityConstraints, types.Dict),
		"loginConfig":         llx.DictData(dictOrEmpty(parsed.LoginConfig)),
		"sessionTimeout":      llx.IntData(parsed.SessionTimeout),
		"cookieHttpOnly":      llx.BoolData(parsed.CookieHTTPOnly),
		"cookieSecure":        llx.BoolData(parsed.CookieSecure),
		"servlets":            llx.ArrayData(servlets, types.Dict),
		"filters":             llx.ArrayData(filters, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlTomcatWebxml), nil
}

// --- webapp -----------------------------------------------------------------

func (w *mqlTomcatWebapp) context() (*mqlTomcatContext, error) {
	filePath := path.Join(w.Path.Data, "META-INF", "context.xml")
	if !w.exists(filePath) {
		return nil, w.setContextNull()
	}

	res, err := newTomcatContextFromPath(w.MqlRuntime, filePath, w.paths)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, w.setContextNull()
	}
	return res, nil
}

func (w *mqlTomcatWebapp) setContextNull() error {
	w.Context = plugin.TValue[*mqlTomcatContext]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}

func (w *mqlTomcatWebapp) webXml() (*mqlTomcatWebxml, error) {
	filePath := path.Join(w.Path.Data, "WEB-INF", "web.xml")
	if !w.exists(filePath) {
		return nil, w.setWebXmlNull()
	}

	res, err := newTomcatWebxmlFromPath(w.MqlRuntime, filePath)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, w.setWebXmlNull()
	}
	return res, nil
}

func (w *mqlTomcatWebapp) setWebXmlNull() error {
	w.WebXml = plugin.TValue[*mqlTomcatWebxml]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}

func (w *mqlTomcatWebapp) logging() (map[string]any, error) {
	filePath := path.Join(w.Path.Data, "WEB-INF", "classes", "logging.properties")
	if !w.exists(filePath) {
		return map[string]any{}, nil
	}

	_, content, err := readFileResource(w.MqlRuntime, filePath)
	if err != nil {
		return nil, err
	}
	return propertiesToDict(tomcat.ParseProperties(content, w.paths)), nil
}

func (w *mqlTomcatWebapp) exists(filePath string) bool {
	conn, ok := w.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return false
	}
	return fileExistsOn(&afero.Afero{Fs: conn.FileSystem()}, filePath)
}
