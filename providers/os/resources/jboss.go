// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/jboss"
	"go.mondoo.com/mql/types"
)

type mqlJbossInternal struct {
	lock       sync.Mutex
	discovered bool
	homePath   string
	serverMode string
	// configName is the configuration file the server is started with, as a
	// bare file name.
	configName string
	// hostConfigName is the host controller configuration of a managed domain.
	hostConfigName string

	// The product identity is read by two fields and costs a directory walk,
	// so it is resolved once.
	identityOnce sync.Once
	productName  string
	productVer   string
}

func initJboss(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	for _, key := range []string{"home", "configFile"} {
		if x, ok := args[key]; ok {
			if _, ok := x.Value.(string); !ok {
				return nil, nil, errors.New("wrong type for '" + key + "' in jboss initialization, it must be a string")
			}
		}
	}
	return args, nil, nil
}

// The resource names jboss.config and jboss.management collide with the jboss
// fields of the same name: writing `jboss.config.management` resolves to the
// *resource* rather than to the `config` field of `jboss`. These init
// functions make both spellings mean the same thing by handing back the
// instance the jboss resource already built.

func initJbossConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	installation, err := jbossInstallation(runtime)
	if err != nil {
		return nil, nil, err
	}
	config := installation.GetConfig()
	if config.Error != nil {
		return nil, nil, config.Error
	}
	if config.Data == nil {
		// No installation, or no configuration in it. An empty document built
		// through the same constructor keeps `jboss.config.profiles` an empty
		// list rather than an error, and cannot drift out of step with the
		// resource's fields the way a hand-written argument list would.
		res, err := newJbossConfig(runtime, &jboss.Document{}, nil, "jboss.config", "")
		if err != nil {
			return nil, nil, err
		}
		return args, res, nil
	}
	return args, config.Data, nil
}

func initJbossManagement(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	installation, err := jbossInstallation(runtime)
	if err != nil {
		return nil, nil, err
	}
	management := installation.GetManagement()
	if management.Error != nil {
		return nil, nil, management.Error
	}
	if management.Data == nil {
		// newJbossManagement answers (nil, nil) for a nil Management, so
		// calling it with one handed back a nil *mqlJbossManagement as the
		// resource. Inside the plugin.Resource interface that pointer is not
		// == nil, so the caller took it for a resource and dereferenced it
		// reading its id, panicking the provider and failing the scan.
		//
		// A host with no management configuration has no such resource, and
		// saying so beats a blank one whose every field reads null with
		// nothing to attribute it to.
		return nil, nil, errors.New("jboss.management not found: this installation declares no management configuration")
	}
	return args, management.Data, nil
}

func jbossInstallation(runtime *plugin.Runtime) (*mqlJboss, error) {
	raw, err := CreateResource(runtime, "jboss", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJboss), nil
}

func (j *mqlJboss) id() (string, error) {
	home := j.install().home
	if home == "" {
		return "jboss", nil
	}
	return "jboss/" + home, nil
}

// jbossInstall is everything the discovery resolves once and every other field
// on the resource reads.
type jbossInstall struct {
	home       string
	launchType string
	configName string
	hostConfig string
}

func (j *mqlJboss) install() jbossInstall {
	j.lock.Lock()
	defer j.lock.Unlock()

	if j.discovered {
		return jbossInstall{
			home:       j.homePath,
			launchType: j.serverMode,
			configName: j.configName,
			hostConfig: j.hostConfigName,
		}
	}
	j.discovered = true

	// Explicit init(home:) always wins.
	home := ""
	if j.Home.IsSet() {
		home = j.Home.Data
	}

	observed := j.discover()
	if home == "" {
		home = observed.home
	}

	launchType := observed.launchType
	if launchType == "" {
		launchType = jboss.LaunchTypeFromDisk(j.fs(), home)
	}
	if launchType == "" && home != "" {
		// Nothing was running, no unit file said so, and the installation
		// carries both trees. A JBoss installation runs standalone unless it
		// is deliberately started with domain.sh, so that is the assumption —
		// stated here rather than hidden, and overridable through `configs`,
		// which lists every configuration the installation carries.
		launchType = "standalone"
	}

	// --domain-config names the configuration of a managed domain and
	// --server-config that of a standalone server. Reading one in the other's
	// mode would parse a document the server never loaded.
	configName := observed.serverConfig
	if launchType == "domain" {
		configName = observed.domainConfig
	}
	if configName == "" {
		configName = "standalone.xml"
		if launchType == "domain" {
			configName = "domain.xml"
		}
	}

	hostConfig := observed.hostConfig
	if hostConfig == "" {
		hostConfig = "host.xml"
	}

	// An explicit init(configFile:) overrides the discovered selection.
	if j.ConfigFile.IsSet() && j.ConfigFile.Data != "" {
		configName = j.ConfigFile.Data
	}

	j.homePath = home
	j.serverMode = launchType
	j.configName = configName
	j.hostConfigName = hostConfig

	return jbossInstall{home: home, launchType: launchType, configName: configName, hostConfig: hostConfig}
}

func (j *mqlJboss) fs() afero.Fs {
	conn, ok := j.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return afero.NewMemMapFs()
	}
	return conn.FileSystem()
}

// discover walks the discovery order: the running JBoss process, then the
// places a distribution declares JBOSS_HOME, then the well-known layouts.
//
// Every step after the first is filesystem-only on purpose. An installation
// scanned as a container image or a snapshot has no running JVM, and every
// field of this resource is readable without one — so the process steps
// contribute when they can and are skipped when they cannot.
func (j *mqlJboss) discover() observedInstall {
	fs := j.fs()
	afs := &afero.Afero{Fs: fs}

	// 1. The command line and environment of a running JBoss process.
	res := j.pathsFromProcesses(afs)

	// 2. A systemd unit that runs JBoss, plus any EnvironmentFile it names.
	if res.home == "" || res.launchType == "" {
		unitHome, unitLaunch := jboss.PathsFromSystemd(fs)
		if res.home == "" {
			res.home = unitHome
		}
		if res.launchType == "" {
			res.launchType = unitLaunch
		}
	}

	// 3. The distribution's own environment files.
	if res.home == "" {
		res.home = jboss.HomeFromEnvConfigs(fs)
	}

	// 4. Well-known layouts, recognized by the module loader the server boots
	// through rather than by the directory name.
	if res.home == "" {
		res.home = jboss.ProbeHome(fs)
	}

	return res
}

// observedInstall is what the discovery could actually observe, before any
// fallback is applied.
type observedInstall struct {
	home         string
	launchType   string
	serverConfig string
	domainConfig string
	hostConfig   string
}

func (j *mqlJboss) pathsFromProcesses(afs *afero.Afero) observedInstall {
	res := observedInstall{}

	raw, err := CreateResource(j.MqlRuntime, "processes", map[string]*llx.RawData{})
	if err != nil {
		return res
	}
	procs, ok := raw.(*mqlProcesses)
	if !ok {
		return res
	}
	list := procs.GetList()
	if list.Error != nil {
		return res
	}

	for i := range list.Data {
		proc, ok := list.Data[i].(*mqlProcess)
		if !ok {
			continue
		}
		cmd := proc.GetCommand()
		if cmd.Error != nil || !jboss.IsJBossCommand(cmd.Data) {
			continue
		}

		if res.home == "" {
			res.home = jboss.HomeFromCommand(cmd.Data)
		}
		if res.home == "" {
			// The process environment is authoritative where it is readable.
			if pid := proc.GetPid(); pid.Error == nil {
				environ, err := afs.ReadFile(path.Join("/proc", strconv.FormatInt(pid.Data, 10), "environ"))
				if err == nil {
					res.home = jboss.HomeFromEnviron(string(environ))
				}
			}
		}

		// A managed domain runs several JBoss processes at once and the
		// managed servers themselves look standalone, so a domain answer from
		// any one of them outranks a standalone answer from another.
		if lt := jboss.LaunchTypeFromCommand(cmd.Data); lt != "" && (res.launchType == "" || lt == "domain") {
			res.launchType = lt
		}

		server, domain, host := jboss.ConfigFromCommand(cmd.Data)
		if res.serverConfig == "" {
			res.serverConfig = server
		}
		if res.domainConfig == "" {
			res.domainConfig = domain
		}
		if res.hostConfig == "" {
			res.hostConfig = host
		}
	}

	return res
}

// --- installation fields -----------------------------------------------------

func (j *mqlJboss) home() (string, error) {
	home := j.install().home
	if home == "" {
		j.Home = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return home, nil
}

func (j *mqlJboss) configFile() (string, error) {
	if j.install().home == "" {
		j.ConfigFile = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return j.install().configName, nil
}

func (j *mqlJboss) launchType() (string, error) {
	lt := j.install().launchType
	if lt == "" {
		j.LaunchType = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return lt, nil
}

func (j *mqlJboss) product() (string, error) {
	product, _ := j.productVersion()
	if product == "" {
		j.Product = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return product, nil
}

func (j *mqlJboss) version() (string, error) {
	_, version := j.productVersion()
	if version == "" {
		j.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return version, nil
}

// productVersion reads the product identity off disk.
//
// Four sources, cheapest first: version.txt, which every Red Hat build ships;
// the MANIFEST.MF of a product module, which a layered product writes instead;
// the file name of the version module, which is all a community WildFly has;
// and the name of the unpacked directory as the last resort.
//
// The version recorded *inside* the jars is deliberately not consulted —
// cracking open an archive costs far more than the answer is worth, and the
// file name of that same jar already carries it.
func (j *mqlJboss) productVersion() (string, string) {
	j.identityOnce.Do(func() {
		j.productName, j.productVer = j.readProductVersion()
	})
	return j.productName, j.productVer
}

func (j *mqlJboss) readProductVersion() (string, string) {
	home := j.install().home
	if home == "" {
		return "", ""
	}
	afs := &afero.Afero{Fs: j.fs()}

	if content, err := afs.ReadFile(path.Join(home, "version.txt")); err == nil {
		if product, version := jboss.ParseVersionFile(string(content)); version != "" {
			return product, version
		}
	}

	manifests, err := afero.Glob(afs, path.Join(home, "modules/system/layers/base/org/jboss/as/product/*/dir/META-INF/MANIFEST.MF"))
	if err == nil {
		for _, manifest := range manifests {
			content, err := afs.ReadFile(manifest)
			if err != nil {
				continue
			}
			if product, version := jboss.ParseProductManifest(string(content)); version != "" {
				return product, version
			}
		}
	}

	if jars, err := afero.Glob(afs, path.Join(home, jboss.VersionJarGlob)); err == nil {
		if product, version := jboss.ProductVersionFromJars(jars); version != "" {
			return product, version
		}
	}

	return "", jboss.VersionFromInstallDir(home)
}

func (j *mqlJboss) baseDir() (string, error) {
	install := j.install()
	if install.home == "" || install.launchType == "" {
		j.BaseDir = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return path.Join(install.home, install.launchType), nil
}

func (j *mqlJboss) configDir() (string, error) {
	return j.modeDir("configuration", func(v plugin.TValue[string]) { j.ConfigDir = v })
}

func (j *mqlJboss) logDir() (string, error) {
	return j.modeDir("log", func(v plugin.TValue[string]) { j.LogDir = v })
}

func (j *mqlJboss) dataDir() (string, error) {
	return j.modeDir("data", func(v plugin.TValue[string]) { j.DataDir = v })
}

func (j *mqlJboss) deploymentDir() (string, error) {
	install := j.install()
	if install.launchType == "domain" {
		// A managed domain has no deployment scanner: content is pushed
		// through the domain controller's repository instead. Reporting the
		// standalone path here would name a directory that has no role.
		j.DeploymentDir = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return j.modeDir("deployments", func(v plugin.TValue[string]) { j.DeploymentDir = v })
}

func (j *mqlJboss) modeDir(name string, setNull func(plugin.TValue[string])) (string, error) {
	install := j.install()
	if install.home == "" || install.launchType == "" {
		setNull(plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull})
		return "", nil
	}
	return path.Join(install.home, install.launchType, name), nil
}

func (j *mqlJboss) vaultDir() (string, error) {
	home := j.install().home
	if home == "" {
		j.VaultDir = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return path.Join(home, "vault"), nil
}

// --- configuration documents -------------------------------------------------

func (j *mqlJboss) config() (*mqlJbossConfig, error) {
	install := j.install()
	dir, ok := j.configDirPath()
	if !ok {
		j.Config = plugin.TValue[*mqlJbossConfig]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	configPath := install.configName
	if !strings.HasPrefix(configPath, "/") {
		configPath = path.Join(dir, configPath)
	}

	res, err := j.readConfig(configPath)
	if err != nil {
		return nil, err
	}
	if res == nil {
		j.Config = plugin.TValue[*mqlJbossConfig]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return res, nil
}

func (j *mqlJboss) host() (*mqlJbossConfig, error) {
	install := j.install()
	if install.home == "" {
		j.Host = plugin.TValue[*mqlJbossConfig]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	res, err := j.readConfig(path.Join(install.home, "domain", "configuration", install.hostConfig))
	if err != nil {
		return nil, err
	}
	if res == nil {
		j.Host = plugin.TValue[*mqlJbossConfig]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return res, nil
}

// configs lists every configuration document in the configuration directory.
//
// The four standalone profiles a JBoss installation ships all sit there and
// only one of them is live, so a requirement that has to hold no matter which
// profile is selected is asserted over this list.
func (j *mqlJboss) configs() ([]any, error) {
	setNull := func() {
		j.Configs = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	dir, ok := j.configDirPath()
	if !ok {
		// No installation was found, which is not the same as an installation
		// that carries no configuration. An empty list would make `.all(...)`
		// vacuously true on an asset that has no JBoss on it at all.
		setNull()
		return nil, nil
	}

	afs := &afero.Afero{Fs: j.fs()}
	entries, err := afs.ReadDir(dir)
	if err != nil {
		setNull()
		return nil, nil
	}

	names := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".xml") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	res := []any{}
	for _, name := range names {
		config, err := j.readConfig(path.Join(dir, name))
		if err != nil {
			return nil, err
		}
		// A document whose root is not one of the three JBoss roots is not a
		// server configuration — the configuration directory also holds
		// unrelated XML on some layouts — and is left out rather than reported
		// as an empty configuration.
		if config == nil {
			continue
		}
		res = append(res, config)
	}
	return res, nil
}

func (j *mqlJboss) configDirPath() (string, bool) {
	install := j.install()
	if install.home == "" || install.launchType == "" {
		return "", false
	}
	return path.Join(install.home, install.launchType, "configuration"), true
}

// readConfig parses a configuration document, returning nil when the file is
// absent or is not a JBoss server configuration.
func (j *mqlJboss) readConfig(configPath string) (*mqlJbossConfig, error) {
	afs := &afero.Afero{Fs: j.fs()}
	if stat, err := afs.Stat(configPath); err != nil || stat.IsDir() {
		return nil, nil
	}

	f, content, err := readFileResource(j.MqlRuntime, configPath)
	if err != nil {
		return nil, err
	}

	doc, err := jboss.ParseDocument([]byte(content))
	if err != nil {
		// A configuration that does not parse is reported as absent rather
		// than as an error: the configuration directory of a live server also
		// holds the history JBoss writes on every change, and one unreadable
		// document must not take down every check on the asset.
		return nil, nil
	}
	switch doc.Mode() {
	case "server", "domain", "host":
	default:
		return nil, nil
	}

	return newJbossConfig(j.MqlRuntime, doc, f, configPath, path.Base(configPath))
}

// management returns the management section that governs the installation.
//
// Standalone mode declares it in the server profile and a managed domain in
// host.xml, because that is where each of them carries the management
// interfaces, the security realms and the audit log. domain.xml has a
// <management> section too, but it holds only access control.
func (j *mqlJboss) management() (*mqlJbossManagement, error) {
	setNull := func() {
		j.Management = plugin.TValue[*mqlJbossManagement]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	var owner *plugin.TValue[*mqlJbossConfig]
	if j.install().launchType == "domain" {
		owner = j.GetHost()
	} else {
		owner = j.GetConfig()
	}
	if owner.Error != nil {
		return nil, owner.Error
	}
	if owner.Data == nil {
		setNull()
		return nil, nil
	}

	management := owner.Data.GetManagement()
	if management.Error != nil {
		return nil, management.Error
	}
	if management.Data == nil {
		setNull()
		return nil, nil
	}
	return management.Data, nil
}

// --- realm users -------------------------------------------------------------

func (j *mqlJboss) managementUsers() ([]any, error) {
	res, ok, err := j.realmUsers("ManagementRealm", "mgmt-users.properties", "mgmt-groups.properties")
	if err != nil {
		return nil, err
	}
	if !ok {
		j.ManagementUsers = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return res, nil
}

func (j *mqlJboss) applicationUsers() ([]any, error) {
	res, ok, err := j.realmUsers("ApplicationRealm", "application-users.properties", "application-roles.properties")
	if err != nil {
		return nil, err
	}
	if !ok {
		j.ApplicationUsers = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return res, nil
}

// realmUsers reads a realm's users file, preferring the path the realm itself
// declares over the conventional file name.
//
// The second return value is false when there is no file to read, which is not
// the same as a file that declares no users: a stock installation ships an
// empty mgmt-users.properties, and that really is a realm with no users.
func (j *mqlJboss) realmUsers(realm string, defaultUsers string, defaultRoles string) ([]any, bool, error) {
	dir, ok := j.configDirPath()
	if !ok {
		return nil, false, nil
	}

	usersName, rolesName := defaultUsers, defaultRoles
	if declared := j.declaredPropertiesPath(realm); declared != "" {
		usersName = declared
	}

	afs := &afero.Afero{Fs: j.fs()}
	usersPath := resolveConfigPath(dir, usersName)
	usersContent, err := afs.ReadFile(usersPath)
	if err != nil {
		return nil, false, nil
	}

	rolesContent, err := afs.ReadFile(resolveConfigPath(dir, rolesName))
	if err != nil {
		rolesContent = nil
	}

	f, _, err := readFileResource(j.MqlRuntime, usersPath)
	if err != nil {
		return nil, false, err
	}

	res := []any{}
	for _, user := range jboss.ParseUsers(string(usersContent), string(rolesContent)) {
		obj, err := CreateResource(j.MqlRuntime, "jboss.user", map[string]*llx.RawData{
			"__id":        llx.StringData(usersPath + "/user/" + user.Username),
			"username":    llx.StringData(user.Username),
			"realm":       llx.StringData(realm),
			"file":        fileOrNull(f),
			"roles":       llx.ArrayData(convert.SliceAnyToInterface(user.Roles), types.String),
			"hasPassword": llx.BoolData(user.HasPassword),
		})
		if err != nil {
			return nil, false, err
		}
		res = append(res, obj)
	}
	return res, true, nil
}

// declaredPropertiesPath returns the users file a realm names, so that an
// installation that renamed it is still read.
func (j *mqlJboss) declaredPropertiesPath(realm string) string {
	management := j.GetManagement()
	if management.Error != nil || management.Data == nil {
		return ""
	}
	realms := management.Data.GetSecurityRealms()
	if realms.Error != nil {
		return ""
	}
	for _, raw := range realms.Data {
		r, ok := raw.(*mqlJbossSecurityRealm)
		if !ok || r.GetName().Data != realm {
			continue
		}
		auth := r.GetAuthentication()
		if auth.Error != nil || auth.Data == nil {
			return ""
		}
		return auth.Data.GetPropertiesPath().Data
	}
	return ""
}

func resolveConfigPath(dir string, name string) string {
	if strings.HasPrefix(name, "/") {
		return name
	}
	return path.Join(dir, name)
}

// --- startup configuration ---------------------------------------------------

func (j *mqlJboss) startupScript() (*mqlFile, error) {
	f := j.binFile(j.install().launchType + ".sh")
	if f == nil {
		j.StartupScript = plugin.TValue[*mqlFile]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return f, nil
}

func (j *mqlJboss) startupConfig() (*mqlFile, error) {
	f := j.binFile(j.install().launchType + ".conf")
	if f == nil {
		j.StartupConfig = plugin.TValue[*mqlFile]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return f, nil
}

// binFile builds a file resource for a file under the installation's bin/
// directory, or nil when the installation or the file is not there.
func (j *mqlJboss) binFile(name string) *mqlFile {
	install := j.install()
	if install.home == "" || install.launchType == "" {
		return nil
	}
	filePath := path.Join(install.home, "bin", name)
	afs := &afero.Afero{Fs: j.fs()}
	if stat, err := afs.Stat(filePath); err != nil || stat.IsDir() {
		return nil
	}
	raw, err := CreateResource(j.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(filePath),
	})
	if err != nil {
		return nil
	}
	return raw.(*mqlFile)
}

func (j *mqlJboss) javaOpts() ([]any, error) {
	cfg, ok := j.startupSettings()
	if !ok {
		j.JavaOpts = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return convert.SliceAnyToInterface(cfg.JavaOpts), nil
}

func (j *mqlJboss) securityManagerEnabled() (bool, error) {
	cfg, ok := j.startupSettings()
	if !ok {
		j.SecurityManagerEnabled = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return cfg.SecurityManager, nil
}

func (j *mqlJboss) securityPolicy() (string, error) {
	cfg, ok := j.startupSettings()
	if !ok || cfg.SecurityPolicy == "" {
		j.SecurityPolicy = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return cfg.SecurityPolicy, nil
}

// startupSettings reads bin/standalone.conf or bin/domain.conf.
//
// The second return value is false when the file could not be read at all,
// which is not the same as a file that turns nothing on: an installation
// whose startup configuration is missing cannot be said to have the Security
// Manager off, and every field that depends on it reports null instead.
func (j *mqlJboss) startupSettings() (jboss.StartupConfig, bool) {
	install := j.install()
	if install.home == "" || install.launchType == "" {
		return jboss.StartupConfig{}, false
	}
	afs := &afero.Afero{Fs: j.fs()}
	content, err := afs.ReadFile(path.Join(install.home, "bin", install.launchType+".conf"))
	if err != nil {
		return jboss.StartupConfig{}, false
	}
	return jboss.ParseStartupConfig(string(content)), true
}

// --- document resource construction ------------------------------------------

func newJbossConfig(runtime *plugin.Runtime, doc *jboss.Document, f *mqlFile, id string, name string) (*mqlJbossConfig, error) {
	management, err := newJbossManagement(runtime, doc.Management, id)
	if err != nil {
		return nil, err
	}

	profiles, err := newJbossProfiles(runtime, doc.AllProfiles(), id)
	if err != nil {
		return nil, err
	}

	interfaces, err := newJbossInterfaces(runtime, doc.Interfaces, id)
	if err != nil {
		return nil, err
	}

	socketGroups, err := newJbossSocketBindingGroups(runtime, doc.AllSocketBindingGroups(), id)
	if err != nil {
		return nil, err
	}

	vault, err := newJbossVault(runtime, doc.Vault, id)
	if err != nil {
		return nil, err
	}

	deployments := make([]any, 0, len(doc.Deployments))
	for i := range doc.Deployments {
		attrs := jboss.AttrMap(doc.Deployments[i].Attrs)
		deployments = append(deployments, map[string]any{
			"name":        attrs["name"],
			"runtimeName": attrs["runtime-name"],
			"enabled":     jboss.AttrBool(doc.Deployments[i].Attrs, "enabled", true),
		})
	}

	serverGroups := make([]any, 0, len(doc.ServerGroups))
	for i := range doc.ServerGroups {
		group := doc.ServerGroups[i]
		attrs := jboss.AttrMap(group.Attrs)
		socket := group.SocketBindingAttrs()
		serverGroups = append(serverGroups, map[string]any{
			"name":               attrs["name"],
			"profile":            attrs["profile"],
			"socketBindingGroup": socket["ref"],
			"portOffset":         socket["port-offset"],
		})
	}

	servers := make([]any, 0, len(doc.HostServers))
	for i := range doc.HostServers {
		server := doc.HostServers[i]
		attrs := jboss.AttrMap(server.Attrs)
		portOffset := ""
		if server.SocketBindings != nil {
			portOffset = jboss.Attr(server.SocketBindings.Attrs, "port-offset")
		}
		servers = append(servers, map[string]any{
			"name":       attrs["name"],
			"group":      attrs["group"],
			"autoStart":  jboss.AttrBool(server.Attrs, "auto-start", true),
			"portOffset": portOffset,
		})
	}

	extensions := make([]string, 0, len(doc.Extensions))
	for i := range doc.Extensions {
		extensions = append(extensions, doc.Extensions[i].Module)
	}

	systemProperties := make(map[string]any, len(doc.SystemProperties))
	for i := range doc.SystemProperties {
		systemProperties[doc.SystemProperties[i].Name] = doc.SystemProperties[i].Value
	}

	raw, err := CreateResource(runtime, "jboss.config", map[string]*llx.RawData{
		"__id":                llx.StringData(id),
		"file":                fileOrNull(f),
		"name":                llx.StringData(name),
		"mode":                llx.StringData(doc.Mode()),
		"hostName":            llx.StringData(jboss.Attr(doc.Attrs, "name")),
		"management":          managementOrNull(management),
		"profiles":            llx.ArrayData(profiles, types.Resource("jboss.profile")),
		"interfaces":          llx.ArrayData(interfaces, types.Resource("jboss.interface")),
		"socketBindingGroups": llx.ArrayData(socketGroups, types.Resource("jboss.socketBindingGroup")),
		"vault":               vaultOrNull(vault),
		"deployments":         llx.ArrayData(deployments, types.Dict),
		"serverGroups":        llx.ArrayData(serverGroups, types.Dict),
		"servers":             llx.ArrayData(servers, types.Dict),
		"extensions":          llx.ArrayData(convert.SliceAnyToInterface(extensions), types.String),
		"systemProperties":    llx.MapData(systemProperties, types.String),
		"domainController":    llx.StringData(doc.DomainController.Kind()),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossConfig), nil
}

// managementOrNull keeps an absent <management> section reading as null rather
// than as a typed nil pointer, which a comparison would treat as a value.
func managementOrNull(m *mqlJbossManagement) *llx.RawData {
	if m == nil {
		return &llx.RawData{Type: types.Resource("jboss.management")}
	}
	return llx.ResourceData(m, "jboss.management")
}

func vaultOrNull(v *mqlJbossVault) *llx.RawData {
	if v == nil {
		return &llx.RawData{Type: types.Resource("jboss.vault")}
	}
	return llx.ResourceData(v, "jboss.vault")
}

func newJbossManagement(runtime *plugin.Runtime, m *jboss.Management, id string) (*mqlJbossManagement, error) {
	if m == nil {
		return nil, nil
	}
	mgmtID := id + "/management"

	interfaces := make([]any, 0, 2)
	for _, mi := range m.ManagementInterfaces() {
		attrs := jboss.AttrMap(mi.Attrs)
		binding := mi.SocketBindingAttrs()
		socket := mi.SocketAttrs()

		obj, err := CreateResource(runtime, "jboss.managementInterface", map[string]*llx.RawData{
			"__id":               llx.StringData(mgmtID + "/interface/" + mi.Type),
			"type":               llx.StringData(mi.Type),
			"securityRealm":      llx.StringData(attrs["security-realm"]),
			"consoleEnabled":     llx.BoolData(jboss.AttrBool(mi.Attrs, "console-enabled", true)),
			"httpUpgradeEnabled": llx.BoolData(jboss.AttrBool(mi.Attrs, "http-upgrade-enabled", false)),
			"httpBinding":        llx.StringData(binding["http"]),
			"httpsBinding":       llx.StringData(binding["https"]),
			"nativeBinding":      llx.StringData(binding["native"]),
			"socketInterface":    llx.StringData(socket["interface"]),
			"socketPort":         llx.StringData(socket["port"]),
			"socketSecurePort":   llx.StringData(socket["secure-port"]),
			"params":             llx.MapData(stringMap(attrs), types.String),
		})
		if err != nil {
			return nil, err
		}
		interfaces = append(interfaces, obj)
	}

	realms, err := newJbossSecurityRealms(runtime, m.SecurityRealms, mgmtID)
	if err != nil {
		return nil, err
	}

	auditLog, err := newJbossAuditLog(runtime, m.AuditLog, mgmtID)
	if err != nil {
		return nil, err
	}

	roleMappings := []any{}
	if m.AccessControl != nil {
		for i := range m.AccessControl.Roles {
			role := m.AccessControl.Roles[i]
			roleMappings = append(roleMappings, map[string]any{
				"name":          role.Name,
				"includeUsers":  toAnySlice(jboss.Names(role.IncludeUsers)),
				"includeGroups": toAnySlice(jboss.Names(role.IncludeGroups)),
				"excludeUsers":  toAnySlice(jboss.Names(role.ExcludeUsers)),
				"excludeGroups": toAnySlice(jboss.Names(role.ExcludeGroups)),
			})
		}
	}

	raw, err := CreateResource(runtime, "jboss.management", map[string]*llx.RawData{
		"__id":                  llx.StringData(mgmtID),
		"interfaces":            llx.ArrayData(interfaces, types.Resource("jboss.managementInterface")),
		"securityRealms":        llx.ArrayData(realms, types.Resource("jboss.securityRealm")),
		"auditLog":              auditLogOrNull(auditLog),
		"accessControlProvider": llx.StringData(m.AccessControlProvider()),
		"roleMappings":          llx.ArrayData(roleMappings, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossManagement), nil
}

func auditLogOrNull(a *mqlJbossAuditLog) *llx.RawData {
	if a == nil {
		return &llx.RawData{Type: types.Resource("jboss.auditLog")}
	}
	return llx.ResourceData(a, "jboss.auditLog")
}

func newJbossSecurityRealms(runtime *plugin.Runtime, realms []jboss.SecurityRealm, ownerID string) ([]any, error) {
	res := make([]any, 0, len(realms))
	for i := range realms {
		realm := realms[i]
		realmID := ownerID + "/realm/" + strconv.Itoa(i) + "/" + realm.Name

		auth, err := newJbossRealmAuthentication(runtime, realm.Authentication, realmID)
		if err != nil {
			return nil, err
		}

		identity, err := newJbossKeystore(runtime, realm.Identity(), realmID+"/identity")
		if err != nil {
			return nil, err
		}

		authorizationProperties := ""
		mapGroupsToRoles := true
		if realm.Authorization != nil {
			mapGroupsToRoles = jboss.AttrBool(realm.Authorization.Attrs, "map-groups-to-roles", true)
			if realm.Authorization.Properties != nil {
				authorizationProperties = jboss.Attr(realm.Authorization.Properties.Attrs, "path")
			}
		}

		obj, err := CreateResource(runtime, "jboss.securityRealm", map[string]*llx.RawData{
			"__id":                    llx.StringData(realmID),
			"name":                    llx.StringData(realm.Name),
			"authentication":          realmAuthOrNull(auth),
			"authorizationProperties": llx.StringData(authorizationProperties),
			"mapGroupsToRoles":        llx.BoolData(mapGroupsToRoles),
			"serverIdentity":          keystoreOrNull(identity),
			"hasSecretIdentity":       llx.BoolData(realm.HasSecretIdentity()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func realmAuthOrNull(a *mqlJbossRealmAuthentication) *llx.RawData {
	if a == nil {
		return &llx.RawData{Type: types.Resource("jboss.realmAuthentication")}
	}
	return llx.ResourceData(a, "jboss.realmAuthentication")
}

func keystoreOrNull(k *mqlJbossKeystore) *llx.RawData {
	if k == nil {
		return &llx.RawData{Type: types.Resource("jboss.keystore")}
	}
	return llx.ResourceData(k, "jboss.keystore")
}

func ldapOrNull(l *mqlJbossLdapAuthentication) *llx.RawData {
	if l == nil {
		return &llx.RawData{Type: types.Resource("jboss.ldapAuthentication")}
	}
	return llx.ResourceData(l, "jboss.ldapAuthentication")
}

func newJbossRealmAuthentication(runtime *plugin.Runtime, auth *jboss.RealmAuthentication, id string) (*mqlJbossRealmAuthentication, error) {
	if auth == nil {
		return nil, nil
	}
	authID := id + "/authentication"

	ldap, err := newJbossLDAP(runtime, auth.LDAP, authID)
	if err != nil {
		return nil, err
	}
	truststore, err := newJbossKeystore(runtime, auth.Truststore, authID+"/truststore")
	if err != nil {
		return nil, err
	}

	local := auth.LocalAttrs()
	propertiesPath, propertiesRelativeTo, plainText := "", "", false
	if auth.Properties != nil {
		propertiesPath = jboss.Attr(auth.Properties.Attrs, "path")
		propertiesRelativeTo = jboss.Attr(auth.Properties.Attrs, "relative-to")
		plainText = jboss.AttrBool(auth.Properties.Attrs, "plain-text", false)
	}
	jaasName := ""
	if auth.JAAS != nil {
		jaasName = auth.JAAS.Name
	}

	raw, err := CreateResource(runtime, "jboss.realmAuthentication", map[string]*llx.RawData{
		"__id":                 llx.StringData(authID),
		"hasLocal":             llx.BoolData(auth.Local != nil),
		"localDefaultUser":     llx.StringData(local["default-user"]),
		"localAllowedUsers":    llx.StringData(local["allowed-users"]),
		"propertiesPath":       llx.StringData(propertiesPath),
		"propertiesRelativeTo": llx.StringData(propertiesRelativeTo),
		"plainText":            llx.BoolData(plainText),
		"ldap":                 ldapOrNull(ldap),
		"truststore":           keystoreOrNull(truststore),
		"jaasName":             llx.StringData(jaasName),
		"inlineUsers":          llx.ArrayData(toAnySlice(jboss.Names(auth.Users)), types.String),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossRealmAuthentication), nil
}

func newJbossLDAP(runtime *plugin.Runtime, ldap *jboss.LDAPAuth, id string) (*mqlJbossLdapAuthentication, error) {
	if ldap == nil {
		return nil, nil
	}
	attrs := jboss.AttrMap(ldap.Attrs)

	raw, err := CreateResource(runtime, "jboss.ldapAuthentication", map[string]*llx.RawData{
		"__id":                llx.StringData(id + "/ldap"),
		"connection":          llx.StringData(attrs["connection"]),
		"baseDn":              llx.StringData(attrs["base-dn"]),
		"recursive":           llx.BoolData(jboss.AttrBool(ldap.Attrs, "recursive", false)),
		"userDn":              llx.StringData(attrs["user-dn"]),
		"allowEmptyPasswords": llx.BoolData(jboss.AttrBool(ldap.Attrs, "allow-empty-passwords", false)),
		"usernameAttribute":   llx.StringData(ldap.UsernameAttribute()),
		"advancedFilter":      llx.StringData(ldap.Filter()),
		"params":              llx.MapData(stringMap(attrs), types.String),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossLdapAuthentication), nil
}

func newJbossKeystore(runtime *plugin.Runtime, ks *jboss.Keystore, id string) (*mqlJbossKeystore, error) {
	if ks == nil {
		return nil, nil
	}
	attrs := jboss.AttrMap(ks.Attrs)

	raw, err := CreateResource(runtime, "jboss.keystore", map[string]*llx.RawData{
		"__id":                      llx.StringData(id),
		"path":                      llx.StringData(ks.Path()),
		"relativeTo":                llx.StringData(ks.RelativeTo()),
		"provider":                  llx.StringData(attrs["provider"]),
		"alias":                     llx.StringData(attrs["alias"]),
		"passwordIsVaultExpression": llx.BoolData(ks.PasswordIsVaultExpression()),
		"params":                    llx.MapData(stringMap(attrs), types.String),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossKeystore), nil
}

func newJbossAuditLog(runtime *plugin.Runtime, auditLog *jboss.AuditLog, id string) (*mqlJbossAuditLog, error) {
	if auditLog == nil {
		return nil, nil
	}
	auditID := id + "/audit-log"

	logger, err := newJbossAuditLogger(runtime, auditLog.Logger, "logger", auditID)
	if err != nil {
		return nil, err
	}
	serverLogger, err := newJbossAuditLogger(runtime, auditLog.ServerLogger, "server-logger", auditID)
	if err != nil {
		return nil, err
	}

	formatters := make([]any, 0, len(auditLog.Formatters))
	for i := range auditLog.Formatters {
		formatter := auditLog.Formatters[i]
		attrs := jboss.AttrMap(formatter.Attrs)
		obj, err := CreateResource(runtime, "jboss.auditFormatter", map[string]*llx.RawData{
			"__id":                    llx.StringData(auditID + "/formatter/" + strconv.Itoa(i) + "/" + attrs["name"]),
			"name":                    llx.StringData(attrs["name"]),
			"includeDate":             llx.BoolData(jboss.AttrBool(formatter.Attrs, "include-date", true)),
			"dateFormat":              llx.StringData(attrs["date-format"]),
			"dateSeparator":           llx.StringData(attrs["date-separator"]),
			"compact":                 llx.BoolData(jboss.AttrBool(formatter.Attrs, "compact", false)),
			"escapeNewLine":           llx.BoolData(jboss.AttrBool(formatter.Attrs, "escape-new-line", false)),
			"escapeControlCharacters": llx.BoolData(jboss.AttrBool(formatter.Attrs, "escape-control-characters", false)),
			"params":                  llx.MapData(stringMap(attrs), types.String),
		})
		if err != nil {
			return nil, err
		}
		formatters = append(formatters, obj)
	}

	handlers := []any{}
	for i, handler := range auditLog.Handlers() {
		attrs := jboss.AttrMap(handler.Attrs)
		transport, transportAttrs := handler.Transport()

		obj, err := CreateResource(runtime, "jboss.auditHandler", map[string]*llx.RawData{
			"__id":            llx.StringData(auditID + "/handler/" + strconv.Itoa(i) + "/" + attrs["name"]),
			"name":            llx.StringData(attrs["name"]),
			"type":            llx.StringData(handler.Type),
			"formatter":       llx.StringData(attrs["formatter"]),
			"path":            llx.StringData(attrs["path"]),
			"relativeTo":      llx.StringData(attrs["relative-to"]),
			"rotateAtStartup": llx.BoolData(jboss.AttrBool(handler.Attrs, "rotate-at-startup", true)),
			"maxFailureCount": llx.IntData(jboss.AttrInt(handler.Attrs, "max-failure-count", 10)),
			"syslogFormat":    llx.StringData(attrs["syslog-format"]),
			"appName":         llx.StringData(attrs["app-name"]),
			"transport":       llx.StringData(transport),
			"host":            llx.StringData(transportAttrs["host"]),
			"port":            llx.StringData(transportAttrs["port"]),
			"params":          llx.MapData(stringMap(attrs), types.String),
		})
		if err != nil {
			return nil, err
		}
		handlers = append(handlers, obj)
	}

	raw, err := CreateResource(runtime, "jboss.auditLog", map[string]*llx.RawData{
		"__id":         llx.StringData(auditID),
		"enabled":      llx.BoolData(auditLog.Enabled()),
		"logger":       auditLoggerOrNull(logger),
		"serverLogger": auditLoggerOrNull(serverLogger),
		"formatters":   llx.ArrayData(formatters, types.Resource("jboss.auditFormatter")),
		"handlers":     llx.ArrayData(handlers, types.Resource("jboss.auditHandler")),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossAuditLog), nil
}

func auditLoggerOrNull(l *mqlJbossAuditLogger) *llx.RawData {
	if l == nil {
		return &llx.RawData{Type: types.Resource("jboss.auditLogger")}
	}
	return llx.ResourceData(l, "jboss.auditLogger")
}

func newJbossAuditLogger(runtime *plugin.Runtime, logger *jboss.AuditLogger, kind string, ownerID string) (*mqlJbossAuditLogger, error) {
	if logger == nil {
		return nil, nil
	}
	raw, err := CreateResource(runtime, "jboss.auditLogger", map[string]*llx.RawData{
		"__id":        llx.StringData(ownerID + "/" + kind),
		"type":        llx.StringData(kind),
		"enabled":     llx.BoolData(logger.Enabled()),
		"logBoot":     llx.BoolData(logger.LogBoot()),
		"logReadOnly": llx.BoolData(logger.LogReadOnly()),
		"handlers":    llx.ArrayData(toAnySlice(jboss.Names(logger.Handlers)), types.String),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossAuditLogger), nil
}

func newJbossInterfaces(runtime *plugin.Runtime, interfaces []jboss.Interface, ownerID string) ([]any, error) {
	res := make([]any, 0, len(interfaces))
	for i := range interfaces {
		iface := interfaces[i]
		obj, err := CreateResource(runtime, "jboss.interface", map[string]*llx.RawData{
			"__id":        llx.StringData(ownerID + "/interface/" + strconv.Itoa(i) + "/" + iface.Name),
			"name":        llx.StringData(iface.Name),
			"inetAddress": llx.StringData(iface.Address()),
			"anyAddress":  llx.BoolData(iface.IsAnyAddress()),
			"criteria":    llx.ArrayData(toAnySlice(iface.Criteria()), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func newJbossSocketBindingGroups(runtime *plugin.Runtime, groups []jboss.SocketBindingGroup, ownerID string) ([]any, error) {
	res := make([]any, 0, len(groups))
	for i := range groups {
		group := groups[i]
		attrs := jboss.AttrMap(group.Attrs)
		groupID := ownerID + "/socket-binding-group/" + strconv.Itoa(i) + "/" + attrs["name"]

		bindings, err := newJbossSocketBindings(runtime, group.SocketBindings, groupID, false)
		if err != nil {
			return nil, err
		}
		outbound, err := newJbossSocketBindings(runtime, group.OutboundBindings(), groupID+"/outbound", true)
		if err != nil {
			return nil, err
		}

		obj, err := CreateResource(runtime, "jboss.socketBindingGroup", map[string]*llx.RawData{
			"__id":                   llx.StringData(groupID),
			"name":                   llx.StringData(attrs["name"]),
			"defaultInterface":       llx.StringData(attrs["default-interface"]),
			"portOffset":             llx.StringData(attrs["port-offset"]),
			"socketBindings":         llx.ArrayData(bindings, types.Resource("jboss.socketBinding")),
			"outboundSocketBindings": llx.ArrayData(outbound, types.Resource("jboss.socketBinding")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func newJbossSocketBindings(runtime *plugin.Runtime, bindings []jboss.SocketBinding, ownerID string, outbound bool) ([]any, error) {
	res := make([]any, 0, len(bindings))
	for i := range bindings {
		binding := bindings[i]
		attrs := jboss.AttrMap(binding.Attrs)
		remote := binding.RemoteAttrs()

		obj, err := CreateResource(runtime, "jboss.socketBinding", map[string]*llx.RawData{
			"__id":             llx.StringData(ownerID + "/binding/" + strconv.Itoa(i) + "/" + attrs["name"]),
			"name":             llx.StringData(attrs["name"]),
			"interface":        llx.StringData(attrs["interface"]),
			"port":             llx.StringData(attrs["port"]),
			"multicastAddress": llx.StringData(attrs["multicast-address"]),
			"multicastPort":    llx.StringData(attrs["multicast-port"]),
			"fixedPort":        llx.BoolData(jboss.AttrBool(binding.Attrs, "fixed-port", false)),
			"outbound":         llx.BoolData(outbound),
			"remoteHost":       llx.StringData(remote["host"]),
			"remotePort":       llx.StringData(remote["port"]),
			"localDestination": llx.StringData(binding.LocalRef()),
			"params":           llx.MapData(stringMap(attrs), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func newJbossVault(runtime *plugin.Runtime, vault *jboss.Vault, ownerID string) (*mqlJbossVault, error) {
	if vault == nil {
		return nil, nil
	}
	attrs := jboss.AttrMap(vault.Attrs)
	options := vault.OptionMap()

	raw, err := CreateResource(runtime, "jboss.vault", map[string]*llx.RawData{
		"__id":                llx.StringData(ownerID + "/vault"),
		"keystoreUrl":         llx.StringData(options["KEYSTORE_URL"]),
		"keystoreAlias":       llx.StringData(options["KEYSTORE_ALIAS"]),
		"encryptionDirectory": llx.StringData(options["ENC_FILE_DIR"]),
		"code":                llx.StringData(attrs["code"]),
		"module":              llx.StringData(attrs["module"]),
		"options":             llx.MapData(stringMap(options), types.String),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossVault), nil
}

// --- profiles and subsystems -------------------------------------------------

func newJbossProfiles(runtime *plugin.Runtime, profiles []jboss.Profile, ownerID string) ([]any, error) {
	res := make([]any, 0, len(profiles))
	for i := range profiles {
		profile := profiles[i]
		profileID := ownerID + "/profile/" + strconv.Itoa(i) + "/" + profile.Name

		subsystems := make([]any, 0, len(profile.Subsystems))
		var logging, web, jmxSubsystem, scanners *jboss.Subsystem
		for k := range profile.Subsystems {
			subsystem := &profile.Subsystems[k]
			obj, err := CreateResource(runtime, "jboss.subsystem", map[string]*llx.RawData{
				"__id":      llx.StringData(profileID + "/subsystem/" + strconv.Itoa(k) + "/" + subsystem.Name()),
				"name":      llx.StringData(subsystem.Name()),
				"namespace": llx.StringData(subsystem.Namespace()),
				"version":   llx.StringData(subsystem.Version()),
				"params":    llx.MapData(stringMap(jboss.AttrMap(subsystem.Attrs)), types.String),
			})
			if err != nil {
				return nil, err
			}
			subsystems = append(subsystems, obj)

			switch subsystem.Name() {
			case "logging":
				logging = subsystem
			case "web":
				web = subsystem
			case "jmx":
				jmxSubsystem = subsystem
			case "deployment-scanner":
				scanners = subsystem
			}
		}

		loggingRes, err := newJbossLogging(runtime, logging, profileID)
		if err != nil {
			return nil, err
		}
		webRes, err := newJbossWeb(runtime, web, profileID)
		if err != nil {
			return nil, err
		}
		jmxRes, err := newJbossJMX(runtime, jmxSubsystem, profileID)
		if err != nil {
			return nil, err
		}
		scannerRes, err := newJbossDeploymentScanners(runtime, scanners, profileID)
		if err != nil {
			return nil, err
		}

		obj, err := CreateResource(runtime, "jboss.profile", map[string]*llx.RawData{
			"__id":               llx.StringData(profileID),
			"name":               llx.StringData(profile.Name),
			"subsystems":         llx.ArrayData(subsystems, types.Resource("jboss.subsystem")),
			"logging":            loggingOrNull(loggingRes),
			"web":                webOrNull(webRes),
			"jmx":                jmxOrNull(jmxRes),
			"deploymentScanners": llx.ArrayData(scannerRes, types.Resource("jboss.deploymentScanner")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func loggingOrNull(l *mqlJbossLogging) *llx.RawData {
	if l == nil {
		return &llx.RawData{Type: types.Resource("jboss.logging")}
	}
	return llx.ResourceData(l, "jboss.logging")
}

func webOrNull(w *mqlJbossWeb) *llx.RawData {
	if w == nil {
		return &llx.RawData{Type: types.Resource("jboss.web")}
	}
	return llx.ResourceData(w, "jboss.web")
}

func jmxOrNull(j *mqlJbossJmx) *llx.RawData {
	if j == nil {
		return &llx.RawData{Type: types.Resource("jboss.jmx")}
	}
	return llx.ResourceData(j, "jboss.jmx")
}

func newJbossLogging(runtime *plugin.Runtime, subsystem *jboss.Subsystem, ownerID string) (*mqlJbossLogging, error) {
	if subsystem == nil {
		return nil, nil
	}
	parsed, err := jboss.ParseLogging(subsystem)
	if err != nil {
		return nil, nil
	}
	loggingID := ownerID + "/logging"

	handlers := []any{}
	for i, handler := range parsed.Handlers() {
		attrs := jboss.AttrMap(handler.Attrs)
		file := handler.FileAttrs()

		obj, err := CreateResource(runtime, "jboss.logHandler", map[string]*llx.RawData{
			"__id":           llx.StringData(loggingID + "/handler/" + strconv.Itoa(i) + "/" + attrs["name"]),
			"name":           llx.StringData(attrs["name"]),
			"type":           llx.StringData(handler.Type),
			"level":          llx.StringData(handler.LevelName()),
			"path":           llx.StringData(file["path"]),
			"relativeTo":     llx.StringData(file["relative-to"]),
			"suffix":         llx.StringData(handler.Suffix.Get()),
			"append":         llx.BoolData(handler.Appends()),
			"rotateSize":     llx.StringData(handler.RotateSize.Get()),
			"maxBackupIndex": llx.IntData(handler.MaxBackup()),
			"formatter":      llx.StringData(handler.FormatterName()),
			"serverAddress":  llx.StringData(handler.ServerAddress.Get()),
			"port":           llx.StringData(handler.Port.Get()),
			"appName":        llx.StringData(handler.AppName.Get()),
			"params":         llx.MapData(stringMap(attrs), types.String),
		})
		if err != nil {
			return nil, err
		}
		handlers = append(handlers, obj)
	}

	loggers := make([]any, 0, len(parsed.Loggers))
	for i := range parsed.Loggers {
		logger := parsed.Loggers[i]
		loggers = append(loggers, map[string]any{
			"category":          logger.Category,
			"level":             logger.LevelName(),
			"useParentHandlers": jboss.AttrBool(logger.Attrs, "use-parent-handlers", true),
			"handlers":          toAnySlice(jboss.Names(logger.Handlers)),
		})
	}

	raw, err := CreateResource(runtime, "jboss.logging", map[string]*llx.RawData{
		"__id":               llx.StringData(loggingID),
		"rootLoggerLevel":    llx.StringData(parsed.RootLevel()),
		"rootLoggerHandlers": llx.ArrayData(toAnySlice(parsed.RootHandlers()), types.String),
		"handlers":           llx.ArrayData(handlers, types.Resource("jboss.logHandler")),
		"loggers":            llx.ArrayData(loggers, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossLogging), nil
}

func newJbossWeb(runtime *plugin.Runtime, subsystem *jboss.Subsystem, ownerID string) (*mqlJbossWeb, error) {
	if subsystem == nil {
		return nil, nil
	}
	parsed, err := jboss.ParseWeb(subsystem)
	if err != nil {
		return nil, nil
	}
	webID := ownerID + "/web"
	attrs := jboss.AttrMap(parsed.Attrs)

	connectors := make([]any, 0, len(parsed.Connectors))
	for i := range parsed.Connectors {
		connector := parsed.Connectors[i]
		connectorAttrs := jboss.AttrMap(connector.Attrs)
		ssl := connector.SSLAttrs()

		obj, err := CreateResource(runtime, "jboss.connector", map[string]*llx.RawData{
			"__id":                  llx.StringData(webID + "/connector/" + strconv.Itoa(i) + "/" + connectorAttrs["name"]),
			"name":                  llx.StringData(connectorAttrs["name"]),
			"protocol":              llx.StringData(connectorAttrs["protocol"]),
			"scheme":                llx.StringData(connectorAttrs["scheme"]),
			"socketBinding":         llx.StringData(connectorAttrs["socket-binding"]),
			"secure":                llx.BoolData(jboss.AttrBool(connector.Attrs, "secure", false)),
			"enabled":               llx.BoolData(jboss.AttrBool(connector.Attrs, "enabled", true)),
			"sslEnabled":            llx.BoolData(connector.SSLEnabled()),
			"sslProtocol":           llx.StringData(ssl["protocol"]),
			"sslCipherSuite":        llx.StringData(ssl["cipher-suite"]),
			"sslVerifyClient":       llx.StringData(ssl["verify-client"]),
			"sslKeyAlias":           llx.StringData(ssl["key-alias"]),
			"sslCertificateKeyFile": llx.StringData(ssl["certificate-key-file"]),
			"sslCaCertificateFile":  llx.StringData(ssl["ca-certificate-file"]),
			"sslParams":             llx.MapData(stringMap(ssl), types.String),
			"params":                llx.MapData(stringMap(connectorAttrs), types.String),
		})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, obj)
	}

	virtualServers := make([]any, 0, len(parsed.VirtualServers))
	for i := range parsed.VirtualServers {
		vs := parsed.VirtualServers[i]
		vsAttrs := jboss.AttrMap(vs.Attrs)

		obj, err := CreateResource(runtime, "jboss.virtualServer", map[string]*llx.RawData{
			"__id":               llx.StringData(webID + "/virtual-server/" + strconv.Itoa(i) + "/" + vsAttrs["name"]),
			"name":               llx.StringData(vsAttrs["name"]),
			"enableWelcomeRoot":  llx.BoolData(jboss.AttrBool(vs.Attrs, "enable-welcome-root", true)),
			"aliases":            llx.ArrayData(toAnySlice(jboss.Names(vs.Aliases)), types.String),
			"accessLogEnabled":   llx.BoolData(vs.AccessLogEnabled()),
			"accessLogPattern":   llx.StringData(vs.AccessLogPattern()),
			"accessLogDirectory": llx.StringData(vs.AccessLogDirectory()),
		})
		if err != nil {
			return nil, err
		}
		virtualServers = append(virtualServers, obj)
	}

	raw, err := CreateResource(runtime, "jboss.web", map[string]*llx.RawData{
		"__id":                 llx.StringData(webID),
		"defaultVirtualServer": llx.StringData(attrs["default-virtual-server"]),
		"native":               llx.BoolData(jboss.AttrBool(parsed.Attrs, "native", true)),
		"connectors":           llx.ArrayData(connectors, types.Resource("jboss.connector")),
		"virtualServers":       llx.ArrayData(virtualServers, types.Resource("jboss.virtualServer")),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossWeb), nil
}

func newJbossJMX(runtime *plugin.Runtime, subsystem *jboss.Subsystem, ownerID string) (*mqlJbossJmx, error) {
	if subsystem == nil {
		return nil, nil
	}
	parsed, err := jboss.ParseJMX(subsystem)
	if err != nil {
		return nil, nil
	}

	raw, err := CreateResource(runtime, "jboss.jmx", map[string]*llx.RawData{
		"__id":                     llx.StringData(ownerID + "/jmx"),
		"remotingConnectorEnabled": llx.BoolData(parsed.RemotingConnectorEnabled()),
		"useManagementEndpoint":    llx.BoolData(parsed.UseManagementEndpoint()),
		"exposeResolvedModel":      llx.BoolData(parsed.ExposeResolvedModel != nil),
		"exposeExpressionModel":    llx.BoolData(parsed.ExposeExpressionModel != nil),
		"nonCoreMbeansSensitive":   llx.BoolData(parsed.NonCoreMbeansSensitive()),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlJbossJmx), nil
}

func newJbossDeploymentScanners(runtime *plugin.Runtime, subsystem *jboss.Subsystem, ownerID string) ([]any, error) {
	if subsystem == nil {
		return []any{}, nil
	}
	parsed, err := jboss.ParseDeploymentScanners(subsystem)
	if err != nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(parsed.Scanners))
	for i := range parsed.Scanners {
		scanner := parsed.Scanners[i]
		attrs := jboss.AttrMap(scanner.Attrs)
		name := attrs["name"]
		if name == "" {
			name = "default"
		}

		obj, err := CreateResource(runtime, "jboss.deploymentScanner", map[string]*llx.RawData{
			"__id":                         llx.StringData(ownerID + "/deployment-scanner/" + strconv.Itoa(i) + "/" + name),
			"name":                         llx.StringData(name),
			"path":                         llx.StringData(attrs["path"]),
			"relativeTo":                   llx.StringData(attrs["relative-to"]),
			"scanEnabled":                  llx.BoolData(jboss.AttrBool(scanner.Attrs, "scan-enabled", true)),
			"scanInterval":                 llx.IntData(jboss.AttrInt(scanner.Attrs, "scan-interval", 5000)),
			"autoDeployExploded":           llx.BoolData(jboss.AttrBool(scanner.Attrs, "auto-deploy-exploded", false)),
			"autoDeployZipped":             llx.BoolData(jboss.AttrBool(scanner.Attrs, "auto-deploy-zipped", true)),
			"autoDeployXml":                llx.BoolData(jboss.AttrBool(scanner.Attrs, "auto-deploy-xml", true)),
			"runtimeFailureCausesRollback": llx.BoolData(jboss.AttrBool(scanner.Attrs, "runtime-failure-causes-rollback", false)),
			"params":                       llx.MapData(stringMap(attrs), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}
