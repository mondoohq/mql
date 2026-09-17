// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/versionx"
)

// jetbrainsConfigRoots are the per-platform directories holding one
// subdirectory per installed JetBrains product, named <Product><Version>.
//
// The plugins a user installed live under that product directory; on macOS and
// Windows in a plugins/ subdirectory, on Linux directly in it, which is why the
// relative path is part of the entry rather than assumed.
var jetbrainsConfigRoots = map[string][]jetbrainsConfigRoot{
	"darwin": {
		{relPath: "Library/Application Support/JetBrains", pluginsSubdir: "plugins"},
	},
	"windows": {
		{relPath: "AppData/Roaming/JetBrains", pluginsSubdir: "plugins"},
	},
	"linux": {
		{relPath: ".local/share/JetBrains", pluginsSubdir: ""},
		// Pre-2020.1 layout, still present on long-lived machines.
		{relPath: ".config/JetBrains", pluginsSubdir: "plugins"},
	},
}

type jetbrainsConfigRoot struct {
	relPath       string
	pluginsSubdir string
}

// jetbrainsAppRoots are the directories holding installed IDEs, whose bundled
// plugins ship with the product rather than being chosen by a user.
//
// Bundled plugins are the majority of the code loaded by an IDE, and on a host
// where nobody has installed anything extra they are all of it, so leaving them
// out reports an empty inventory for a machine full of IDEs.
var jetbrainsAppRoots = map[string][]string{
	"darwin": {
		"/Applications",
		"Applications", // per-user installs, relative to the home directory
		"Library/Application Support/JetBrains/Toolbox/apps",
	},
	"linux": {
		".local/share/JetBrains/Toolbox/apps",
		"/opt",
	},
	"windows": {
		"AppData/Local/JetBrains/Toolbox/apps",
	},
}

// jetbrainsProductDirRegex splits a config directory name such as
// "IntelliJIdea2026.2" or "PyCharmCE2025.1" into product and version. A
// directory that does not carry a version is not a product directory:
// JetBrains puts Toolbox, consentOptions and similar bookkeeping alongside.
var jetbrainsProductDirRegex = regexp.MustCompile(`^([A-Za-z]+)(\d{4}\.\d+)$`)

// jetbrainsPluginDescriptor is the subset of META-INF/plugin.xml that identifies
// a plugin. The file also carries the plugin's extensions, actions and content
// modules, which run to hundreds of kilobytes and say nothing about identity.
type jetbrainsPluginDescriptor struct {
	XMLName     xml.Name `xml:"idea-plugin"`
	ID          string   `xml:"id"`
	Name        string   `xml:"name"`
	Version     string   `xml:"version"`
	Vendor      string   `xml:"vendor"`
	Category    string   `xml:"category"`
	Description string   `xml:"description"`
	IdeaVersion struct {
		SinceBuild string `xml:"since-build,attr"`
		UntilBuild string `xml:"until-build,attr"`
	} `xml:"idea-version"`
}

// jetbrainsPlugin is a decoded plugin descriptor with its identity resolved.
type jetbrainsPlugin struct {
	Identifier  string
	Name        string
	Version     string
	Vendor      string
	Category    string
	Description string
	SinceBuild  string
	UntilBuild  string
}

var errJetBrainsNoDescriptor = errors.New("no META-INF/plugin.xml found")

// parseJetBrainsPluginXML decodes a plugin descriptor.
//
// id and name are both optional in the format and mean different things: id is
// the stable identifier the IDE and the marketplace key on, name is the display
// label, and they routinely differ (id "org.intellij.plugins.markdown" against
// name "Markdown"). Where one is missing the other stands in for it, because a
// plugin with an empty identifier would collide with every other such plugin in
// the resource cache.
func parseJetBrainsPluginXML(data []byte) (*jetbrainsPlugin, error) {
	var descriptor jetbrainsPluginDescriptor
	if err := xml.Unmarshal(data, &descriptor); err != nil {
		return nil, err
	}

	plugin := &jetbrainsPlugin{
		Identifier:  strings.TrimSpace(descriptor.ID),
		Name:        strings.TrimSpace(descriptor.Name),
		Version:     strings.TrimSpace(descriptor.Version),
		Vendor:      strings.TrimSpace(descriptor.Vendor),
		Category:    strings.TrimSpace(descriptor.Category),
		Description: strings.TrimSpace(descriptor.Description),
		SinceBuild:  strings.TrimSpace(descriptor.IdeaVersion.SinceBuild),
		UntilBuild:  strings.TrimSpace(descriptor.IdeaVersion.UntilBuild),
	}

	if plugin.Identifier == "" {
		plugin.Identifier = plugin.Name
	}
	if plugin.Name == "" {
		plugin.Name = plugin.Identifier
	}
	if plugin.Identifier == "" {
		return nil, errors.New("plugin descriptor declares neither an id nor a name")
	}

	return plugin, nil
}

// readJetBrainsPlugin reads the descriptor for one plugin, which is either a
// directory or a single jar.
func readJetBrainsPlugin(afs *afero.Afero, path string) (*jetbrainsPlugin, error) {
	if strings.HasSuffix(path, ".jar") {
		return jetbrainsPluginFromJar(afs, path)
	}

	// Some plugins ship the descriptor on disk instead of inside a jar.
	unpacked := filepath.Join(path, "META-INF", "plugin.xml")
	if data, err := afs.ReadFile(unpacked); err == nil {
		return parseJetBrainsPluginXML(data)
	}

	libDir := filepath.Join(path, "lib")
	entries, err := afs.ReadDir(libDir)
	if err != nil {
		return nil, err
	}

	// The jar named after the plugin directory holds the descriptor for most
	// plugins, so try it first. It is not reliable on its own: 18 of the 139
	// plugins bundled with Rider 2026.2 keep it elsewhere, for example
	// markdown/lib/intellij.markdown.jar, so the rest are scanned after.
	preferred := filepath.Base(path) + ".jar"
	jars := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jar") {
			continue
		}
		if entry.Name() == preferred {
			jars = append([]string{entry.Name()}, jars...)
			continue
		}
		jars = append(jars, entry.Name())
	}

	for _, jar := range jars {
		plugin, err := jetbrainsPluginFromJar(afs, filepath.Join(libDir, jar))
		if err == nil {
			return plugin, nil
		}
		if !errors.Is(err, errJetBrainsNoDescriptor) {
			log.Debug().Err(err).Str("jar", jar).Msg("could not read a JetBrains plugin jar")
		}
	}

	return nil, errJetBrainsNoDescriptor
}

// jetbrainsPluginFromJar reads META-INF/plugin.xml out of a jar.
//
// The jar is read through the connection's filesystem rather than opened from
// the local disk, so this works against an image, a mounted volume or a remote
// host the same way it works locally.
func jetbrainsPluginFromJar(afs *afero.Afero, path string) (*jetbrainsPlugin, error) {
	data, err := afs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	file, err := reader.Open("META-INF/plugin.xml")
	if err != nil {
		return nil, errJetBrainsNoDescriptor
	}
	defer file.Close()

	descriptor, err := afero.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return parseJetBrainsPluginXML(descriptor)
}

// jetbrainsPluginCandidates lists the entries in a plugins directory that could
// be a plugin. The IDE also writes bookkeeping files such as
// plugin_classpath.txt there, which are neither.
func jetbrainsPluginCandidates(afs *afero.Afero, dir string) []string {
	entries, err := afs.ReadDir(dir)
	if err != nil {
		return nil
	}

	candidates := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".jar") {
			candidates = append(candidates, filepath.Join(dir, entry.Name()))
		}
	}
	return candidates
}

// readJetBrainsDisabledPlugins reads the ids the IDE has been told not to load.
//
// An absent file means nothing is disabled, which is the normal state, so it
// returns an empty set rather than an error.
func readJetBrainsDisabledPlugins(afs *afero.Afero, configDir string) map[string]bool {
	disabled := map[string]bool{}

	data, err := afs.ReadFile(filepath.Join(configDir, "disabled_plugins.txt"))
	if err != nil {
		return disabled
	}

	for _, line := range strings.Split(string(data), "\n") {
		if id := strings.TrimSpace(line); id != "" {
			disabled[id] = true
		}
	}
	return disabled
}

// jetbrainsProductFromDir turns a config directory name into a readable product
// and version, for example "GoLand2026.2" into "GoLand 2026.2".
func jetbrainsProductFromDir(dir string) (string, bool) {
	match := jetbrainsProductDirRegex.FindStringSubmatch(dir)
	if match == nil {
		return "", false
	}
	return match[1] + " " + match[2], true
}

// jetbrainsBuildOutsideRange reports whether a plugin declares support only for
// IDE builds older than the one it is installed into.
//
// JetBrains writes until-build either as a full build number or with a trailing
// wildcard (262.*), which means every build of that branch, so a wildcard is
// compared on the segments it actually states. An absent bound means the plugin
// declares no upper limit, and an unknown IDE build means there is nothing to
// compare against; neither is a finding.
func jetbrainsBuildOutsideRange(untilBuild, ideBuild string) bool {
	if untilBuild == "" || ideBuild == "" {
		return false
	}

	if idx := strings.Index(untilBuild, "*"); idx >= 0 {
		prefix := strings.TrimSuffix(untilBuild[:idx], ".")
		if prefix == "" {
			return false
		}
		segments := strings.Count(prefix, ".") + 1
		ideSegments := strings.Split(ideBuild, ".")
		if len(ideSegments) > segments {
			ideBuild = strings.Join(ideSegments[:segments], ".")
		}
		untilBuild = prefix
	}

	return versionx.Compare(untilBuild, ideBuild) < 0
}

func (j *mqlJetbrains) id() (string, error) {
	return "jetbrains", nil
}

// jetbrainsPluginsDir pairs a directory to search with what it says about the
// plugins inside it.
type jetbrainsPluginsDir struct {
	path     string
	product  string
	bundled  bool
	ideBuild string
	disabled map[string]bool
	uid      int64
}

func (j *mqlJetbrains) paths() ([]any, error) {
	dirs, err := j.pluginDirs()
	if err != nil {
		return nil, err
	}

	paths := make([]any, 0, len(dirs))
	for _, dir := range dirs {
		paths = append(paths, dir.path)
	}
	return paths, nil
}

func (j *mqlJetbrains) plugins() ([]any, error) {
	dirs, err := j.pluginDirs()
	if err != nil {
		return nil, err
	}

	conn := j.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	plugins := make([]any, 0, 64)
	seen := map[string]bool{}

	for _, dir := range dirs {
		for _, candidate := range jetbrainsPluginCandidates(afs, dir.path) {
			plugin, err := readJetBrainsPlugin(afs, candidate)
			if err != nil {
				log.Debug().Err(err).Str("path", candidate).Msg("skipping a path that is not a JetBrains plugin")
				continue
			}

			// A plugin can be installed into several products and for several
			// users, and the same id in two products is two installations with
			// their own enablement, so the key carries all three.
			key := fmt.Sprintf("%d|%s|%s", dir.uid, dir.product, plugin.Identifier)
			if seen[key] {
				continue
			}
			seen[key] = true

			resource, err := CreateResource(j.MqlRuntime, "jetbrains.plugin", map[string]*llx.RawData{
				"__id":              llx.StringData(key),
				"identifier":        llx.StringData(plugin.Identifier),
				"name":              llx.StringData(plugin.Name),
				"version":           llx.StringData(plugin.Version),
				"vendor":            llx.StringData(plugin.Vendor),
				"category":          llx.StringData(plugin.Category),
				"description":       llx.StringData(plugin.Description),
				"product":           llx.StringData(dir.product),
				"path":              llx.StringData(candidate),
				"bundled":           llx.BoolData(dir.bundled),
				"enabled":           llx.BoolData(!dir.disabled[plugin.Identifier]),
				"sinceBuild":        llx.StringData(plugin.SinceBuild),
				"untilBuild":        llx.StringData(plugin.UntilBuild),
				"outsideBuildRange": llx.BoolData(jetbrainsBuildOutsideRange(plugin.UntilBuild, dir.ideBuild)),
				"uid":               llx.IntData(dir.uid),
			})
			if err != nil {
				log.Debug().Err(err).Str("plugin", plugin.Identifier).Msg("could not create JetBrains plugin resource")
				continue
			}

			plugins = append(plugins, resource)
		}
	}

	return plugins, nil
}

// pluginDirs finds every directory that could hold plugins, for every user and
// every installed product.
func (j *mqlJetbrains) pluginDirs() ([]jetbrainsPluginsDir, error) {
	conn := j.MqlRuntime.Connection.(shared.Connection)
	pf := conn.Asset().Platform
	if pf == nil {
		return nil, nil
	}

	platformKey := getPlatformKey(pf)
	if platformKey == "" {
		log.Debug().Str("platform", pf.Name).Msg("unsupported platform for JetBrains plugin detection")
		return nil, nil
	}

	users, err := targetUserHomes(j.MqlRuntime)
	if err != nil {
		log.Debug().Err(err).Msg("could not retrieve users list")
		return nil, nil
	}

	afs := &afero.Afero{Fs: conn.FileSystem()}
	return jetbrainsPluginDirs(afs, platformKey, users), nil
}

// jetbrainsPluginDirs finds every directory that could hold plugins, across the
// IDEs installed system-wide and the ones each user installed for themselves.
//
// An IDE under an absolute root such as /Applications or /opt is installed once
// for the whole machine, so it is scanned once. Walking it per user reported
// every bundled plugin once per account, which on a shared host multiplies a
// few hundred plugins by the number of logins.
func jetbrainsPluginDirs(afs *afero.Afero, platformKey string, users []targetUser) []jetbrainsPluginsDir {
	dirs := []jetbrainsPluginsDir{}

	// Products installed for the whole machine, plus the build number each one
	// states, which the plugins a user added to it are compared against.
	systemDirs, builds := jetbrainsBundledRoots(afs, jetbrainsSystemAppRoots(platformKey), 0)
	dirs = append(dirs, systemDirs...)

	for _, u := range users {
		userDirs, userBuilds := jetbrainsBundledRoots(afs, jetbrainsUserAppRoots(platformKey, u.home), u.uid)
		dirs = append(dirs, userDirs...)

		// A product the user installed for themselves takes precedence over a
		// system-wide one of the same name, since that is the one their
		// configuration directory belongs to.
		productBuilds := map[string]string{}
		for dataDir, build := range builds {
			productBuilds[dataDir] = build
		}
		for dataDir, build := range userBuilds {
			productBuilds[dataDir] = build
		}

		for _, root := range jetbrainsConfigRoots[platformKey] {
			configRoot := filepath.Join(u.home, root.relPath)
			entries, err := afs.ReadDir(configRoot)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				product, ok := jetbrainsProductFromDir(entry.Name())
				if !ok {
					continue
				}

				configDir := filepath.Join(configRoot, entry.Name())
				pluginsDir := configDir
				if root.pluginsSubdir != "" {
					pluginsDir = filepath.Join(configDir, root.pluginsSubdir)
				}
				if exists, err := afs.DirExists(pluginsDir); err != nil || !exists {
					continue
				}

				dirs = append(dirs, jetbrainsPluginsDir{
					path:     pluginsDir,
					product:  product,
					bundled:  false,
					ideBuild: productBuilds[entry.Name()],
					disabled: readJetBrainsDisabledPlugins(afs, configDir),
					uid:      u.uid,
				})
			}
		}
	}

	return dirs
}

// jetbrainsSystemAppRoots are the application roots that hold one installation
// for the whole machine.
func jetbrainsSystemAppRoots(platformKey string) []string {
	roots := []string{}
	for _, root := range jetbrainsAppRoots[platformKey] {
		if filepath.IsAbs(root) {
			roots = append(roots, root)
		}
	}
	return roots
}

// jetbrainsUserAppRoots are the application roots that live inside a home
// directory, which Toolbox and per-user installs use.
func jetbrainsUserAppRoots(platformKey, home string) []string {
	roots := []string{}
	for _, root := range jetbrainsAppRoots[platformKey] {
		if !filepath.IsAbs(root) {
			roots = append(roots, filepath.Join(home, root))
		}
	}
	return roots
}

// jetbrainsBundledRoots scans application roots for installed products,
// returning their bundled plugin directories and the build each product states
// keyed by the configuration directory name it uses.
func jetbrainsBundledRoots(afs *afero.Afero, appRoots []string, uid int64) ([]jetbrainsPluginsDir, map[string]string) {
	dirs := []jetbrainsPluginsDir{}
	builds := map[string]string{}

	for _, appRoot := range appRoots {
		dirs = append(dirs, jetbrainsBundledDirs(afs, appRoot, uid)...)

		entries, err := afs.ReadDir(appRoot)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			info, ok := readJetBrainsProductInfo(afs, filepath.Join(appRoot, entry.Name()))
			if ok && info.DataDirectoryName != "" && info.BuildNumber != "" {
				builds[info.DataDirectoryName] = info.BuildNumber
			}
		}
	}

	return dirs, builds
}

// jetbrainsProductInfo is the identity an installed IDE states about itself in
// product-info.json.
type jetbrainsProductInfo struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	BuildNumber       string `json:"buildNumber"`
	ProductCode       string `json:"productCode"`
	DataDirectoryName string `json:"dataDirectoryName"`
}

// readJetBrainsProductInfo reads the product marker from an installed IDE.
//
// This is what distinguishes a JetBrains IDE from any other application, and it
// matters more than it looks: Contents/plugins is a standard macOS bundle
// directory, so treating its presence as the signal matched twenty-three
// unrelated applications on a real Mac against three actual IDEs. It also
// carries buildNumber, which is the only statement of the IDE build a plugin's
// until-build has to be compared against.
func readJetBrainsProductInfo(afs *afero.Afero, appDir string) (*jetbrainsProductInfo, bool) {
	// macOS keeps it under Contents/Resources; other platforms at the root.
	candidates := []string{
		filepath.Join(appDir, "Contents", "Resources", "product-info.json"),
		filepath.Join(appDir, "product-info.json"),
	}

	for _, path := range candidates {
		data, err := afs.ReadFile(path)
		if err != nil {
			continue
		}

		var info jetbrainsProductInfo
		if err := json.Unmarshal(data, &info); err != nil {
			log.Debug().Err(err).Str("path", path).Msg("could not read a JetBrains product-info.json")
			continue
		}
		if info.Name == "" {
			continue
		}
		return &info, true
	}

	return nil, false
}

// jetbrainsBundledDirs finds the plugins that ship inside the IDEs installed
// under one application root.
func jetbrainsBundledDirs(afs *afero.Afero, appRoot string, uid int64) []jetbrainsPluginsDir {
	entries, err := afs.ReadDir(appRoot)
	if err != nil {
		return nil
	}

	dirs := []jetbrainsPluginsDir{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		appDir := filepath.Join(appRoot, entry.Name())
		info, ok := readJetBrainsProductInfo(afs, appDir)
		if !ok {
			continue
		}

		product := info.Name
		if info.Version != "" {
			product += " " + info.Version
		}

		// macOS keeps an IDE's plugins inside the bundle; every other layout
		// keeps them beside the binary.
		for _, pluginsDir := range []string{
			filepath.Join(appDir, "Contents", "plugins"),
			filepath.Join(appDir, "plugins"),
		} {
			if exists, err := afs.DirExists(pluginsDir); err != nil || !exists {
				continue
			}
			dirs = append(dirs, jetbrainsPluginsDir{
				path:     pluginsDir,
				product:  product,
				bundled:  true,
				ideBuild: info.BuildNumber,
				uid:      uid,
			})
		}
	}

	return dirs
}

func (j *mqlJetbrainsPlugin) id() (string, error) {
	return j.__id, nil
}
