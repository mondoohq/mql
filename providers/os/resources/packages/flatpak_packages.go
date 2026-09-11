// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

const (
	FlatpakPkgFormat = "flatpak"

	// flatpakSystemInstallation is the system-wide installation root.
	flatpakSystemInstallation = "/var/lib/flatpak"

	// flatpakUserInstallation is a per-user installation root, relative to the
	// user's home directory.
	flatpakUserInstallation = ".local/share/flatpak"

	// flatpakListCmd enumerates installed applications. The column ORDER is the
	// parser's contract, parseFlatpakList reads by position, so the command and
	// the parser have to change together. That is why they sit next to each
	// other.
	//
	// Runtimes are excluded (--app). They are the shared library surface inside
	// the sandbox and do carry CVEs, but they cannot be matched today: their
	// version is a build string or nothing at all. Measured on a RHEL 10.2 host
	// with Flathub enabled:
	//
	//	org.freedesktop.Platform               freedesktop-sdk-25.08.16
	//	org.freedesktop.Platform.GL.default    26.1.6
	//	org.freedesktop.Platform.codecs-extra   (empty)
	//
	// Collecting them would add several unmatchable entries per host, plus the
	// per-app Locale and GL extensions. Revisit when an advisory source
	// publishes ranges keyed on a runtime's own version scheme.
	flatpakListCmd = "flatpak list --app --columns=application,version,branch,arch,origin,active,installation"

	// flatpakRemotesCmd resolves each remote NAME to its URL. The name alone
	// does not identify the publisher: it is local configuration, and a Flathub
	// build and a vendor build of the same application ID are different
	// software on different release trains. Measured on RHEL 10.2:
	//
	//	flathub  https://dl.flathub.org/repo/          org.mozilla.firefox 155.0.1  (rapid)
	//	rhel     oci+https://flatpaks.redhat.io/rhel/  org.mozilla.firefox 140.14.0 (ESR)
	//
	// The URL is what a consumer can trust; it travels in the PURL as the
	// repository_url qualifier, matching the qualifier pkg:oci already uses.
	flatpakRemotesCmd = "flatpak remotes --columns=name,url,options"
)

type FlatpakPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (fpm *FlatpakPkgManager) Name() string {
	return "Flatpak Package Manager"
}

func (fpm *FlatpakPkgManager) Format() string {
	return FlatpakPkgFormat
}

func (fpm *FlatpakPkgManager) List() ([]Package, error) {
	// Primary: flatpak CLI
	if fpm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		pkgs, err := fpm.listFromCLI()
		if err == nil {
			return pkgs, nil
		}
		log.Debug().Err(err).Msg("mql[flatpak]> could not enumerate via CLI, falling back to filesystem")
	}

	// Fallback: parse the installation directories
	return fpm.listFromFS()
}

func (fpm *FlatpakPkgManager) listFromCLI() ([]Package, error) {
	cmd, err := fpm.conn.RunCommand(flatpakListCmd)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, fmt.Errorf("flatpak list failed with exit code %d", cmd.ExitStatus)
	}

	deployments, err := parseFlatpakList(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	// Best effort: a host with no remotes configured, or an older flatpak
	// without the url column, still yields usable packages, just without the
	// repository_url qualifier.
	remotes := fpm.remoteURLs()
	return flatpakPackages(deployments, func(d flatpakDeployment) (string, bool) {
		url, ok := remotes[flatpakRemoteKey(d.scope, d.origin)]
		return url, ok
	}), nil
}

// remoteURLs maps remote name to URL. Returns nil on any failure; the URL is
// provenance metadata, never a reason to lose the package list.
func (fpm *FlatpakPkgManager) remoteURLs() map[string]string {
	cmd, err := fpm.conn.RunCommand(flatpakRemotesCmd)
	if err != nil {
		log.Debug().Err(err).Msg("mql[flatpak]> could not list remotes")
		return nil
	}
	if cmd.ExitStatus != 0 {
		log.Debug().Int("exit_status", cmd.ExitStatus).Msg("mql[flatpak]> flatpak remotes failed")
		return nil
	}
	return ParseFlatpakRemotes(cmd.Stdout)
}

// ParseFlatpakRemotes parses the output of
// `flatpak remotes --columns=name,url,options` into a (scope, name) to URL map.
//
// The SCOPE is load-bearing. `flatpak remotes` lists the system and the per-user
// remotes together with no installation column, and a remote name is scoped to
// its installation, so `flatpak remote-add --user rhel <other-url>` is legal and
// produces a second row named "rhel". Keying on the name alone lets that row
// overwrite the system remote's URL for every system-installed application --
// verified on a RHEL 10.2 host, where adding a user remote appends a row whose
// only distinguishing column is `options`:
//
//	flathub   https://dl.flathub.org/repo/           system
//	rhel      oci+https://flatpaks.redhat.io/rhel/   system,oci,no-gpg-verify
//	testuser  https://example.com/repo/              user
func ParseFlatpakRemotes(r io.Reader) map[string]string {
	remotes := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		url := flatpakColumnValue(fields[1])
		if name == "" || url == "" {
			continue
		}
		options := ""
		if len(fields) >= 3 {
			options = flatpakColumnValue(fields[2])
		}
		remotes[flatpakRemoteKey(flatpakScopeFromOptions(options), name)] = url
	}
	return remotes
}

// flatpakRemoteKey pairs an installation scope with a remote name.
func flatpakRemoteKey(scope, name string) string {
	return scope + "\x00" + name
}

// flatpakScopeUser and flatpakScopeSystem are the two BUILT-IN installation
// scopes. A host can also define custom system installations, which flatpak
// names in both the `installation` and `options` columns, and each of those is
// its own scope -- collapsing them onto "system" would let a custom
// installation's remote overwrite the default one's remote of the same name,
// which is the collision the (scope, name) key exists to prevent.
const (
	flatpakScopeUser   = "user"
	flatpakScopeSystem = "system"
)

// flatpakScopeFromOptions reads the scope out of a remote's options cell.
// Options is a comma-separated flag list ("system", "user", "oci",
// "no-gpg-verify", or a custom installation's name).
//
// "system" and "user" are matched POSITIVELY and win wherever they appear in
// the cell. Only when neither is present is an unrecognised token read as a
// custom installation's name, because those names are arbitrary and cannot be
// enumerated. Selecting the first non-flag token instead made the answer depend
// on field order against a list of flags we do not control: a flatpak release
// adding one flag we have not listed would, if it sorted before "system", have
// been returned as the scope and given every remote in that installation a
// scope no deployment uses -- silently losing all of them.
//
// The residual risk is narrow and unavoidable: a new flag preceding a custom
// installation's name in a cell that names no standard scope.
func flatpakScopeFromOptions(options string) string {
	custom := ""
	for _, opt := range strings.Split(options, ",") {
		opt = strings.TrimSpace(opt)
		if opt == flatpakScopeSystem || opt == flatpakScopeUser {
			return opt
		}
		if opt == "" || flatpakNonScopeOptions[opt] {
			continue
		}
		if custom == "" {
			custom = opt
		}
	}
	if custom != "" {
		return custom
	}
	return flatpakScopeSystem
}

// flatpakNonScopeOptions are the option flags that describe the remote rather
// than the installation it belongs to. Anything else in the cell names the
// installation.
var flatpakNonScopeOptions = map[string]bool{
	"oci":                true,
	"no-gpg-verify":      true,
	"no-enumerate":       true,
	"no-deps":            true,
	"disabled":           true,
	"gpg-verify":         true,
	"gpg-verify-summary": true,
}

func flatpakScopeFromInstallation(installation string) string {
	if installation == "" {
		return flatpakScopeSystem
	}
	return installation
}

// parseFlatpakList parses the output of flatpakListCmd. Each line is
// tab-delimited: APPLICATION, VERSION, BRANCH, ARCH, ORIGIN, ACTIVE COMMIT,
// INSTALLATION.
//
// Trailing columns are optional so a short line from an older flatpak still
// yields an application and a version rather than nothing.
//
// Deliberately NOT exported, and it returns deployments rather than packages.
// listFromCLI needs the deployments so it can stamp each one's remote URL, and
// an exported wrapper that skipped that step would be a second, more inviting
// entry point producing PURLs without the qualifier a consumer treats as the
// publisher boundary -- a difference that surfaces only as missing advisory
// matches.
func parseFlatpakList(r io.Reader) ([]flatpakDeployment, error) {
	var deployments []flatpakDeployment
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}

		appID := flatpakColumn(fields, 0)
		if appID == "" {
			continue
		}

		deployment := flatpakDeployment{
			appID:   appID,
			version: flatpakColumn(fields, 1),
			branch:  flatpakColumn(fields, 2),
			arch:    flatpakColumn(fields, 3),
			origin:  flatpakColumn(fields, 4),
			// flatpak truncates the commit column to 12 characters, and does so
			// even with the :f (full) ellipsization suffix, so this is a short
			// commit. The filesystem path reads the full 64-character one.
			commit: flatpakColumn(fields, 5),
			scope:  flatpakScopeFromInstallation(flatpakColumn(fields, 6)),
		}
		deployments = append(deployments, deployment)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return deployments, nil
}

// flatpakPackages turns deployments into packages: it collapses duplicates and
// stamps each package with its remote's URL.
//
// ONE implementation for both enumeration paths. They discover deployments
// differently but must agree on the resulting package set, and a dedup written
// twice is a dedup that drifts. The paths differ only in how a deployment maps
// to a remote URL, which is what remoteURL abstracts; pass nil when no URL is
// available.
//
// Deduplication matters because both paths can see one application twice.
// `flatpak list` prints a row per INSTALLATION, so an application installed
// both system-wide and per-user appears with identical application, version,
// branch, arch, origin and commit; the filesystem walk reaches the same
// deployment through more than one root.
func flatpakPackages(deployments []flatpakDeployment, remoteURL func(flatpakDeployment) (string, bool)) []Package {
	seen := make(map[string]struct{}, len(deployments))
	pkgs := make([]Package, 0, len(deployments))
	for _, d := range deployments {
		key := d.key()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		pkg := d.toPackage()
		if remoteURL != nil {
			if url, ok := remoteURL(d); ok {
				pkg.PUrl = addFlatpakRepositoryURL(pkg.PUrl, url)
			}
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

// flatpakColumn reads one cell by position, tolerating a short line from an
// older flatpak. A package-level function rather than a closure over the line's
// fields: this runs per package on every scanned asset.
func flatpakColumn(fields []string, i int) string {
	if i >= len(fields) {
		return ""
	}
	return flatpakColumnValue(fields[i])
}

// flatpakColumnValue normalizes one `flatpak --columns` cell. flatpak renders
// an unset cell either as an empty string or as a lone "-", depending on the
// column, and a literal "-" is never a meaningful value for the columns read
// here.
func flatpakColumnValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "-" {
		return ""
	}
	return s
}

// flatpakDeployment is one installed (application, arch, branch) deployment,
// however it was discovered. Both enumeration paths build this, so they cannot
// produce differently shaped packages.
type flatpakDeployment struct {
	appID   string
	version string
	branch  string
	arch    string
	origin  string
	commit  string

	// scope is the installation scope ("user" or "system") the deployment
	// belongs to. It pairs with origin to look up the remote's URL, because a
	// remote name means different things in different installations.
	scope string

	// installationRoot is the installation this deployment was found under
	// (/var/lib/flatpak, or a per-user root). It scopes the remote-name lookup;
	// it is not part of the identity, so key() ignores it -- the same
	// application at the same commit is the same software wherever it is
	// installed.
	installationRoot string
}

// key identifies a deployment. A system-wide and a per-user install of the same
// application at the same commit are the same software and collapse to one
// entry; different branches or commits stay apart.
func (d flatpakDeployment) key() string {
	return strings.Join([]string{d.appID, d.arch, d.branch, d.origin, d.commit}, "\x00")
}

func (d flatpakDeployment) toPackage() Package {
	return Package{
		Name:    d.appID,
		Version: d.version,
		Arch:    d.arch,
		Format:  FlatpakPkgFormat,
		Origin:  d.origin,
		PUrl:    newFlatpakPurl(d.appID, d.version, d.origin, d.branch, d.commit),
	}
}

func (fpm *FlatpakPkgManager) listFromFS() ([]Package, error) {
	return fpm.listFromFSWith(&afero.Afero{Fs: fpm.conn.FileSystem()})
}

// listFromFSWith is the filesystem enumeration against an explicit filesystem,
// so the walk can be tested without a connection.
func (fpm *FlatpakPkgManager) listFromFSWith(afs *afero.Afero) ([]Package, error) {
	roots := []string{flatpakSystemInstallation}

	// Per-user installations. /root IS a home directory; /home CONTAINS them.
	// Treating /root like /home builds /root/<subdir>/.local/share/flatpak and
	// never /root/.local/share/flatpak, so anything installed with
	// `sudo flatpak install --user` is invisible -- and the filesystem walk is
	// the ONLY path when a container image is scanned.
	roots = append(roots, path.Join("/root", flatpakUserInstallation))
	if entries, err := afs.ReadDir("/home"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			roots = append(roots, path.Join("/home", entry.Name(), flatpakUserInstallation))
		}
	}

	// Remotes are resolved PER INSTALLATION ROOT, never merged. A remote name is
	// scoped to its installation: `flatpak remote-add --user rhel <other-url>`
	// is legal and would, in a merged map, overwrite the system `rhel` entry and
	// hand every system-installed Red Hat Flatpak a foreign repository_url.
	// A consumer that derives the publisher from that URL then reads the
	// deployment as coming from somewhere else, which is precisely the boundary
	// the URL exists to establish.
	remoteURLs := map[string]map[string]string{}
	var deployments []flatpakDeployment
	for _, root := range roots {
		found, err := parseFlatpakDir(afs, path.Join(root, "app"), root)
		if err != nil {
			continue
		}
		deployments = append(deployments, found...)
		remoteURLs[root] = parseFlatpakRepoConfig(afs, path.Join(root, "repo", "config"))
	}

	return flatpakPackages(deployments, func(d flatpakDeployment) (string, bool) {
		url, ok := remoteURLs[d.installationRoot][d.origin]
		return url, ok
	}), nil
}

// parseFlatpakDir enumerates Flatpak deployments below an installation's app
// directory: <appDir>/<app-id>/<arch>/<branch>/active/deploy.
//
// The deploy file is REQUIRED, not incidental. It is the only per-deployment
// record of the origin and the commit, and demanding it also keeps the walk
// honest: "current" and "active" are symlinks that some filesystem backends
// report as directories, and a backend that flattens a listing would otherwise
// have every path below the deployment mistaken for an arch or a branch. One
// installed application produced 207 identical packages that way.
func parseFlatpakDir(afs *afero.Afero, appDir, installationRoot string) ([]flatpakDeployment, error) {
	apps, err := afs.ReadDir(appDir)
	if err != nil {
		return nil, fmt.Errorf("could not read flatpak app directory at %s: %w", appDir, err)
	}

	var deployments []flatpakDeployment
	for _, app := range apps {
		if !isFlatpakDeploymentDir(app.Name()) || !app.IsDir() {
			continue
		}
		appID := app.Name()

		// path.Join (not filepath.Join) is intentional, these are always Linux
		// filesystem paths, even when mql runs on a different OS.
		archDir := path.Join(appDir, appID)
		arches, err := afs.ReadDir(archDir)
		if err != nil {
			continue
		}

		for _, archEntry := range arches {
			if !isFlatpakDeploymentDir(archEntry.Name()) || !archEntry.IsDir() {
				continue
			}
			arch := archEntry.Name()

			branchDir := path.Join(archDir, arch)
			branches, err := afs.ReadDir(branchDir)
			if err != nil {
				continue
			}

			for _, branchEntry := range branches {
				if !isFlatpakDeploymentDir(branchEntry.Name()) || !branchEntry.IsDir() {
					continue
				}
				branch := branchEntry.Name()

				deploy, outcome := resolveFlatpakDeployment(afs, path.Join(branchDir, branch), installationRoot, appID, arch, branch)
				// Only an explicit OK publishes a package. Anything else skips,
				// including an outcome added later: falling through on an
				// unrecognised one would report a zero-value deployment, which
				// is the versionless, originless package this reader exists to
				// stop producing.
				if outcome != flatpakResolveOK {
					if outcome == flatpakResolveUnreadable {
						// A branch directory exists but no deployment could be
						// read from it. Warn rather than skip silently: deploy
						// is a versioned GVariant tuple, so a future flatpak
						// that reorders or prepends a field would make every
						// file fail to parse and this function would return
						// zero packages for a host full of Flatpaks, with
						// List() still reporting success. One WARN naming the
						// application is the difference between "we lost the
						// inventory" and total silence.
						log.Warn().Str("app", appID).Str("arch", arch).Str("branch", branch).
							Str("installation", installationRoot).
							Msg("mql[flatpak]> could not read a deployment record; application not reported")
					}
					continue
				}
				deploy.appID = appID
				deploy.arch = arch
				deploy.branch = branch
				deploy.installationRoot = installationRoot
				deployments = append(deployments, deploy)
			}
		}
	}

	return deployments, nil
}

// flatpakResolveOutcome says why a branch directory produced no deployment.
//
// The two failures are not the same event and must not log the same way. A
// directory that holds nothing deployment-shaped is simply not a branch, and on
// a container IMAGE there are many of them: the image is read as a layered tar
// whose ReadDir reports every descendant, not just direct children, so each
// file under the deployment (locale codes, icon sizes, bin, browser) comes back
// as a branch candidate. One installed application produced 154 of them. Those
// must be silent. A directory that does hold commit-named subdirectories but
// yielded no readable record is the case worth a WARN.
type flatpakResolveOutcome int

const (
	// flatpakResolveOK means a deployment was read.
	flatpakResolveOK flatpakResolveOutcome = iota
	// flatpakResolveNotADeployment means the directory is not a branch.
	flatpakResolveNotADeployment
	// flatpakResolveUnreadable means it looks like a branch but no deployment
	// record could be read from it.
	flatpakResolveUnreadable
)

// resolveFlatpakDeployment reads the deploy record for one
// <app>/<arch>/<branch> directory.
//
// The obvious path is the `active` symlink flatpak maintains beside the commit
// directories, and on a live filesystem that is exactly right: it names the
// deployment currently in use, unambiguously.
//
// It is not always traversable. A container IMAGE is read as a layered tar, and
// symlinks in it do not resolve, so `<branch>/active/deploy` simply does not
// exist there. That is the quiet half of the old bug: the previous
// implementation read `active/metadata`, got nothing on an image, and reported
// a package with no version and no origin rather than reporting that it could
// not read the deployment.
//
// So fall back to the commit directories themselves, whose names are the
// commit checksums. One candidate is unambiguous. Several means an update was
// interrupted or has not been pruned yet, and the filesystem alone cannot say
// which is live -- resolve that against the remote's OSTree ref, and if it
// still cannot be decided, report nothing for this branch rather than guess a
// version for the host.
func resolveFlatpakDeployment(afs *afero.Afero, branchDir, installationRoot, appID, arch, branch string) (flatpakDeployment, flatpakResolveOutcome) {
	if deploy, ok := parseFlatpakDeployFile(afs, path.Join(branchDir, "active", "deploy")); ok {
		return deploy, flatpakResolveOK
	}

	entries, err := afs.ReadDir(branchDir)
	if err != nil {
		return flatpakDeployment{}, flatpakResolveNotADeployment
	}

	candidates := map[string]flatpakDeployment{}
	// Commit-named subdirectories are what makes a directory a branch. Counting
	// them separately from the ones that parsed is what tells "this is not a
	// branch at all" apart from "this is a branch we could not read".
	commitDirs := 0
	for _, entry := range entries {
		if !isFlatpakCommit(entry.Name()) {
			continue
		}
		commitDirs++
		deploy, ok := parseFlatpakDeployFile(afs, path.Join(branchDir, entry.Name(), "deploy"))
		if !ok {
			continue
		}
		// The directory name and the deploy record must agree, or this is not
		// the deployment it claims to be.
		if deploy.commit != entry.Name() {
			continue
		}
		candidates[entry.Name()] = deploy
	}

	switch len(candidates) {
	case 0:
		if commitDirs == 0 {
			return flatpakDeployment{}, flatpakResolveNotADeployment
		}
		return flatpakDeployment{}, flatpakResolveUnreadable
	case 1:
		for _, deploy := range candidates {
			return deploy, flatpakResolveOK
		}
	}

	// More than one deployment on disk. The remote's ref names the commit the
	// origin is at, which is the one flatpak deployed.
	for commit, deploy := range candidates {
		refPath := path.Join(installationRoot, "repo", "refs", "remotes", deploy.origin, "app", appID, arch, branch)
		if ref, err := afs.ReadFile(refPath); err == nil && strings.TrimSpace(string(ref)) == commit {
			return deploy, flatpakResolveOK
		}
	}

	log.Debug().Str("app", appID).Str("branch", branch).Int("deployments", len(candidates)).
		Msg("mql[flatpak]> cannot tell which deployment is active, skipping")
	return flatpakDeployment{}, flatpakResolveUnreadable
}

// isFlatpakDeploymentDir rejects the two symlinks flatpak keeps alongside real
// directories: "current" beside the arch directories and "active" beside the
// commit directories. Both point back into the tree, so following them yields
// the same deployment under a second path.
func isFlatpakDeploymentDir(name string) bool {
	return name != "" && name != "current" && name != "active" && !strings.HasPrefix(name, ".")
}

// flatpakDeployMaxSize caps the read of a deploy file. Real ones are a few
// hundred bytes; this exists so a corrupt or hostile file cannot be read whole
// into memory.
const flatpakDeployMaxSize = 64 * 1024

// parseFlatpakDeployFile reads <deployment>/active/deploy and extracts the
// origin, the commit and the version.
//
// # Why not the metadata file
//
// The obvious-looking source is `metadata` next to it, but a real deployment's
// metadata contains NEITHER an `origin=` nor a `version=` key. It holds only
// [Application], [Extension ...], [Context] and [Session Bus Policy] sections
// describing the sandbox. Reading those keys yields a package with no version
// and no origin, which cannot be matched against any advisory and has lost the
// only signal that says which remote it came from.
//
// # The format
//
// `deploy` is GVariant, and the fields this needs sit in the parts of the
// encoding that are plain, NUL-terminated text:
//
//	flathub\0c84b98e041e5...cb67\0...appdata-version\0154.0.1\0\0s...
//
// The origin and the commit are the tuple's two leading string fields, so they
// are always the first two NUL-terminated strings in the file. `appdata-version`
// is a dictionary key whose string value follows it directly; this is the same
// value `flatpak list --columns=version` reports.
//
// Everything read is validated before it is used (the commit must be 64 hex
// characters, the strings must be printable and bounded), and a file that does
// not match the expected shape is skipped rather than guessed at.
func parseFlatpakDeployFile(afs *afero.Afero, deployPath string) (flatpakDeployment, bool) {
	f, err := afs.Open(deployPath)
	if err != nil {
		return flatpakDeployment{}, false
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, flatpakDeployMaxSize))
	if err != nil {
		log.Debug().Err(err).Str("path", deployPath).Msg("mql[flatpak]> could not read deploy file")
		return flatpakDeployment{}, false
	}

	return parseFlatpakDeploy(data)
}

// parseFlatpakDeploy is the pure half of parseFlatpakDeployFile, split out so
// the byte-level parsing is testable against a real deploy file.
func parseFlatpakDeploy(data []byte) (flatpakDeployment, bool) {
	// An EMPTY origin is a legitimate value, not a parse failure: flatpak stores
	// the origin as `origin ? origin : ""`, so a bundle-installed application
	// (`flatpak install --bundle app.flatpak`) has none. Rejecting the record
	// would drop the application from the inventory entirely -- and on a
	// container image the filesystem walk is the only path -- to lose a field
	// that only the provenance qualifier needs. The commit and version in the
	// same record are still good.
	origin, rest, ok := nextFlatpakString(data)
	if !ok || (origin != "" && !isPrintableFlatpakValue(origin)) {
		return flatpakDeployment{}, false
	}

	commit, _, ok := nextFlatpakString(rest)
	if !ok || !isFlatpakCommit(commit) {
		// A deployment always records the commit it was installed from. A file
		// that does not start with (origin, commit) is not one we understand,
		// and guessing at the rest of it would invent an identity.
		return flatpakDeployment{}, false
	}

	deployment := flatpakDeployment{origin: origin, commit: commit}
	if version, ok := flatpakDeployDictString(data, "appdata-version"); ok {
		deployment.version = version
	}
	return deployment, true
}

// nextFlatpakString reads one NUL-terminated string and returns the remainder.
func nextFlatpakString(data []byte) (string, []byte, bool) {
	idx := bytes.IndexByte(data, 0)
	if idx < 0 {
		return "", nil, false
	}
	return string(data[:idx]), data[idx+1:], true
}

// flatpakDeployDictString reads the string value of a GVariant dictionary key.
//
// The value does NOT always sit immediately after the key. GVariant aligns the
// variant inside an {sv} entry to 8 bytes, so the serializer inserts up to 7
// NUL padding bytes after the key's own terminator whenever len(key)+1 is not a
// multiple of 8. Both shapes occur in one real deploy file:
//
//	appdata-version\0154.0.1\0        15+1 = 16, aligned, no padding
//	appdata-name\0\0\0\0Firefox\0        12+1 = 13, three padding bytes
//
// Reading the byte right after the key therefore yields "" for half the keys in
// the file. This originally happened to work only because the one key needed
// was 15 characters long.
func flatpakDeployDictString(data []byte, key string) (string, bool) {
	needle := append([]byte(key), 0)
	// The match must START a string, not land inside one. bytes.Index finds the
	// key bytes anywhere in the blob, so a longer key ending in the same suffix
	// ("xa-appdata-version" for "appdata-version") or a value that happens to
	// contain the key text would both match, and the value read back would
	// belong to a different field. A string in this blob is NUL-terminated, so
	// the byte before a genuine key is either a NUL or the start of the buffer.
	// Keep searching rather than giving up: the real key may sit after a
	// spurious hit.
	idx := -1
	for off := 0; ; {
		hit := bytes.Index(data[off:], needle)
		if hit < 0 {
			return "", false
		}
		hit += off
		if hit == 0 || data[hit-1] == 0 {
			idx = hit
			break
		}
		off = hit + 1
	}
	// The gap is COMPUTED, not scanned. Scanning for NULs cannot tell alignment
	// padding from a value that is itself the empty string -- it would consume
	// the empty value's own terminator and return the following type-signature
	// byte as the version. The offset of the key within the buffer is known, so
	// the padding length is arithmetic: the value starts at the next multiple
	// of the variant's 8-byte alignment.
	end := idx + len(needle)
	pad := (flatpakGVariantAlignment - (end % flatpakGVariantAlignment)) % flatpakGVariantAlignment
	if end+pad > len(data) {
		return "", false
	}
	// A well-formed entry has exactly `pad` NUL bytes here. Verifying rather
	// than assuming means a buffer that is not laid out as GVariant is refused
	// instead of read at the wrong offset -- the value would otherwise be a
	// truncation of the real one, which is worse than no value at all.
	for i := end; i < end+pad; i++ {
		if data[i] != 0 {
			return "", false
		}
	}

	value, _, ok := nextFlatpakString(data[end+pad:])
	if !ok || !isPrintableFlatpakValue(value) {
		return "", false
	}
	return value, true
}

// flatpakGVariantAlignment is the alignment GVariant gives the variant inside
// an {sv} dictionary entry.
const flatpakGVariantAlignment = 8

// flatpakValueMaxLen bounds a value read out of the GVariant blob. Application
// versions and remote names are short; anything longer is a sign the parse
// walked into binary data rather than a string field.
const flatpakValueMaxLen = 256

func isPrintableFlatpakValue(s string) bool {
	if s == "" || len(s) > flatpakValueMaxLen {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// isFlatpakCommit reports whether s is an OSTree commit checksum: 64 lowercase
// hex characters.
func isFlatpakCommit(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// parseFlatpakRepoConfig reads remote name to URL out of an installation's
// OSTree repo config, which is the filesystem equivalent of
// `flatpak remotes --columns=name,url`:
//
//	[remote "flathub"]
//	url=https://dl.flathub.org/repo/
//
// Returns nil when the file is absent or unreadable; provenance is enrichment,
// never a reason to drop a package.
func parseFlatpakRepoConfig(afs *afero.Afero, configPath string) map[string]string {
	f, err := afs.Open(configPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	remotes := map[string]string{}
	remote := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			remote = ""
			if name, ok := strings.CutPrefix(line, `[remote "`); ok {
				remote = strings.TrimSuffix(strings.TrimSuffix(name, "]"), `"`)
			}
			continue
		}
		if remote == "" {
			continue
		}
		if url, ok := strings.CutPrefix(line, "url="); ok {
			if url = strings.TrimSpace(url); url != "" {
				remotes[remote] = url
			}
		}
	}
	return remotes
}

// newFlatpakPurl creates a PURL for a Flatpak application:
//
//	pkg:flatpak/<origin>/<app-id>@<version>?branch=<branch>&commit=<commit>
//
// The origin (the remote) is the namespace because it is provenance: one
// application ID names different software depending on where it came from, so
// dropping it makes a Flathub build and a vendor build indistinguishable.
//
// branch and commit travel as qualifiers rather than as the version. The commit
// is the only precise identity a deployment has, but it is a hash: it cannot be
// ordered, so it can never stand in for a version in a range comparison.
// Consumers strip qualifiers before matching, so these are carried for identity
// and evidence without affecting which advisories apply.
//
// A deployment whose version is unknown keeps an empty version deliberately.
// Substituting the branch or the commit would produce a PURL that looks
// versioned and can never match, which is worse than one that is visibly
// unversioned.
func newFlatpakPurl(appID, version, origin, branch, commit string) string {
	if appID == "" {
		return ""
	}
	qualifiers := packageurl.Qualifiers{}
	if branch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "branch", Value: branch})
	}
	if commit = shortFlatpakCommit(commit); commit != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "commit", Value: commit})
	}
	return packageurl.NewPackageURL(
		// The purl TYPE is owned by the purl package, not by this collector:
		// the server matches on it, so a second literal here is a second place
		// for the two to drift apart silently. Same split as snap, where
		// SnapPkgFormat is the Package.Format and purl.TypeSnap is the purl type.
		string(purl.TypeFlatpak),
		origin,
		appID,
		version,
		qualifiers,
		"",
	).String()
}

// flatpakShortCommitLen is the number of checksum characters the PURL carries.
//
// The two enumeration paths know the commit to different precisions: the
// filesystem reads the full 64-character checksum, while `flatpak list`
// truncates its column to 12 and does so even with the :f (full) suffix.
// Publishing whichever one happened to be available would give the same
// deployment two different PURLs depending on how the asset was reached -- a
// running container and its own image would land in the inventory as two
// packages. Both paths publish the same 12-character prefix instead, which is
// what flatpak itself shows and is ample to tell one deployment of an
// application from another.
const flatpakShortCommitLen = 12

func shortFlatpakCommit(commit string) string {
	if len(commit) > flatpakShortCommitLen {
		return commit[:flatpakShortCommitLen]
	}
	return commit
}

// addFlatpakRepositoryURL adds the remote's URL to a PURL as the
// repository_url qualifier, the same qualifier pkg:oci uses to name a registry.
// The remote NAME is local configuration; the URL is what identifies the
// publisher.
func addFlatpakRepositoryURL(purl, url string) string {
	if purl == "" || url == "" {
		return purl
	}
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		return purl
	}
	parsed.Qualifiers = append(parsed.Qualifiers,
		packageurl.Qualifier{Key: "repository_url", Value: url})
	return parsed.String()
}

func (fpm *FlatpakPkgManager) Available() (map[string]PackageUpdate, error) {
	return map[string]PackageUpdate{}, nil
}

func (fpm *FlatpakPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	return nil, nil
}
