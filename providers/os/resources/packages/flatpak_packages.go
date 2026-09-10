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
)

const (
	FlatpakPkgFormat = "flatpak"

	// flatpakSystemInstallation is the system-wide installation root. Per-user
	// installations live under <home>/.local/share/flatpak.
	flatpakSystemInstallation = "/var/lib/flatpak"

	// flatpakListCmd enumerates installed applications. The column ORDER is the
	// parser's contract, ParseFlatpakList reads by position, so the command and
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
	flatpakListCmd = "flatpak list --app --columns=application,version,branch,arch,origin,active"

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
	flatpakRemotesCmd = "flatpak remotes --columns=name,url"
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

	pkgs, err := ParseFlatpakList(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	// Best effort: a host with no remotes configured, or an older flatpak
	// without the url column, still yields usable packages, just without the
	// repository_url qualifier.
	remotes := fpm.remoteURLs()
	for i := range pkgs {
		if url, ok := remotes[pkgs[i].Origin]; ok {
			pkgs[i].PUrl = addFlatpakRepositoryURL(pkgs[i].PUrl, url)
		}
	}

	return pkgs, nil
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
// `flatpak remotes --columns=name,url` into a name to URL map.
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
		remotes[name] = url
	}
	return remotes
}

// ParseFlatpakList parses the output of flatpakListCmd. Each line is
// tab-delimited: APPLICATION, VERSION, BRANCH, ARCH, ORIGIN, ACTIVE COMMIT.
//
// Trailing columns are optional so a short line from an older flatpak still
// yields an application and a version rather than nothing.
func ParseFlatpakList(r io.Reader) ([]Package, error) {
	var pkgs []Package
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

		column := func(i int) string {
			if i >= len(fields) {
				return ""
			}
			return flatpakColumnValue(fields[i])
		}

		appID := column(0)
		if appID == "" {
			continue
		}

		deployment := flatpakDeployment{
			appID:   appID,
			version: column(1),
			branch:  column(2),
			arch:    column(3),
			origin:  column(4),
			// flatpak truncates the commit column to 12 characters, and does so
			// even with the :f (full) ellipsization suffix, so this is a short
			// commit. The filesystem path reads the full 64-character one.
			commit: column(5),
		}
		pkgs = append(pkgs, deployment.toPackage())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
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
	afs := &afero.Afero{Fs: fpm.conn.FileSystem()}

	roots := []string{flatpakSystemInstallation}

	// Per-user installations under the usual home directory roots.
	for _, homeBase := range []string{"/home", "/root"} {
		entries, err := afs.ReadDir(homeBase)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			roots = append(roots, path.Join(homeBase, entry.Name(), ".local/share/flatpak"))
		}
	}

	var deployments []flatpakDeployment
	for _, root := range roots {
		found, err := parseFlatpakDir(afs, path.Join(root, "app"), root)
		if err != nil {
			continue
		}
		deployments = append(deployments, found...)
	}

	// One remote-name to URL map for the host, read from the repo config of
	// every installation root, so the filesystem path carries the same
	// provenance the CLI path does.
	remotes := map[string]string{}
	for _, root := range roots {
		for name, url := range parseFlatpakRepoConfig(afs, path.Join(root, "repo", "config")) {
			remotes[name] = url
		}
	}

	seen := map[string]struct{}{}
	pkgs := []Package{}
	for _, d := range deployments {
		if _, ok := seen[d.key()]; ok {
			continue
		}
		seen[d.key()] = struct{}{}
		pkg := d.toPackage()
		if url, ok := remotes[d.origin]; ok {
			pkg.PUrl = addFlatpakRepositoryURL(pkg.PUrl, url)
		}
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
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

				deploy, ok := resolveFlatpakDeployment(afs, path.Join(branchDir, branch), installationRoot, appID, arch, branch)
				if !ok {
					continue
				}
				deploy.appID = appID
				deploy.arch = arch
				deploy.branch = branch
				deployments = append(deployments, deploy)
			}
		}
	}

	return deployments, nil
}

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
func resolveFlatpakDeployment(afs *afero.Afero, branchDir, installationRoot, appID, arch, branch string) (flatpakDeployment, bool) {
	if deploy, ok := parseFlatpakDeployFile(afs, path.Join(branchDir, "active", "deploy")); ok {
		return deploy, true
	}

	entries, err := afs.ReadDir(branchDir)
	if err != nil {
		return flatpakDeployment{}, false
	}

	candidates := map[string]flatpakDeployment{}
	for _, entry := range entries {
		if !isFlatpakCommit(entry.Name()) {
			continue
		}
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
		return flatpakDeployment{}, false
	case 1:
		for _, deploy := range candidates {
			return deploy, true
		}
	}

	// More than one deployment on disk. The remote's ref names the commit the
	// origin is at, which is the one flatpak deployed.
	for commit, deploy := range candidates {
		refPath := path.Join(installationRoot, "repo", "refs", "remotes", deploy.origin, "app", appID, arch, branch)
		if ref, err := afs.ReadFile(refPath); err == nil && strings.TrimSpace(string(ref)) == commit {
			return deploy, true
		}
	}

	log.Debug().Str("app", appID).Str("branch", branch).Int("deployments", len(candidates)).
		Msg("mql[flatpak]> cannot tell which deployment is active, skipping")
	return flatpakDeployment{}, false
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
	origin, rest, ok := nextFlatpakString(data)
	if !ok || !isPrintableFlatpakValue(origin) {
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
// The value is the NUL-terminated string immediately following the key.
func flatpakDeployDictString(data []byte, key string) (string, bool) {
	needle := append([]byte(key), 0)
	idx := bytes.Index(data, needle)
	if idx < 0 {
		return "", false
	}
	value, _, ok := nextFlatpakString(data[idx+len(needle):])
	if !ok || !isPrintableFlatpakValue(value) {
		return "", false
	}
	return value, true
}

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
	if commit != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "commit", Value: commit})
	}
	return packageurl.NewPackageURL(
		FlatpakPkgFormat,
		origin,
		appID,
		version,
		qualifiers,
		"",
	).String()
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
