// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/ulikunitz/xz"
)

const (
	pacmanConf = "/etc/pacman.conf"
	// pacmanDefaultDBPath is where pacman keeps its databases unless the
	// configuration says otherwise; the sync databases are under sync/.
	pacmanDefaultDBPath = "/var/lib/pacman/"

	// pacmanMaxSyncDB caps the size of one compressed sync database. Arch's
	// extra.db is 9 MB.
	pacmanMaxSyncDB = 256 * 1024 * 1024
	// pacmanMaxSyncDBText caps what one sync database decompresses to.
	pacmanMaxSyncDBText = 2 * 1024 * 1024 * 1024
	// pacmanMaxRepos caps the repositories read from pacman.conf.
	pacmanMaxRepos = 64
	// pacmanMaxConfFile caps pacman.conf, an included file and a keyring
	// listing.
	pacmanMaxConfFile = 1024 * 1024
	// pacmanMaxKeyringFile caps one keyring. archlinux.gpg is 1.8 MB.
	pacmanMaxKeyringFile = 32 * 1024 * 1024
)

// pacmanOSKeyringPackages are, per distribution, the packages that install the
// keys the distribution's packagers sign its packages with. A package signed
// by a key from one of these keyrings is the operating system's; the key of a
// repository an administrator added (`pacman-key --lsign-key`) lives in the
// host's own keyring and in no such package.
//
// Each entry was read off the distribution's own image with `pacman -Ql`.
// Manjaro's own repositories carry both: it builds some packages itself and
// signs them with a Manjaro key, and copies the rest unchanged from Arch, with
// the Arch packager's signature. Of the 320 packages in the core database of
// manjarolinux/base (2026-11-27), 254 are signed with a key from archlinux.gpg
// and 66 with one from manjaro.gpg. The residual risk is an Arch repository an
// administrator adds to a Manjaro host: its packages read as the operating
// system's.
var pacmanOSKeyringPackages = map[string][]string{
	"arch":    {"archlinux-keyring"},
	"manjaro": {"manjaro-keyring", "archlinux-keyring"},
}

// pacmanKeyringDir is where a keyring package puts its keys.
const pacmanKeyringDir = "usr/share/pacman/keyrings"

// pacmanRepo is one repository of pacman.conf.
type pacmanRepo struct {
	name string
	// server is the first Server of the repository, or of the mirror list it
	// includes, with $repo and $arch not yet replaced.
	server string
}

type pacmanConfig struct {
	repos  []pacmanRepo
	dbPath string
	// incomplete is true when the configuration names repositories this
	// reader did not place: an Include outside a repository section, whose
	// file may define sections of its own, or more repositories than the cap.
	incomplete bool
}

// parsePacmanConf reads pacman.conf. read returns the content of an included
// file, or nil. The sections are [options] and one per repository; a
// repository names its mirrors with Server lines, directly or through an
// Include of a mirror list.
func parsePacmanConf(data []byte, read func(p string) []byte) pacmanConfig {
	cfg := pacmanConfig{dbPath: pacmanDefaultDBPath}
	section := ""
	var cur *pacmanRepo
	finish := func() {
		if cur != nil {
			cfg.repos = append(cfg.repos, *cur)
			cur = nil
		}
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			finish()
			section = line[1 : len(line)-1]
			if section != "options" && section != "" {
				if len(cfg.repos) < pacmanMaxRepos {
					cur = &pacmanRepo{name: section}
				} else {
					cfg.incomplete = true
				}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case section == "options" && key == "DBPath" && value != "":
			cfg.dbPath = strings.TrimSuffix(value, "/") + "/"
		case cur == nil && key == "Include":
			// an included file can hold [repository] sections of its own
			cfg.incomplete = true
		case cur != nil && key == "Server" && cur.server == "":
			cur.server = value
		case cur != nil && key == "Include" && cur.server == "":
			// mirror lists are under /etc, as pacman's own are
			if p := path.Clean(value); strings.HasPrefix(p, "/etc/") && read != nil {
				cur.server = firstPacmanServer(read(p))
			}
		}
	}
	finish()
	return cfg
}

// firstPacmanServer returns the first Server line of a mirror list.
func firstPacmanServer(data []byte) string {
	for line := range strings.SplitSeq(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(key) == "Server" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// url is the repository's address with $repo and $arch replaced and credentials
// removed.
func (r pacmanRepo) url(arch string) string {
	if r.server == "" {
		return ""
	}
	s := strings.NewReplacer("$repo", r.name, "$arch", arch).Replace(r.server)
	return sanitizeRepoURL(s)
}

// pacmanSyncEntry is one package a sync database lists.
type pacmanSyncEntry struct {
	version, arch string
	// osSigned is true when the package's signature was made by a key from the
	// operating system's keyring. unsigned is true when the database lists no
	// signature for it.
	osSigned bool
	// buildDate is %BUILDDATE% of the listed package. The package installed
	// from this listing carries the same value.
	buildDate string
	repo      *pacmanRepoDB
}

// pacmanRepoDB is one repository whose sync database was read.
type pacmanRepoDB struct {
	pacmanRepo
	url string
}

// pacmanSyncDBs is what the sync databases say about the installed packages.
type pacmanSyncDBs struct {
	// any is true when at least one database was read.
	any bool
	// complete is true when every repository pacman.conf names has a sync
	// database on the system.
	complete bool
	// trustKnown is false when the operating system's keyring was not found.
	trustKnown bool
	byName     map[string][]pacmanSyncEntry
}

// Sources says where each pacman package came from (ADR 049).
//
// pacman records no repository for an installed package. The installed
// (name, version) is matched against the sync databases `pacman -Sy` downloaded
// (/var/lib/pacman/sync/*.db), and the listing carries the signature on the
// package: made by a key from the distribution's keyring package, the package
// is the operating system's; made by another key, or unsigned, it came from a
// repository an administrator added. A package in no sync database is foreign
// (`pacman -Qm`): built locally, from the AUR, or installed with `pacman -U`.
// An image that never ran `pacman -Sy` has no sync database; nothing can be
// decided there, and the answer is null.
func (ppm *PacmanPkgManager) Sources(pkgs []Package) ([]Source, error) {
	platform := ""
	if ppm.platform != nil {
		platform = ppm.platform.Name
	}
	files := newSourceFiles(ppm.conn)
	return pacmanSources(pkgs, readPacmanSyncDBs(files, platform, pkgs)), nil
}

// pacmanArch is the architecture the $arch of a mirror address stands for: the
// one most installed packages carry. An architecture-independent package says
// "any".
func pacmanArch(pkgs []Package) string {
	counts := map[string]int{}
	best := ""
	for i := range pkgs {
		a := pkgs[i].Arch
		if a == "" || a == "any" {
			continue
		}
		counts[a]++
		if counts[a] > counts[best] {
			best = a
		}
	}
	return best
}

func readPacmanSyncDBs(files *sourceFiles, platform string, pkgs []Package) pacmanSyncDBs {
	out := pacmanSyncDBs{byName: map[string][]pacmanSyncEntry{}}
	var conf []byte
	if data, err := files.read(pacmanConf); err == nil && len(data) <= pacmanMaxConfFile {
		conf = data
	}
	cfg := parsePacmanConf(conf, func(p string) []byte {
		data, err := files.read(p)
		if err != nil || len(data) > pacmanMaxConfFile {
			return nil
		}
		return data
	})
	if len(cfg.repos) == 0 {
		return out
	}

	osKeys, keysKnown := readPacmanOSKeys(files, platform, pkgs)
	out.trustKnown = keysKnown

	installed := make(map[string]struct{}, len(pkgs))
	for i := range pkgs {
		if pkgs[i].Format == PacmanPkgFormat {
			installed[pkgs[i].Name] = struct{}{}
		}
	}
	arch := pacmanArch(pkgs)

	out.complete = !cfg.incomplete
	// A sync database no repository of the configuration explains belongs to a
	// repository this reader did not place, or one since removed. A package
	// may have come from it.
	if pacmanUnexplainedDB(files.fs, cfg) {
		out.complete = false
	}
	for _, repo := range cfg.repos {
		dbFile := path.Join(cfg.dbPath, "sync", repo.name+".db")
		fi, err := files.fs.Stat(dbFile)
		if err != nil || fi.IsDir() || fi.Size() > pacmanMaxSyncDB {
			out.complete = false
			continue
		}
		data, err := afero.ReadFile(files.fs, dbFile)
		if err != nil {
			out.complete = false
			continue
		}
		db := &pacmanRepoDB{pacmanRepo: repo, url: repo.url(arch)}
		entries, err := readPacmanSyncDB(data, installed, osKeys, db)
		if err != nil {
			log.Debug().Err(err).Str("path", dbFile).Msg("mql[packages]> could not read a pacman sync database")
			out.complete = false
			continue
		}
		out.any = true
		for name, es := range entries {
			out.byName[name] = append(out.byName[name], es...)
		}
	}
	return out
}

// pacmanUnexplainedDB reports a "*.db" file in the sync directory that no
// repository of the configuration names.
func pacmanUnexplainedDB(fs afero.Fs, cfg pacmanConfig) bool {
	entries, err := afero.ReadDir(fs, path.Join(cfg.dbPath, "sync"))
	if err != nil {
		return false
	}
	known := map[string]bool{}
	for _, r := range cfg.repos {
		known[r.name+".db"] = true
	}
	for i, e := range entries {
		if i >= 1024 {
			return true
		}
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".db") && !known[e.Name()] {
			return true
		}
	}
	return false
}

// readPacmanOSKeys collects the keys in the keyring files the distribution's
// keyring packages own. The second result is false when none of them is
// installed or none holds a key: then no package can be attributed to the
// operating system or to anyone else.
func readPacmanOSKeys(files *sourceFiles, platform string, pkgs []Package) (openPGPKeys, bool) {
	installed := map[string]string{}
	for i := range pkgs {
		if pkgs[i].Format == PacmanPkgFormat {
			installed[pkgs[i].Name] = pkgs[i].Version
		}
	}
	var keyringFiles, revokedFiles []string
	for _, name := range pacmanOSKeyringPackages[platform] {
		version, ok := installed[name]
		if !ok {
			continue
		}
		data, err := files.read(path.Join(PacmanLocalDB, name+"-"+version, "files"))
		if err != nil || len(data) > pacmanMaxConfFile {
			continue
		}
		for _, f := range pacmanOwnedFiles(data) {
			switch {
			case path.Dir(f) != pacmanKeyringDir:
			case path.Ext(f) == ".gpg":
				keyringFiles = append(keyringFiles, "/"+f)
			case strings.HasSuffix(f, "-revoked"):
				revokedFiles = append(revokedFiles, "/"+f)
			}
		}
	}
	files.prefetch(append(append([]string{}, keyringFiles...), revokedFiles...))
	// The keyring package lists the fingerprints of the keys it revoked, one
	// per line, in a "<distribution>-revoked" file next to the keyring.
	revoked := map[string]bool{}
	for _, f := range revokedFiles {
		if data, err := files.read(f); err == nil && len(data) <= pacmanMaxConfFile {
			for line := range strings.SplitSeq(string(data), "\n") {
				if fp := strings.ToUpper(strings.TrimSpace(line)); fp != "" {
					revoked[fp] = true
				}
			}
		}
	}
	keys := openPGPKeys{}
	for _, f := range keyringFiles {
		data, err := files.read(f)
		if err != nil || len(data) > pacmanMaxKeyringFile {
			continue
		}
		keys.addKeyringExcept(data, revoked)
	}
	return keys, len(keys) > 0
}

// pacmanOwnedFiles lists the paths of a local database `files` record: a
// %FILES% header, then one path per line, without the leading slash.
func pacmanOwnedFiles(data []byte) []string {
	var out []string
	inFiles := false
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "%FILES%":
			inFiles = true
		case strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%"):
			inFiles = false
		case inFiles && line != "":
			out = append(out, line)
		}
	}
	return out
}

// readPacmanSyncDB reads one sync database: a tar archive, compressed, with a
// "<name>-<version>/desc" record per package. Only the records of installed
// names are kept.
func readPacmanSyncDB(data []byte, installed map[string]struct{}, osKeys openPGPKeys, db *pacmanRepoDB) (map[string][]pacmanSyncEntry, error) {
	r, closeFn, err := pacmanDecompress(data)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	out := map[string][]pacmanSyncEntry{}
	tr := tar.NewReader(newLimitedReader(r, pacmanMaxSyncDBText))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// a database cut short, damaged or too large lists packages it
			// did not show; reading on would turn them into "listed nowhere"
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || path.Base(hdr.Name) != "desc" {
			continue
		}
		if hdr.Size > pacmanMaxConfFile {
			return nil, errTooLarge
		}
		raw, err := io.ReadAll(io.LimitReader(tr, pacmanMaxConfFile))
		if err != nil {
			return nil, err
		}
		fields := parsePacmanDescSections(bytes.NewReader(raw))
		name := fields["%NAME%"]
		if _, ok := installed[name]; !ok {
			continue
		}
		out[name] = append(out[name], pacmanSyncEntry{
			version:   fields["%VERSION%"],
			arch:      fields["%ARCH%"],
			buildDate: fields["%BUILDDATE%"],
			osSigned:  pacmanSignedBy(fields["%PGPSIG%"], osKeys),
			repo:      db,
		})
	}
	return out, nil
}

// pacmanSignedBy reports whether a package signature, as a sync database lists
// it (base64 of a detached OpenPGP signature), was made by one of the keys. The
// package file itself is not on the system, so the signature is matched by its
// issuer and not re-verified: pacman verified it when it installed the package.
func pacmanSignedBy(pgpsig string, keys openPGPKeys) bool {
	if pgpsig == "" || len(keys) == 0 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(pgpsig)
	if err != nil {
		return false
	}
	return keys.signedBy(signatureIssuers(raw))
}

// pacmanDecompress opens a sync database, whichever way it is compressed.
func pacmanDecompress(data []byte) (io.Reader, func(), error) {
	noop := func() {}
	switch {
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, noop, err
		}
		return gz, func() { gz.Close() }, nil
	case bytes.HasPrefix(data, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		z, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, noop, err
		}
		return z, z.Close, nil
	case bytes.HasPrefix(data, []byte{0xfd, '7', 'z', 'X', 'Z', 0}):
		x, err := xz.NewReader(bytes.NewReader(data))
		return x, noop, err
	case bytes.HasPrefix(data, []byte("BZh")):
		return bzip2.NewReader(bytes.NewReader(data)), noop, nil
	}
	// an uncompressed tar archive has "ustar" at offset 257; anything else is a
	// format this reader does not know (.lz4, .lz, .lrz, .lzo and .Z are
	// accepted by repo-add), and must not read as an empty database
	if len(data) >= 262 && bytes.Equal(data[257:262], []byte("ustar")) {
		return bytes.NewReader(data), noop, nil
	}
	return nil, noop, errors.New("unknown sync database format")
}

// pacmanSources decides each package's source:
//
//   - the installed version in a sync database whose package carries a
//     signature from the operating system's keyring: os
//   - the installed version only in databases whose package carries another
//     key, or none: vendor-repository
//   - the name in no sync database, with a database for every repository
//     pacman.conf names: direct, a foreign package (`pacman -Qm`)
//   - the version in no database, the name only in OS-signed packages: os.
//     Arch's repositories list only the current version, so a package that
//     missed an update matches the name and not the version.
//   - the version in no database while a third-party repository lists the
//     name, a repository without a database, no keyring to tell the operating
//     system's key, or an operating system package pacman installed without
//     checking its signature: null
func pacmanSources(pkgs []Package, dbs pacmanSyncDBs) []Source {
	out := make([]Source, len(pkgs))
	for i := range pkgs {
		pkg := &pkgs[i]
		if pkg.Format != PacmanPkgFormat {
			out[i] = DefaultSource(*pkg)
			continue
		}
		if !dbs.any || !dbs.trustKnown {
			out[i] = unknownSource()
			continue
		}
		out[i] = pacmanSource(pkg, dbs.byName[pkg.Name], dbs.complete)
	}
	return out
}

func pacmanSource(pkg *Package, entries []pacmanSyncEntry, complete bool) Source {
	if len(entries) == 0 {
		if !complete {
			return unknownSource()
		}
		return Source{OSProvided: osProvided(false), Channel: ChannelDirect}
	}
	var exactOS, exactOther *pacmanRepoDB
	nameOS, nameOther, rebuilt := false, false, false
	for _, e := range entries {
		if e.osSigned {
			nameOS = true
		} else {
			nameOther = true
		}
		if e.version != pkg.Version || (e.arch != pkg.Arch && e.arch != "" && pkg.Arch != "") {
			continue
		}
		if e.buildDate != "" && pkg.pacmanBuildDate != "" && e.buildDate != pkg.pacmanBuildDate {
			// the same version built another time: a rebuild by someone else
			rebuilt = true
			continue
		}
		switch {
		case e.osSigned:
			if exactOS == nil {
				exactOS = e.repo
			}
		case exactOther == nil:
			exactOther = e.repo
		}
	}
	// pacman records how it checked a package when it installed it: "pgp" for
	// a signature. Anything else on a package the operating system's database
	// lists means the package was not checked against that signature, so the
	// listing says nothing about what is installed.
	checked := pacmanChecked(pkg.pacmanValidation)
	switch {
	case exactOS != nil && !checked:
		return unknownSource()
	case exactOS != nil:
		return Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: exactOS.name, URL: exactOS.url}
	case exactOther != nil:
		return Source{OSProvided: osProvided(false), Channel: ChannelVendorRepository, Name: exactOther.name, URL: exactOther.url}
	case rebuilt:
		return unknownSource()
	case nameOS && !nameOther && checked:
		// an operating system package that missed an update
		return Source{OSProvided: osProvided(true), Channel: ChannelOS}
	}
	return unknownSource()
}

var _ SourceResolver = (*PacmanPkgManager)(nil)

// pacmanChecked reports whether pacman checked a package's signature when it
// installed it: %VALIDATION% lists the methods, one per line ("none", "md5",
// "sha256", "pgp"), and "pgp" among them is the signature. An absent value, as
// from `pacman -Q`, says nothing against it.
func pacmanChecked(validation string) bool {
	if validation == "" {
		return true
	}
	for v := range strings.SplitSeq(validation, "\n") {
		if strings.TrimSpace(v) == "pgp" {
			return true
		}
	}
	return false
}
