// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/ulikunitz/xz"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// aptListsDir is where apt keeps the package indexes and release files it
// downloaded with `apt-get update`.
const aptListsDir = "/var/lib/apt/lists"

// dpkgOSKeyringPackages are, per distribution, the packages that install the
// keys the distribution signs its own repositories with. A repository whose
// release file is signed by a key from one of these files is the operating
// system's; any other key was added by an administrator.
//
// The list is deliberately explicit. Any package can install a key file, and
// some distribution packages ship a third party's key so that its repository
// can be added: postgresql-common carries the PostgreSQL project's PGDG key.
// Counting every key an installed package owns would turn that third-party
// repository into the operating system's.
//
// Each entry was read off the distribution's own image, except raspbian, which
// follows the file lists the Raspberry Pi archive publishes for its keyring
// packages. debian-keyring is not on any list: it holds the personal keys of
// Debian developers, not an archive key.
var dpkgOSKeyringPackages = map[string][]string{
	"debian": {"debian-archive-keyring", "debian-ports-archive-keyring"},
	// ubuntu-pro-client installs the keys of the ESM repositories Ubuntu Pro
	// enables; ubuntu-advantage-tools is the package's earlier name.
	"ubuntu": {"ubuntu-keyring", "ubuntu-pro-client", "ubuntu-advantage-tools"},
	"kali":   {"kali-archive-keyring"},
	// Linux Mint adds its own repository to Ubuntu's, LMDE to Debian's
	"linuxmint": {"linuxmint-keyring", "ubuntu-keyring", "debian-archive-keyring"},
	"raspbian":  {"raspberrypi-archive-keyring", "raspbian-archive-keyring", "debian-archive-keyring"},
}

// Sources says where each deb package came from (ADR 049).
//
// The installed version is matched against the package indexes apt keeps.
// Debian signs repositories, not packages, so the index's release file
// decides: signed by the distribution's archive keyring, the package is the
// operating system's; signed by a key someone added, it came from a vendor
// repository.
func (dpm *DebPkgManager) Sources(pkgs []Package) ([]Source, error) {
	files := newSourceFiles(dpm.conn)
	platform := ""
	if dpm.platform != nil {
		platform = dpm.platform.Name
	}
	installed := make(map[string]struct{}, len(pkgs))
	arches := map[string]string{}
	for i := range pkgs {
		if pkgs[i].Format == DpkgPkgFormat {
			installed[pkgs[i].Name] = struct{}{}
			arches[pkgs[i].Name] = pkgs[i].Arch
		}
	}
	// Over SSH, read the keyring packages' file lists, the sources and the
	// release files in one round trip, then the key files the lists name in a
	// second one.
	files.prefetch(append(dpkgKeyringLists(platform, arches), aptSourceFiles(files.fs)...))
	lists := newAptLists(files, aptSources{})
	files.prefetch(lists.releasePaths())
	osKeys, keysKnown := readDpkgOSKeys(files, platform, arches)
	lists.setTrust(osKeys, keysKnown, readAptSources(files))
	idx, ok := lists.readRemote(dpm.conn, installed)
	if ok {
		log.Debug().Int("packages", len(installed)).Msg("mql[packages]> matched deb packages against the apt indexes filtered on the host")
	} else {
		idx = lists.read(installed)
		log.Debug().Int("packages", len(installed)).Msg("mql[packages]> matched deb packages against the apt indexes read from files")
	}
	return dpkgSources(pkgs, idx), nil
}

// aptRelease is one repository suite apt downloaded: a release file and the
// package indexes it covers.
type aptRelease struct {
	// Origin and Label as the release file declares them, e.g. "Debian" /
	// "Debian-Security", "nginx" / "nginx", "Docker" / "Docker CE".
	origin, label string
	// host is the repository's address without scheme, decoded from the list
	// file name, e.g. "nginx.org/packages/debian".
	host string
	// url is the repository's address with its scheme, from the sources files,
	// without credentials. Empty when no sources entry names the repository.
	url string
	// osSigned is true when a signature on the release file is by a key the
	// operating system's keyring package installed. trustKnown is false when
	// the operating system's keys could not be determined at all, so a
	// release can be neither the operating system's nor someone else's.
	osSigned   bool
	trustKnown bool
}

func (r *aptRelease) name() string {
	switch {
	case r.origin != "":
		return r.origin
	case r.label != "":
		return r.label
	}
	return r.host
}

// aptIndexEntry is one (version, architecture) an index lists for a package.
type aptIndexEntry struct {
	version, arch string
	release       *aptRelease
}

// aptIndexes is what the package indexes say about the installed packages.
type aptIndexes struct {
	// any is true when at least one package index was read. Without one
	// nothing can be decided: most container images ship without indexes.
	any bool
	// complete is true when every component the sources enable has an index
	// on the system. Only then does a name no index lists mean the package
	// was installed from a file: an Ubuntu cloud image ships the main and
	// restricted indexes and none for universe until the first apt-get update.
	complete bool
	// byName holds the index entries of every installed package name.
	byName map[string][]aptIndexEntry
}

// dpkgSources decides each package's source from the indexes. The match is on
// the exact (name, version, architecture):
//
//   - listed by an index the operating system signed: os
//   - listed only by indexes signed by other keys: vendor-repository
//   - the name in no index, with an index for every enabled component:
//     direct, installed from a local .deb
//   - the version in no index, the name only in indexes the operating system
//     signed: os. The Debian archive lists only the current version, so a
//     package that missed an update matches the name and not the version.
//   - the version in no index, the name also in a third-party index: null. A
//     name match would send an outdated Debian nginx to nginx.org's index.
//   - no indexes on the system: null
func dpkgSources(pkgs []Package, idx aptIndexes) []Source {
	out := make([]Source, len(pkgs))
	for i := range pkgs {
		pkg := &pkgs[i]
		if pkg.Format != DpkgPkgFormat {
			out[i] = DefaultSource(*pkg)
			continue
		}
		if !idx.any {
			out[i] = unknownSource()
			continue
		}
		out[i] = dpkgSource(pkg, idx.byName[pkg.Name], idx.complete)
	}
	return out
}

func dpkgSource(pkg *Package, entries []aptIndexEntry, complete bool) Source {
	if len(entries) == 0 {
		if !complete {
			return unknownSource()
		}
		return Source{OSProvided: osProvided(false), Channel: ChannelDirect}
	}

	var exactOS, exactOther, exactUnknown *aptRelease
	nameOS, nameOther, nameUnknown := false, false, false
	for _, e := range entries {
		exact := e.version == pkg.Version && (e.arch == pkg.Arch || e.arch == "" || pkg.Arch == "")
		switch {
		case !e.release.trustKnown:
			nameUnknown = true
			if exact && exactUnknown == nil {
				exactUnknown = e.release
			}
		case e.release.osSigned:
			nameOS = true
			if exact && exactOS == nil {
				exactOS = e.release
			}
		default:
			nameOther = true
			if exact && exactOther == nil {
				exactOther = e.release
			}
		}
	}

	switch {
	case exactOS != nil:
		return Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: exactOS.name(), URL: exactOS.url}
	case exactOther != nil:
		return Source{OSProvided: osProvided(false), Channel: ChannelVendorRepository, Name: exactOther.name(), URL: exactOther.url}
	case exactUnknown != nil:
		return Source{Channel: ChannelUnknown, Name: exactUnknown.name(), URL: exactUnknown.url}
	case nameOS && !nameOther && !nameUnknown:
		// an operating system package that missed an update
		return Source{OSProvided: osProvided(true), Channel: ChannelOS}
	}
	return unknownSource()
}

// readDpkgOSKeys collects the key IDs and fingerprints in every key file the
// distribution's keyring packages installed. The second result is false when
// the distribution is not known, or none of its keyring packages is installed:
// then no release can be attributed to the operating system or to anyone else.
//
// arches maps each installed package to its architecture: a keyring package
// that is not installed is skipped, and an installed one's file list is
// opened by name. Listing /var/lib/dpkg/info instead would read thousands of
// entries, which is slow over SSH.
func readDpkgOSKeys(files *sourceFiles, platform string, arches map[string]string) (openPGPKeys, bool) {
	keys := openPGPKeys{}
	found := false
	var keyFiles []string
	for _, name := range dpkgOSKeyringPackages[platform] {
		arch, installed := arches[name]
		if !installed {
			continue
		}
		owned, ok := readDpkgInfoList(files, name, arch)
		if !ok {
			continue
		}
		found = true
		for _, f := range owned {
			// debian-archive-removed-keys.gpg holds the keys Debian retired;
			// they no longer sign anything, so they are not trusted here either
			if !isKeyFile(f) || strings.Contains(path.Base(f), "removed-keys") {
				continue
			}
			keyFiles = append(keyFiles, f)
		}
	}
	files.prefetch(keyFiles)
	for _, f := range keyFiles {
		keys.addFile(files, f)
	}
	return keys, found && len(keys) > 0
}

// dpkgKeyringLists are the dpkg file lists of the distribution's installed
// keyring packages.
func dpkgKeyringLists(platform string, arches map[string]string) []string {
	var out []string
	for _, name := range dpkgOSKeyringPackages[platform] {
		if arch, ok := arches[name]; ok {
			out = append(out, path.Join(dpkgInfoDir, name+".list"), path.Join(dpkgInfoDir, name+":"+arch+".list"))
		}
	}
	return out
}

// readDpkgInfoList returns the files an installed package laid down. dpkg
// records them in <name>.list, or in <name>:<arch>.list for a package that
// can be installed for several architectures.
func readDpkgInfoList(files *sourceFiles, name, arch string) ([]string, bool) {
	candidates := []string{path.Join(dpkgInfoDir, name+".list")}
	if arch != "" {
		candidates = append(candidates, path.Join(dpkgInfoDir, name+":"+arch+".list"))
	}
	for _, c := range candidates {
		data, err := files.read(c)
		if err != nil {
			continue
		}
		var owned []string
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				owned = append(owned, line)
			}
		}
		return owned, true
	}
	return nil, false
}

func isKeyFile(p string) bool {
	switch path.Ext(p) {
	case ".gpg", ".asc", ".pgp":
		return true
	}
	return false
}

// openPGPKeys holds the key IDs (as 16 hex digits) and fingerprints (as
// upper-case hex) of a set of keys, primary keys and subkeys alike.
type openPGPKeys map[string]struct{}

func (k openPGPKeys) addFile(files *sourceFiles, p string) {
	data, err := files.read(p)
	if err != nil {
		return
	}
	k.addKeyring(data)
}

// addKeyring adds every key of a keyring, binary or ASCII-armored.
func (k openPGPKeys) addKeyring(data []byte) {
	var entities openpgp.EntityList
	var err error
	if bytes.Contains(data, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	} else {
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(data))
	}
	if err != nil && len(entities) == 0 {
		// A keyring with a key the library cannot parse would lose every key
		// in it; read the public key packets one by one instead.
		k.addKeyPackets(data)
		return
	}
	for _, e := range entities {
		k.addKey(e.PrimaryKey)
		for _, sub := range e.Subkeys {
			k.addKey(sub.PublicKey)
		}
	}
}

func (k openPGPKeys) addKeyPackets(data []byte) {
	var r io.Reader = bytes.NewReader(data)
	if block, err := armor.Decode(bytes.NewReader(data)); err == nil {
		r = block.Body
	}
	pr := packet.NewReader(r)
	for {
		// Next skips packets of unknown or unsupported types itself; an error
		// it returns means the data is damaged, and nothing after it can be
		// trusted.
		p, err := pr.Next()
		if err != nil {
			return
		}
		if pub, ok := p.(*packet.PublicKey); ok {
			k.addKey(pub)
		}
	}
}

func (k openPGPKeys) addKey(pub *packet.PublicKey) {
	if pub == nil {
		return
	}
	k[keyIDHex(pub.KeyId)] = struct{}{}
	if len(pub.Fingerprint) > 0 {
		k[strings.ToUpper(hexString(pub.Fingerprint))] = struct{}{}
	}
}

// hasKeyID reports whether a key is in the set, given as rpm names an imported
// key: its 8-digit short ID ("b86b3716"), its 16-digit ID, or its 40-digit
// fingerprint (Fedora and Photon). A short ID is the last 8 digits of the ID.
func (k openPGPKeys) hasKeyID(id string) bool {
	id = strings.ToUpper(id)
	switch len(id) {
	case 16, 40:
		_, ok := k[id]
		return ok
	case 8:
		for key := range k {
			if len(key) == 16 && strings.HasSuffix(key, id) {
				return true
			}
		}
	}
	return false
}

// signedBy reports whether any of the issuers is one of the keys. An issuer is
// a 16-digit key ID or a fingerprint; an older rpm prints an 8-digit short ID.
func (k openPGPKeys) signedBy(issuers []string) bool {
	for _, iss := range issuers {
		if _, ok := k[iss]; ok {
			return true
		}
		if len(iss) == 8 && k.hasKeyID(iss) {
			return true
		}
	}
	return false
}

func keyIDHex(id uint64) string {
	const digits = "0123456789ABCDEF"
	b := make([]byte, 16)
	for i := 15; i >= 0; i-- {
		b[i] = digits[id&0xf]
		id >>= 4
	}
	return string(b)
}

func hexString(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0xf]
	}
	return string(out)
}

// signatureIssuers returns the key ID and fingerprint of every signature in an
// OpenPGP signature block, binary or armored. A release file is often signed
// by more than one key: Debian signs with the current and the previous
// archive key.
func signatureIssuers(sig []byte) []string {
	raw := sig
	if block, err := armor.Decode(bytes.NewReader(sig)); err == nil {
		if b, err := io.ReadAll(block.Body); err == nil {
			raw = b
		}
	}
	var r io.Reader = bytes.NewReader(raw)
	var issuers []string
	pr := packet.NewReader(r)
	for {
		// unsupported signature versions are skipped by Next itself
		p, err := pr.Next()
		if err != nil {
			break
		}
		s, ok := p.(*packet.Signature)
		if !ok {
			continue
		}
		if s.IssuerKeyId != nil {
			issuers = append(issuers, keyIDHex(*s.IssuerKeyId))
		}
		if len(s.IssuerFingerprint) > 0 {
			fp := strings.ToUpper(hexString(s.IssuerFingerprint))
			issuers = append(issuers, fp)
			// A v4 fingerprint's last 8 bytes are the key ID; a signature that
			// carries only the fingerprint still matches a keyring indexed by ID.
			if len(fp) >= 16 {
				issuers = append(issuers, fp[len(fp)-16:])
			}
		}
	}
	// The library skips version 3 signatures as unsupported. SUSE still signs
	// its packages with them, so they are read here.
	if len(issuers) == 0 {
		issuers = v3SignatureIssuers(raw)
	}
	return issuers
}

// v3SignatureIssuers returns the issuer key ID of every version 3 signature
// packet (RFC 4880 5.2.2) in a binary packet stream: version, hashed length,
// signature type, creation time, then the 8-byte key ID.
func v3SignatureIssuers(data []byte) []string {
	var issuers []string
	for len(data) > 1 {
		tag, body, rest, ok := nextOpenPGPPacket(data)
		if !ok {
			break
		}
		if tag == 2 && len(body) >= 15 && body[0] == 3 {
			issuers = append(issuers, keyIDHex(binary.BigEndian.Uint64(body[7:15])))
		}
		data = rest
	}
	return issuers
}

// nextOpenPGPPacket splits the first packet off a binary OpenPGP stream, in
// either the old or the new header format. Partial body lengths do not occur in
// signature packets and are not read.
func nextOpenPGPPacket(data []byte) (tag byte, body, rest []byte, ok bool) {
	b := data[0]
	if b&0x80 == 0 {
		return 0, nil, nil, false
	}
	var n, hdr int
	if b&0x40 == 0 {
		// old format: tag in bits 5-2, length type in bits 1-0
		tag = (b >> 2) & 0x0f
		switch b & 0x03 {
		case 0:
			if len(data) < 2 {
				return 0, nil, nil, false
			}
			n, hdr = int(data[1]), 2
		case 1:
			if len(data) < 3 {
				return 0, nil, nil, false
			}
			n, hdr = int(binary.BigEndian.Uint16(data[1:3])), 3
		case 2:
			if len(data) < 5 {
				return 0, nil, nil, false
			}
			n, hdr = int(binary.BigEndian.Uint32(data[1:5])), 5
		default:
			n, hdr = len(data)-1, 1
		}
	} else {
		tag = b & 0x3f
		if len(data) < 2 {
			return 0, nil, nil, false
		}
		switch l := data[1]; {
		case l < 192:
			n, hdr = int(l), 2
		case l < 224:
			if len(data) < 3 {
				return 0, nil, nil, false
			}
			n, hdr = (int(l)-192)<<8+int(data[2])+192, 3
		case l == 255:
			if len(data) < 6 {
				return 0, nil, nil, false
			}
			n, hdr = int(binary.BigEndian.Uint32(data[2:6])), 6
		default:
			return 0, nil, nil, false
		}
	}
	if n < 0 || hdr+n > len(data) {
		return 0, nil, nil, false
	}
	return tag, data[hdr : hdr+n], data[hdr+n:], true
}

// parseAptReleaseFile reads the Origin and Label of an InRelease (clearsigned)
// or Release file, and the issuers of the signature an InRelease carries.
func parseAptReleaseFile(data []byte) (origin, label string, issuers []string) {
	text := data
	if block, _ := clearsign.Decode(data); block != nil {
		text = block.Plaintext
		if block.ArmoredSignature != nil {
			sig, err := io.ReadAll(block.ArmoredSignature.Body)
			if err == nil {
				issuers = signatureIssuers(sig)
			}
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		// the fields that name the release come first; the file lists end it
		if line == "" || strings.HasPrefix(line, " ") {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "Origin":
			origin = strings.TrimSpace(value)
		case "Label":
			label = strings.TrimSpace(value)
		}
	}
	return origin, label, issuers
}

// aptPackagesFile recognizes a package index in the lists directory and
// returns the prefix it shares with its release file, and its compression.
// apt names files after their URL with "/" turned into "_":
//
//	deb.debian.org_debian_dists_bookworm_InRelease
//	deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.lz4
//
// A flat repository has no dists part:
//
//	repo.example_debian_._InRelease
//	repo.example_debian_._Packages
func aptPackagesFile(name string) (base string, compression string, ok bool) {
	for _, ext := range []string{"", ".gz", ".xz", ".lz4", ".bz2", ".zst"} {
		if strings.HasSuffix(name, "_Packages"+ext) {
			return strings.TrimSuffix(name, "Packages"+ext), ext, true
		}
	}
	return "", "", false
}

// aptListHost decodes the repository address apt encoded into a release file
// name prefix: "nginx.org_packages_debian_dists_bookworm_" is
// "nginx.org/packages/debian". apt escapes "_" and other reserved characters
// as %XX before it turns "/" into "_", so the reverse is unambiguous.
//
// The result is reported as the repository's name when its release file names
// none, so it never carries what a repository address can hide credentials in:
// apt drops user information from the file name, but keeps a query string.
func aptListHost(releaseBase string) string {
	base := aptRepoPrefix(releaseBase)
	decoded, err := url.PathUnescape(strings.ReplaceAll(base, "_", "/"))
	if err != nil {
		decoded = strings.ReplaceAll(base, "_", "/")
	}
	decoded = stripURIQuery(decoded)
	if at := strings.LastIndex(decoded, "@"); at >= 0 {
		decoded = decoded[at+1:]
	}
	return decoded
}

// aptRepoPrefix is the part of a release file name prefix that names the
// repository, without the suite: "nginx.org_packages_debian_dists_bookworm_"
// is "nginx.org_packages_debian", a flat "repo.example_debian_._" is
// "repo.example_debian".
func aptRepoPrefix(releaseBase string) string {
	base := strings.TrimSuffix(releaseBase, "_")
	if i := strings.Index(base, "_dists_"); i >= 0 {
		return base[:i]
	}
	return strings.TrimSuffix(base, "_.")
}

// aptListFileQuote are the characters apt escapes as %XX when it turns a
// repository URL into a file name (URItoFileName). "/" becomes "_" after.
const aptListFileQuote = "\\|{}[]<>\"^~_=!@#$%^&*"

// aptURIListPrefix returns the file name prefix apt gives the indexes of a
// repository URL, the reverse of aptListHost. Scheme and credentials are
// dropped, the port is kept, reserved characters are escaped, and "/" becomes
// "_":
//
//	http://user:pw@example.invalid:8080/a_b~c/  example.invalid:8080_a%5fb%7ec
//	mirror+file:///etc/apt/mirrors/debian.list  _etc_apt_mirrors_debian.list
func aptURIListPrefix(uri string) string {
	rest := uri
	if i := strings.Index(rest, ":"); i > 0 && !strings.ContainsAny(rest[:i], "/@") {
		rest = rest[i+1:]
	}
	if strings.HasPrefix(rest, "//") {
		rest = rest[2:]
		// user information ends at the last @ of the authority
		authorityEnd := strings.Index(rest, "/")
		if authorityEnd < 0 {
			authorityEnd = len(rest)
		}
		if at := strings.LastIndex(rest[:authorityEnd], "@"); at >= 0 {
			rest = rest[at+1:]
		}
	}
	rest = strings.TrimSuffix(rest, "/")
	var b strings.Builder
	for _, c := range rest {
		if c < 0x80 && strings.ContainsRune(aptListFileQuote, c) {
			b.WriteString("%" + strings.ToLower(hexString([]byte{byte(c)})))
			continue
		}
		b.WriteRune(c)
	}
	return strings.ReplaceAll(b.String(), "/", "_")
}

// aptSourceEntry is one "deb" source: a repository and the suites and
// components it enables.
type aptSourceEntry struct {
	uri        string
	suites     []string
	components []string
}

// aptSources is what the sources files say: the repositories they enable, and
// for each repository's file name prefix its address for display.
type aptSources struct {
	entries []aptSourceEntry
	// urls maps aptURIListPrefix of a repository to its address without
	// credentials.
	urls map[string]string
}

// aptLists reads the lists directory. One is built per scan.
type aptLists struct {
	files     *sourceFiles
	osKeys    openPGPKeys
	keysKnown bool
	sources   aptSources

	names        []string
	releaseFiles map[string]string
	bases        []string
	releases     map[string]*aptRelease
}

func newAptLists(files *sourceFiles, sources aptSources) *aptLists {
	l := &aptLists{files: files, sources: sources,
		releaseFiles: map[string]string{}, releases: map[string]*aptRelease{}}
	entries, err := afero.ReadDir(files.fs, aptListsDir)
	if err != nil {
		return l
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		l.names = append(l.names, n)
		switch {
		case strings.HasSuffix(n, "_InRelease"):
			l.releaseFiles[strings.TrimSuffix(n, "InRelease")] = n
		case strings.HasSuffix(n, "_Release"):
			base := strings.TrimSuffix(n, "Release")
			if _, ok := l.releaseFiles[base]; !ok {
				l.releaseFiles[base] = n
			}
		}
	}
	sort.Strings(l.names)
	for b := range l.releaseFiles {
		l.bases = append(l.bases, b)
	}
	// the longest release prefix of a Packages file is its release
	sort.Slice(l.bases, func(i, j int) bool { return len(l.bases[i]) > len(l.bases[j]) })
	return l
}

// setTrust sets the operating system's keys and the sources, which can only be
// read once the keyring files and sources are fetched.
func (l *aptLists) setTrust(osKeys openPGPKeys, keysKnown bool, sources aptSources) {
	l.osKeys, l.keysKnown, l.sources = osKeys, keysKnown, sources
}

// releasePaths are the release files and detached signatures in the lists
// directory.
func (l *aptLists) releasePaths() []string {
	var out []string
	for _, f := range l.releaseFiles {
		out = append(out, path.Join(aptListsDir, f))
		if strings.HasSuffix(f, "_Release") {
			out = append(out, path.Join(aptListsDir, f+".gpg"))
		}
	}
	sort.Strings(out)
	return out
}

// releaseOf returns the release a Packages file belongs to, reading and
// attributing the release file the first time.
func (l *aptLists) releaseOf(pkgBase string) *aptRelease {
	base := pkgBase
	for _, b := range l.bases {
		if strings.HasPrefix(pkgBase, b) {
			base = b
			break
		}
	}
	if r, ok := l.releases[base]; ok {
		return r
	}
	r := &aptRelease{host: aptListHost(base), trustKnown: l.keysKnown}
	r.url = l.sources.urls[aptRepoPrefix(base)]
	if f, ok := l.releaseFiles[base]; ok {
		if data, err := l.files.read(path.Join(aptListsDir, f)); err == nil {
			var issuers []string
			r.origin, r.label, issuers = parseAptReleaseFile(data)
			// a Release file carries its signature beside it, in Release.gpg;
			// a repository added with [trusted=yes] has neither
			if strings.HasSuffix(f, "_Release") {
				if sig, err := l.files.read(path.Join(aptListsDir, f+".gpg")); err == nil {
					issuers = signatureIssuers(sig)
				}
			}
			r.osSigned = l.keysKnown && l.osKeys.signedBy(issuers)
		}
	}
	l.releases[base] = r
	return r
}

// complete reports whether every component the sources enable has a package
// index on the system. Without sources to compare against, it is not known to
// be complete.
func (l *aptLists) complete() bool {
	if len(l.sources.entries) == 0 {
		return false
	}
	has := func(prefix string) bool {
		i := sort.SearchStrings(l.names, prefix)
		for ; i < len(l.names) && strings.HasPrefix(l.names[i], prefix); i++ {
			if _, _, ok := aptPackagesFile(l.names[i]); ok {
				return true
			}
		}
		return false
	}
	for _, e := range l.sources.entries {
		repo := aptURIListPrefix(e.uri)
		for _, suite := range e.suites {
			if strings.HasSuffix(suite, "/") {
				// a flat repository: the suite is a path, there are no components
				if !has(repo + "_" + aptURIListPrefix(strings.TrimSuffix(suite, "/"))) {
					return false
				}
				continue
			}
			for _, comp := range e.components {
				if !has(repo + "_dists_" + aptURIListPrefix(suite) + "_" + aptURIListPrefix(comp) + "_binary-") {
					return false
				}
			}
		}
	}
	return true
}

// read reads every package index from the file system, keeping only the entries
// of installed package names, and attributes each to its release file.
func (l *aptLists) read(installed map[string]struct{}) aptIndexes {
	idx := aptIndexes{byName: map[string][]aptIndexEntry{}}
	for _, n := range l.names {
		pkgBase, compression, ok := aptPackagesFile(n)
		if !ok {
			continue
		}
		release := l.releaseOf(pkgBase)
		if err := readAptPackagesIndex(l.files.fs, path.Join(aptListsDir, n), compression, installed, release, idx.byName); err != nil {
			log.Debug().Err(err).Str("file", n).Msg("could not read apt package index")
			continue
		}
		idx.any = true
	}
	idx.complete = idx.any && l.complete()
	return idx
}

// aptRemoteIndexCmd filters the package indexes on the scanned system and
// prints only what the reader needs: each index's path behind a "#", then the
// Package, Version and Architecture lines of installed package names. apt's
// own apt-helper decompresses every format apt writes.
//
// It exists for the network. The indexes of a Debian host are 60 MB, an
// Ubuntu host's 140 to 210 MB; copied over SSH that is 10 to 40 seconds per
// scan. Filtered on the host the output is a few hundred kilobytes.
const aptRemoteIndexCmd = `for f in /var/lib/apt/lists/*_Packages /var/lib/apt/lists/*_Packages.*; do ` +
	`[ -f "$f" ] || continue; case "$f" in *.diff_Index) continue;; esac; printf '#%s\n' "$f"; ` +
	`/usr/lib/apt/apt-helper cat-file "$f" 2>/dev/null | awk 'BEGIN{while((getline l < "/var/lib/dpkg/status")>0) if (l ~ /^Package: /) w[substr(l,10)]=1} ` +
	`/^Package: /{k=(substr($0,10) in w)} k && /^(Package|Version|Architecture):/'; done`

// readRemote reads the indexes through aptRemoteIndexCmd on an SSH connection.
// It reports false when it did not run, so the caller reads the files instead.
func (l *aptLists) readRemote(conn shared.Connection, installed map[string]struct{}) (aptIndexes, bool) {
	if conn == nil || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return aptIndexes{}, false
	}
	if t := conn.Type(); t != shared.Type_SSH && t != shared.Type_Vagrant {
		return aptIndexes{}, false
	}
	if len(l.names) == 0 {
		return aptIndexes{byName: map[string][]aptIndexEntry{}}, true
	}
	cmd, err := conn.RunCommand(aptRemoteIndexCmd)
	if err != nil || cmd.ExitStatus != 0 {
		return aptIndexes{}, false
	}
	idx, err := l.parseRemote(cmd.Stdout, installed)
	if err != nil {
		log.Debug().Err(err).Msg("could not read the filtered apt indexes")
		return aptIndexes{}, false
	}
	return idx, true
}

func (l *aptLists) parseRemote(r io.Reader, installed map[string]struct{}) (aptIndexes, error) {
	idx := aptIndexes{byName: map[string][]aptIndexEntry{}}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, dpkgMaxLine)
	var release *aptRelease
	var name, version, arch string
	flush := func() {
		if name != "" && release != nil {
			if _, ok := installed[name]; ok {
				idx.byName[name] = append(idx.byName[name], aptIndexEntry{version: version, arch: arch, release: release})
			}
		}
		name, version, arch = "", "", ""
	}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "#"):
			flush()
			pkgBase, _, ok := aptPackagesFile(path.Base(line[1:]))
			if !ok {
				release = nil
				continue
			}
			release = l.releaseOf(pkgBase)
			idx.any = true
		case strings.HasPrefix(line, "Package:"):
			flush()
			name = strings.TrimSpace(line[len("Package:"):])
		case strings.HasPrefix(line, "Version:"):
			version = strings.TrimSpace(line[len("Version:"):])
		case strings.HasPrefix(line, "Architecture:"):
			arch = strings.TrimSpace(line[len("Architecture:"):])
		}
	}
	flush()
	idx.complete = idx.any && l.complete()
	return idx, scanner.Err()
}

// readAptPackagesIndex streams one package index and records the entries of
// installed package names. An index of the Debian archive lists some 60,000
// packages, so only the three fields that identify an entry are looked at.
func readAptPackagesIndex(fs afero.Fs, p, compression string, installed map[string]struct{}, release *aptRelease, out map[string][]aptIndexEntry) error {
	f, err := fs.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	r, closeFn, err := decompressAptIndex(f, compression)
	if err != nil {
		return err
	}
	defer closeFn()

	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, dpkgMaxLine)
	var name, version, arch string
	flush := func() {
		if name == "" {
			return
		}
		if _, ok := installed[name]; ok {
			out[name] = append(out[name], aptIndexEntry{version: version, arch: arch, release: release})
		}
		name, version, arch = "", "", ""
	}
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			flush()
			continue
		}
		switch {
		case bytes.HasPrefix(line, []byte("Package:")):
			name = string(bytes.TrimSpace(line[len("Package:"):]))
		case bytes.HasPrefix(line, []byte("Version:")):
			version = string(bytes.TrimSpace(line[len("Version:"):]))
		case bytes.HasPrefix(line, []byte("Architecture:")):
			arch = string(bytes.TrimSpace(line[len("Architecture:"):]))
		}
	}
	flush()
	return scanner.Err()
}

func decompressAptIndex(r io.Reader, compression string) (io.Reader, func(), error) {
	noop := func() {}
	switch compression {
	case "":
		return r, noop, nil
	case ".gz":
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, noop, err
		}
		return gz, func() { gz.Close() }, nil
	case ".xz":
		x, err := xz.NewReader(r)
		return x, noop, err
	case ".lz4":
		return lz4.NewReader(r), noop, nil
	case ".bz2":
		return bzip2.NewReader(r), noop, nil
	case ".zst":
		z, err := zstd.NewReader(r)
		if err != nil {
			return nil, noop, err
		}
		return z, z.Close, nil
	}
	return nil, noop, errors.New("unsupported index compression " + compression)
}

// aptSourceFiles lists sources.list and the files in sources.list.d.
func aptSourceFiles(fs afero.Fs) []string {
	out := []string{"/etc/apt/sources.list"}
	if entries, err := afero.ReadDir(fs, "/etc/apt/sources.list.d"); err == nil {
		for _, e := range entries {
			n := e.Name()
			if strings.HasSuffix(n, ".list") || strings.HasSuffix(n, ".sources") {
				out = append(out, path.Join("/etc/apt/sources.list.d", n))
			}
		}
	}
	return out
}

// readAptSources reads the deb sources from sources.list and sources.list.d,
// in both the one-line and the deb822 format.
func readAptSources(files *sourceFiles) aptSources {
	srcs := aptSources{urls: map[string]string{}}
	for _, f := range aptSourceFiles(files.fs) {
		data, err := files.read(f)
		if err != nil {
			continue
		}
		var entries []aptSourceEntry
		if strings.HasSuffix(f, ".sources") {
			entries = parseDeb822Sources(data)
		} else {
			entries = parseOneLineSources(data)
		}
		srcs.entries = append(srcs.entries, entries...)
	}
	for _, e := range srcs.entries {
		u := e.uri
		prefix := aptURIListPrefix(stripURIQuery(u))
		if _, ok := srcs.urls[prefix]; ok {
			continue
		}
		// a mirror+file source names a file listing the mirrors to use; the
		// repository is the first one in it
		if rest, ok := strings.CutPrefix(u, "mirror+file:"); ok {
			u = firstMirror(files, strings.TrimPrefix(rest, "//"))
		}
		if clean := sanitizeRepoURL(u); clean != "" {
			srcs.urls[prefix] = clean
			// apt names the files after the address as written, query
			// included; keep that spelling too so such a release finds it
			if full := aptURIListPrefix(e.uri); full != prefix {
				srcs.urls[full] = clean
			}
		}
	}
	return srcs
}

// stripURIQuery drops a URL's query and fragment, where private repositories
// carry tokens.
func stripURIQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

// firstMirror returns the first URL of an apt mirror list, one URL per line,
// optionally followed by tab-separated attributes.
func firstMirror(files *sourceFiles, p string) string {
	data, err := files.read(p)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return strings.Fields(line)[0]
	}
	return ""
}

// parseOneLineSources reads "deb [options] uri suite [component...]" lines.
func parseOneLineSources(data []byte) []aptSourceEntry {
	var out []aptSourceEntry
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "deb" {
			continue
		}
		i := 1
		if strings.HasPrefix(fields[i], "[") {
			for i < len(fields) && !strings.HasSuffix(fields[i], "]") {
				i++
			}
			i++
		}
		if i+1 >= len(fields) {
			continue
		}
		out = append(out, aptSourceEntry{uri: fields[i], suites: []string{fields[i+1]}, components: fields[i+2:]})
	}
	return out
}

// parseDeb822Sources reads the stanzas of a deb822 .sources file.
func parseDeb822Sources(data []byte) []aptSourceEntry {
	var out []aptSourceEntry
	fields := map[string]string{}
	flush := func() {
		defer func() { fields = map[string]string{} }()
		if !strings.Contains(" "+fields["types"]+" ", " deb ") {
			return
		}
		if strings.EqualFold(strings.TrimSpace(fields["enabled"]), "no") {
			return
		}
		suites := strings.Fields(fields["suites"])
		components := strings.Fields(fields["components"])
		for _, uri := range strings.Fields(fields["uris"]) {
			out = append(out, aptSourceEntry{uri: uri, suites: suites, components: components})
		}
	}
	key := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			flush()
			key = ""
			continue
		}
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && key != "" {
			fields[key] += " " + strings.TrimSpace(line)
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(k))
		fields[key] = strings.TrimSpace(v)
	}
	flush()
	return out
}
