// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

const (
	// apkKeysDir is where apk looks for the keys it trusts.
	apkKeysDir = "/etc/apk/keys"
	// apkRepositories lists the repositories apk reads.
	apkRepositories = "/etc/apk/repositories"
	// apkArchFile names the architecture apk installs packages for.
	apkArchFile = "/etc/apk/arch"
)

// apkCacheDirs are the directories apk keeps the repository indexes it
// downloaded in. /etc/apk/cache is the one a system that enabled the cache
// uses; the others are where apk-tools writes them otherwise.
var apkCacheDirs = []string{"/var/cache/apk", "/etc/apk/cache", "/var/lib/apk"}

const (
	// apkMaxIndexFile caps the size of one compressed index. Alpine's community
	// index is 2 MB and Wolfi's 8 MB.
	apkMaxIndexFile = 128 * 1024 * 1024
	// apkMaxIndexText caps how much of one index's text is read. Wolfi's is
	// 42 MB.
	apkMaxIndexText = 1024 * 1024 * 1024
	// apkMaxRepositories caps the repositories read from /etc/apk/repositories.
	apkMaxRepositories = 64
	// apkMaxSmallFile caps a key, a signature or the repositories file.
	apkMaxSmallFile = 1024 * 1024
	// apkMaxSignatureStream caps the stream that holds an index's signatures,
	// which is a few kilobytes.
	apkMaxSignatureStream = 1024 * 1024
	// apkMaxSignatures caps the signatures read from one index. Chainguard's
	// carries three.
	apkMaxSignatures = 16
)

// apkOSKeyPackages are, per distribution, the packages that install the keys
// the distribution signs its repositories with. A repository whose index is
// signed by one of the keys such a package owns is the operating system's; a
// key an administrator put in /etc/apk/keys signs a third party's.
//
// The list is explicit, as for dpkg: any package can install a key file. Each
// entry was read off the distribution's own image with `apk info -W`.
var apkOSKeyPackages = map[string][]string{
	"alpine": {"alpine-keys"},
	// BellSoft's keys sit in distro-keys
	"alpaquita":  {"distro-keys"},
	"wolfi":      {"wolfi-keys"},
	"chainguard": {"wolfi-keys"},
}

// apkChainguardKey matches the key files the Wolfi and Chainguard images carry
// for Chainguard's repository. apko writes them into /etc/apk/keys when it
// builds an image, so no package owns them, and `apk info -W` finds no owner.
// wolfi-keys owns wolfi-signing.rsa.pub, which does not sign apk.cgr.dev, the
// repository these images are configured with. The name is the rule here,
// weaker than ownership: whoever can write /etc/apk/keys can name a key like
// this, and can also place a key in an owned file.
var apkChainguardKey = regexp.MustCompile(`^chainguard-[0-9a-f]{64}\.rsa\.pub$`)

var apkOSKeyFilePatterns = map[string]*regexp.Regexp{
	"wolfi":      apkChainguardKey,
	"chainguard": apkChainguardKey,
}

// apkInstalled is what the apk database records about one installed package
// that source resolution needs.
type apkInstalled struct {
	name, version, arch string
	// checksum is the package's "C:" value, "Q1" and the base64 SHA-1 of the
	// package's control segment. The repository index lists the same value for
	// the same build, so it tells a rebuild with an unchanged version apart.
	checksum string
}

// apkDB is the part of the installed database source resolution reads.
type apkDB struct {
	pkgs []apkInstalled
	// keyFiles are the files, by package, that the packages in wanted laid
	// down in the keys directory.
	keyFiles map[string][]string
}

// readApkDB reads the installed database once. wanted names the key packages
// whose files are collected.
func readApkDB(fs afero.Fs, wanted map[string]bool) (apkDB, bool) {
	var f afero.File
	for _, p := range ApkDbPaths {
		var err error
		if f, err = fs.Open(p); err == nil {
			break
		}
		f = nil
	}
	if f == nil {
		return apkDB{}, false
	}
	defer f.Close()
	return parseApkDB(f, wanted), true
}

func parseApkDB(r io.Reader, wanted map[string]bool) apkDB {
	db := apkDB{keyFiles: map[string][]string{}}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, apkMaxLine)
	cur := apkInstalled{}
	dir := ""
	flush := func() {
		if cur.name != "" && cur.version != "" {
			db.pkgs = append(db.pkgs, cur)
		}
		cur = apkInstalled{}
		dir = ""
	}
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			flush()
			continue
		}
		key, value, ok := apkField(line)
		if !ok {
			continue
		}
		switch key {
		case 'P':
			cur.name = string(value)
		case 'V':
			cur.version = string(value)
		case 'A':
			cur.arch = string(value)
		case 'C':
			cur.checksum = string(value)
		case 'F':
			dir = string(value)
		case 'R':
			// a package's file lines follow its P: line, so the name is known
			if wanted[cur.name] {
				db.keyFiles[cur.name] = append(db.keyFiles[cur.name], path.Join("/", dir, string(value)))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Debug().Err(err).Msg("mql[packages]> could not read the apk database to its end, sources are resolved from what was read")
	}
	flush()
	return db
}

// apkRepo is one line of /etc/apk/repositories.
type apkRepo struct {
	// tag is the repository tag without its "@", e.g. "testing".
	tag string
	// location is the repository's address or path as written.
	location string
}

// parseApkRepositories reads a repositories file: one repository per line,
// either "<url or path>" or "@<tag> <url or path>". Lines starting with # are
// comments. ok is false when a line is neither, such as a keyword or a variable
// apk-tools 3 accepts: that line names a repository this reader cannot place,
// so the list is not complete. At most apkMaxRepositories are returned, and
// more are not ok either.
func parseApkRepositories(data []byte) (repos []apkRepo, ok bool) {
	ok = true
	for line := range strings.SplitSeq(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(repos) >= apkMaxRepositories {
			return repos, false
		}
		switch {
		case len(fields) == 1 && !strings.HasPrefix(fields[0], "@"):
			repos = append(repos, apkRepo{location: fields[0]})
		case len(fields) == 2 && strings.HasPrefix(fields[0], "@"):
			repos = append(repos, apkRepo{tag: strings.TrimPrefix(fields[0], "@"), location: fields[1]})
		default:
			ok = false
		}
	}
	return repos, ok
}

// apkRepositoriesDirs are the directories apk-tools 3 reads "*.list" files of
// repositories from, besides /etc/apk/repositories. apk-tools 2.14 has none
// (its binary carries no such path), so an Alpine 3.21 host has no such
// directory.
var apkRepositoriesDirs = []string{"/etc/apk/repositories.d", "/lib/apk/repositories.d"}

// readApkRepositories collects every repository apk reads. complete is false
// when a file could not be read or placed.
func readApkRepositories(files *sourceFiles) (repos []apkRepo, complete bool) {
	complete = true
	read := func(p string, required bool) {
		data, err := files.read(p)
		if err != nil {
			if required {
				complete = false
			}
			return
		}
		if len(data) > apkMaxSmallFile {
			complete = false
			return
		}
		r, ok := parseApkRepositories(data)
		complete = complete && ok
		repos = append(repos, r...)
	}
	read(apkRepositories, true)
	for _, dir := range apkRepositoriesDirs {
		entries, err := afero.ReadDir(files.fs, dir)
		if err != nil {
			continue
		}
		for i, e := range entries {
			if i >= apkMaxRepositories {
				complete = false
				break
			}
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".list") {
				read(path.Join(dir, e.Name()), true)
			}
		}
	}
	if len(repos) > apkMaxRepositories {
		repos, complete = repos[:apkMaxRepositories], false
	}
	return repos, complete
}

// isRemote reports whether the repository is fetched over the network, which
// apk caches, as opposed to a directory it reads in place.
func (r apkRepo) isRemote() bool {
	return strings.Contains(r.location, "://") && !strings.HasPrefix(r.location, "file://")
}

// indexPaths are the files the repository's index can be in on the system, for
// a system whose architecture is arch.
//
// apk names a cached index APKINDEX.<hash>.tar.gz, where hash is the first four
// bytes, in hex, of the SHA-1 of "<repository>/<arch>/APKINDEX.tar.gz".
func (r apkRepo) indexPaths(arch string) []string {
	loc := strings.TrimSuffix(r.location, "/")
	indexURL := loc + "/" + arch + "/APKINDEX.tar.gz"
	if r.isRemote() {
		sum := sha1.Sum([]byte(indexURL))
		name := "APKINDEX." + hex.EncodeToString(sum[:4]) + ".tar.gz"
		paths := make([]string, len(apkCacheDirs))
		for i, d := range apkCacheDirs {
			paths[i] = path.Join(d, name)
		}
		return paths
	}
	return []string{strings.TrimPrefix(indexURL, "file://")}
}

// name is how the system names the repository: its tag, else its address
// without scheme, as `apk policy` and the repositories file show it
// ("dl-cdn.alpinelinux.org/alpine/v3.21/main"). The last element alone would
// name Alpine's and a vendor's repository alike "main". Credentials are
// removed.
func (r apkRepo) name() string {
	if r.tag != "" {
		return r.tag
	}
	loc := strings.TrimSuffix(r.location, "/")
	if u, err := url.Parse(loc); err == nil && u.Host != "" {
		return strings.TrimSuffix(u.Host+u.Path, "/")
	}
	return strings.TrimPrefix(loc, "file://")
}

// apkIndex is one repository's index, as far as it concerns the installed
// packages.
type apkIndex struct {
	repo apkRepo
	// osSigned is true when a signature on the index verifies against a key the
	// operating system installed.
	osSigned bool
	// byName holds the entries of the installed package names.
	byName map[string][]apkIndexEntry
}

type apkIndexEntry struct {
	version, arch, checksum string
	index                   *apkIndex
}

// apkIndexes is what the repository indexes on the system say.
type apkIndexes struct {
	// any is true when at least one index was read.
	any bool
	// complete is true when every configured repository has an index on the
	// system. A repository without one could list any package, so a name no
	// index lists proves nothing then.
	complete bool
	// trustKnown is false when the operating system's keys could not be found.
	trustKnown bool
	byName     map[string][]apkIndexEntry
}

// Sources says where each apk package came from (ADR 049).
//
// apk records no repository for an installed package. The package's checksum
// and name are matched against the indexes apk downloaded
// (/var/cache/apk/APKINDEX.*.tar.gz): an index signed by a key the
// distribution's key package installed is the operating system's, any other is
// a vendor's. An image that never ran `apk update` has no index; nothing can
// be decided there, and the answer is null.
func (apm *AlpinePkgManager) Sources(pkgs []Package) ([]Source, error) {
	platform := ""
	if apm.platform != nil {
		platform = apm.platform.Name
	}
	files := newSourceFiles(apm.conn)
	return apkSources(pkgs, readApkIndexes(files, platform)), nil
}

type apkSourceInput struct {
	db      apkDB
	indexes apkIndexes
}

func readApkIndexes(files *sourceFiles, platform string) apkSourceInput {
	wanted := map[string]bool{}
	for _, p := range apkOSKeyPackages[platform] {
		wanted[p] = true
	}
	db, ok := readApkDB(files.fs, wanted)
	if !ok {
		return apkSourceInput{}
	}
	files.prefetch([]string{apkRepositories, apkArchFile})
	repos, reposComplete := readApkRepositories(files)
	arch := apkSystemArch(files, db)
	osKeys := readApkOSKeys(files, platform, db)

	installed := make(map[string]struct{}, len(db.pkgs))
	for _, p := range db.pkgs {
		installed[p.name] = struct{}{}
	}

	out := apkSourceInput{db: db}
	out.indexes.byName = map[string][]apkIndexEntry{}
	out.indexes.trustKnown = len(osKeys) > 0
	out.indexes.complete = len(repos) > 0 && reposComplete
	for _, repo := range repos {
		idx, ok := readApkRepoIndex(files.fs, repo, arch, osKeys, installed)
		if !ok {
			out.indexes.complete = false
			continue
		}
		out.indexes.any = true
		for name, entries := range idx.byName {
			out.indexes.byName[name] = append(out.indexes.byName[name], entries...)
		}
	}
	// An index in the cache that no configured repository explains came from a
	// repository named on a command line (`apk add -X <url> pkg`) or one since
	// removed. Its address is unknown and it is not read: a package may have
	// come from it, so a name no read index lists proves nothing.
	if out.indexes.complete && apkUnexplainedIndex(files.fs, repos, arch) {
		out.indexes.complete = false
	}
	return out
}

// apkUnexplainedIndex reports an APKINDEX file in a cache directory that is
// not the cached index of one of the repositories.
func apkUnexplainedIndex(fs afero.Fs, repos []apkRepo, arch string) bool {
	known := map[string]bool{}
	for _, r := range repos {
		for _, p := range r.indexPaths(arch) {
			known[p] = true
		}
	}
	for _, dir := range apkCacheDirs {
		entries, err := afero.ReadDir(fs, dir)
		if err != nil {
			continue
		}
		for i, e := range entries {
			if i >= 1024 {
				return true
			}
			name := e.Name()
			if !e.IsDir() && strings.HasPrefix(name, "APKINDEX.") && !known[path.Join(dir, name)] {
				return true
			}
		}
	}
	return false
}

// apkSystemArch is the architecture apk builds repository addresses with.
func apkSystemArch(files *sourceFiles, db apkDB) string {
	if data, err := files.read(apkArchFile); err == nil {
		if a := strings.TrimSpace(string(data)); a != "" && len(a) < 32 {
			return a
		}
	}
	// no arch file: the architecture most packages carry
	counts := map[string]int{}
	best := ""
	for _, p := range db.pkgs {
		if p.arch == "" || p.arch == "noarch" {
			continue
		}
		counts[p.arch]++
		if counts[p.arch] > counts[best] {
			best = p.arch
		}
	}
	return best
}

// apkOSKeys holds the RSA keys the operating system installed, by key file
// name.
type apkOSKeys map[string]*rsa.PublicKey

// readApkOSKeys reads the key files the distribution's key packages own, and
// for the distributions that need it the key files an image builder placed.
func readApkOSKeys(files *sourceFiles, platform string, db apkDB) apkOSKeys {
	names := map[string]bool{}
	for _, pkg := range apkOSKeyPackages[platform] {
		for _, f := range db.keyFiles[pkg] {
			if path.Dir(f) == apkKeysDir && strings.HasSuffix(f, ".pub") {
				names[path.Base(f)] = true
			}
		}
	}
	if re := apkOSKeyFilePatterns[platform]; re != nil {
		if entries, err := afero.ReadDir(files.fs, apkKeysDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && re.MatchString(e.Name()) {
					names[e.Name()] = true
				}
			}
		}
	}
	var paths []string
	for n := range names {
		paths = append(paths, path.Join(apkKeysDir, n))
	}
	files.prefetch(paths)
	keys := apkOSKeys{}
	for n := range names {
		data, err := files.read(path.Join(apkKeysDir, n))
		if err != nil || len(data) > apkMaxSmallFile {
			continue
		}
		if pub := parseApkPublicKey(data); pub != nil {
			keys[n] = pub
		}
	}
	return keys
}

func parseApkPublicKey(data []byte) *rsa.PublicKey {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}
	rsaKey, _ := pub.(*rsa.PublicKey)
	return rsaKey
}

// readApkRepoIndex reads one repository's index from wherever the system keeps
// it. ok is false when the system holds none.
func readApkRepoIndex(fs afero.Fs, repo apkRepo, arch string, osKeys apkOSKeys, installed map[string]struct{}) (*apkIndex, bool) {
	if arch == "" {
		return nil, false
	}
	for _, p := range repo.indexPaths(arch) {
		fi, err := fs.Stat(p)
		if err != nil || fi.IsDir() || fi.Size() > apkMaxIndexFile {
			continue
		}
		data, err := afero.ReadFile(fs, p)
		if err != nil {
			continue
		}
		idx, err := parseApkIndex(data, osKeys, installed)
		if err != nil {
			log.Debug().Err(err).Str("path", p).Msg("mql[packages]> could not read an apk index")
			continue
		}
		idx.repo = repo
		for _, entries := range idx.byName {
			for i := range entries {
				entries[i].index = idx
			}
		}
		return idx, true
	}
	return nil, false
}

// apkSignature is one signature of an index: "<algorithm>.<key file name>".
type apkSignature struct {
	hash    crypto.Hash
	keyName string
	sig     []byte
}

// parseApkIndex reads an APKINDEX.tar.gz: two gzip streams back to back. The
// first holds the signature files (.SIGN.RSA.<key>, .SIGN.RSA256.<key>), the
// second a tar with DESCRIPTION and APKINDEX. A signature is over the bytes of
// the second stream as they are stored.
func parseApkIndex(data []byte, osKeys apkOSKeys, installed map[string]struct{}) (*apkIndex, error) {
	br := bytes.NewReader(data)
	gz, err := gzip.NewReader(br)
	if err != nil {
		return nil, err
	}
	// a reader that is not buffered is read exactly to the end of the stream,
	// which tells where the next one starts
	gz.Multistream(false)

	// The first stream holds the signatures and is small. It is read through a
	// cap, so a stream that inflates without end cannot exhaust memory.
	first := &io.LimitedReader{R: gz, N: apkMaxSignatureStream}
	var sigs []apkSignature
	unsigned := &apkIndex{byName: map[string][]apkIndexEntry{}}
	foundInFirst := false
	tr := tar.NewReader(first)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == "APKINDEX" {
			// an index with no signature is one stream holding the archive itself
			if err := readApkIndexText(newLimitedReader(tr, apkMaxIndexText), installed, unsigned); err != nil {
				return nil, err
			}
			foundInFirst = true
			continue
		}
		if len(sigs) >= apkMaxSignatures {
			continue
		}
		if sig, ok := readApkSignature(hdr, tr); ok {
			sigs = append(sigs, sig)
		}
	}
	if _, err := io.Copy(io.Discard, first); err != nil {
		return nil, err
	}
	if first.N <= 0 {
		return nil, errors.New("the signature stream of the index is too large")
	}
	signed := data[len(data)-br.Len():]
	if len(signed) == 0 {
		if foundInFirst {
			// One stream: an index nobody signed. What it lists is never the
			// operating system's.
			return unsigned, nil
		}
		return nil, errors.New("the index holds no APKINDEX")
	}
	// Two streams: the second is what the signatures cover, and the only
	// stream that counts. An APKINDEX entry in the first is outside the
	// signature and is dropped; trusting it would let anyone prepend entries
	// to an index the operating system signed.
	idx := &apkIndex{byName: map[string][]apkIndexEntry{}}
	for _, s := range sigs {
		if pub := osKeys[s.keyName]; pub != nil && s.verifies(pub, signed) {
			idx.osSigned = true
			break
		}
	}

	gz2, err := gzip.NewReader(bytes.NewReader(signed))
	if err != nil {
		return nil, err
	}
	defer gz2.Close()
	tr2 := tar.NewReader(gz2)
	for {
		hdr, err := tr2.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = errors.New("the index holds no APKINDEX")
			}
			return nil, err
		}
		if hdr.Name == "APKINDEX" {
			if err := readApkIndexText(newLimitedReader(tr2, apkMaxIndexText), installed, idx); err != nil {
				return nil, err
			}
			return idx, nil
		}
	}
}

var errTooLarge = errors.New("larger than the limit")

// limitedReader reads at most n bytes and then fails with errTooLarge, unlike
// io.LimitReader, whose cut looks like the end of the data.
type limitedReader struct {
	r io.Reader
	n int64
}

func newLimitedReader(r io.Reader, n int64) io.Reader { return &limitedReader{r: r, n: n} }

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		// at the limit: more data is an error, none is the end
		var one [1]byte
		n, err := l.r.Read(one[:])
		if n > 0 {
			return 0, errTooLarge
		}
		if err != nil {
			return 0, err
		}
		return 0, nil
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// readApkSignature reads one ".SIGN.<algorithm>.<key file name>" entry of the
// signature stream.
func readApkSignature(hdr *tar.Header, r io.Reader) (apkSignature, bool) {
	name, ok := strings.CutPrefix(hdr.Name, ".SIGN.")
	if !ok || hdr.Size > apkMaxSmallFile {
		return apkSignature{}, false
	}
	alg, keyName, ok := strings.Cut(name, ".")
	if !ok {
		return apkSignature{}, false
	}
	var h crypto.Hash
	switch alg {
	case "RSA":
		h = crypto.SHA1
	case "RSA256":
		h = crypto.SHA256
	case "RSA512":
		h = crypto.SHA512
	default:
		return apkSignature{}, false
	}
	sig, err := io.ReadAll(io.LimitReader(r, apkMaxSmallFile))
	if err != nil {
		return apkSignature{}, false
	}
	return apkSignature{hash: h, keyName: keyName, sig: sig}, true
}

func (s apkSignature) verifies(pub *rsa.PublicKey, signed []byte) bool {
	var digest []byte
	switch s.hash {
	case crypto.SHA1:
		sum := sha1.Sum(signed)
		digest = sum[:]
	case crypto.SHA256:
		sum := sha256.Sum256(signed)
		digest = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(signed)
		digest = sum[:]
	default:
		return false
	}
	return rsa.VerifyPKCS1v15(pub, s.hash, digest, s.sig) == nil
}

// readApkIndexText reads the APKINDEX text: blocks of "X:value" lines separated
// by an empty line. Only the entries of installed package names are kept; the
// text of a large index runs to tens of megabytes.
func readApkIndexText(r io.Reader, installed map[string]struct{}, idx *apkIndex) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, apkMaxLine)
	var cur apkIndexEntry
	var name string
	flush := func() {
		if name != "" {
			if _, ok := installed[name]; ok {
				idx.byName[name] = append(idx.byName[name], cur)
			}
		}
		cur, name = apkIndexEntry{}, ""
	}
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			flush()
			continue
		}
		key, value, ok := apkField(line)
		if !ok {
			continue
		}
		switch key {
		case 'P':
			name = string(value)
		case 'V':
			cur.version = string(value)
		case 'A':
			cur.arch = string(value)
		case 'C':
			cur.checksum = string(value)
		}
	}
	flush()
	// a read that stopped early leaves entries out, which would read as
	// "listed nowhere"
	return scanner.Err()
}

// apkSources decides each package's source:
//
//   - the package's build, by checksum, in an index the operating system
//     signed: os
//   - the build only in indexes signed by other keys: vendor-repository
//   - the name in no index, with an index for every configured repository:
//     direct, installed from a file with `apk add ./file.apk`
//   - the version in no index, the name only in OS-signed indexes: os. An
//     index lists only the current version, so a package that missed an
//     update matches the name and not the version.
//   - the version in an index but built differently (another checksum), the
//     version in no index while a third-party index lists the name, a
//     repository without an index, or no keys to tell the operating system's
//     signature: null
func apkSources(pkgs []Package, in apkSourceInput) []Source {
	checksums := make(map[string]string, len(in.db.pkgs))
	for _, p := range in.db.pkgs {
		checksums[p.name+"\x00"+p.version+"\x00"+p.arch] = p.checksum
	}
	out := make([]Source, len(pkgs))
	for i := range pkgs {
		pkg := &pkgs[i]
		if pkg.Format != AlpinePkgFormat {
			out[i] = DefaultSource(*pkg)
			continue
		}
		if !in.indexes.any || !in.indexes.trustKnown {
			out[i] = unknownSource()
			continue
		}
		sum := checksums[pkg.Name+"\x00"+pkg.Version+"\x00"+pkg.Arch]
		out[i] = apkSource(pkg, sum, in.indexes.byName[pkg.Name], in.indexes.complete)
	}
	return out
}

func apkSource(pkg *Package, checksum string, entries []apkIndexEntry, complete bool) Source {
	if len(entries) == 0 {
		if !complete {
			return unknownSource()
		}
		return Source{OSProvided: osProvided(false), Channel: ChannelDirect}
	}
	var exactOS, exactOther *apkIndex
	nameOS, nameOther, rebuilt := false, false, false
	for _, e := range entries {
		if e.index.osSigned {
			nameOS = true
		} else {
			nameOther = true
		}
		if e.version != pkg.Version || (e.arch != pkg.Arch && e.arch != "" && pkg.Arch != "") {
			continue
		}
		if e.checksum != "" && checksum != "" && e.checksum != checksum {
			rebuilt = true
			continue
		}
		switch {
		case e.index.osSigned:
			if exactOS == nil {
				exactOS = e.index
			}
		case exactOther == nil:
			exactOther = e.index
		}
	}
	switch {
	case exactOS != nil:
		return Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: exactOS.repo.name(), URL: apkRepoURL(exactOS.repo)}
	case exactOther != nil:
		return Source{OSProvided: osProvided(false), Channel: ChannelVendorRepository, Name: exactOther.repo.name(), URL: apkRepoURL(exactOther.repo)}
	case rebuilt:
		return unknownSource()
	case nameOS && !nameOther:
		// an operating system package that missed an update
		return Source{OSProvided: osProvided(true), Channel: ChannelOS}
	}
	return unknownSource()
}

// apkRepoURL is the repository's address with credentials removed. A directory
// is not an address and reports none.
func apkRepoURL(r apkRepo) string {
	if !r.isRemote() {
		return ""
	}
	return sanitizeRepoURL(r.location)
}

var _ SourceResolver = (*AlpinePkgManager)(nil)
