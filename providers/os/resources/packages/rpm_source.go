// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	rpmdbbdb "github.com/knqyf263/go-rpmdb/pkg/bdb"
	rpmdbndb "github.com/knqyf263/go-rpmdb/pkg/ndb"
	rpmdbsqlite "github.com/knqyf263/go-rpmdb/pkg/sqlite3"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// rpmOSKeyPackages are, per distribution, the packages that install the keys
// the distribution signs its own packages with. A package signed by a key in
// one of their files is the operating system's.
//
// The list is explicit for the same reason as dpkgOSKeyringPackages: a
// third-party release package installs its key in the same directory.
// epel-release puts RPM-GPG-KEY-EPEL-9 in /etc/pki/rpm-gpg next to the
// distribution's own key, and EPEL is not the operating system.
//
// Each entry was read off the distribution's own image: the package that owns
// the key files whose keys sign the image's packages. Where a distribution
// keeps its keys differs more than its names suggest. RHEL, Oracle Linux and
// Amazon Linux put them in the release package itself; AlmaLinux 9, Rocky,
// CentOS Stream and Fedora in a separate gpg-keys package; Photon and Azure
// Linux in their repos package.
//
// Oracle Linux re-signs its EPEL mirror (ol9_developer_EPEL) with its release
// key, so packages from it are the operating system's under this rule.
var rpmOSKeyPackages = map[string][]string{
	"redhat":              {"redhat-release"},
	"centos":              {"centos-gpg-keys", "centos-release"},
	"centos-stream":       {"centos-gpg-keys"},
	"almalinux":           {"almalinux-gpg-keys", "almalinux-release"},
	"rockylinux":          {"rocky-gpg-keys", "rocky-release"},
	"oraclelinux":         {"oraclelinux-release"},
	"fedora":              {"fedora-gpg-keys"},
	"amazonlinux":         {"system-release"},
	"opensuse":            {"openSUSE-build-key"},
	"opensuse-leap":       {"openSUSE-build-key"},
	"opensuse-tumbleweed": {"openSUSE-build-key"},
	"sles":                {"suse-build-key"},
	"photon":              {"photon-repos"},
	"azurelinux":          {"azurelinux-repos-shared"},
}

// rpmHistoryLocal is the repository id dnf records for a package installed
// from a file on the command line.
const rpmHistoryLocal = "@commandline"

// Sources says where each rpm package came from (ADR 049).
//
// rpm packages are signed one by one, so the package's own signature decides:
// made with a key the distribution's key package installed, the package is the
// operating system's. Which repository it came from is what dnf recorded in
// its transaction history.
func (rpm *RpmPkgManager) Sources(pkgs []Package) ([]Source, error) {
	files := newSourceFiles(rpm.conn)
	fs := files.fs
	platform := ""
	if rpm.platform != nil {
		platform = rpm.platform.Name
	}
	keyPackages := rpmOSKeyPackages[platform]

	var headers []rpmHeader
	var err error
	if files.remote {
		// Over SSH, ask rpm for the signatures rather than copying the rpm
		// database, which is tens of megabytes on a real host.
		headers, err = rpmRemoteHeaders(rpm.conn, keyPackages)
	}
	if !files.remote || err != nil {
		headers, err = readRpmHeaders(rpm.conn)
	}
	if err != nil {
		return nil, err
	}
	osKeys, keysKnown := rpmOSKeys(files, headers, keyPackages)
	var history map[string]string
	if files.remote {
		history = readRpmInstallHistoryRemote(rpm.conn)
	}
	if history == nil {
		history = readRpmInstallHistory(fs)
	}
	repoURLs := readRepoURLs(fs)

	byNEVRA := make(map[string]*rpmHeader, len(headers))
	for i := range headers {
		byNEVRA[headers[i].key()] = &headers[i]
	}

	out := make([]Source, len(pkgs))
	for i := range pkgs {
		pkg := &pkgs[i]
		if pkg.Format != RpmPkgFormat {
			out[i] = DefaultSource(*pkg)
			continue
		}
		h := byNEVRA[rpmKey(pkg.Name, pkg.Version, pkg.Arch)]
		out[i] = rpmSource(pkg, h, osKeys, keysKnown, history, repoURLs)
	}
	return out, nil
}

func rpmSource(pkg *Package, h *rpmHeader, osKeys openPGPKeys, keysKnown bool, history map[string]string, repoURLs map[string]string) Source {
	repo := reportedRepoID(history[rpmKey(pkg.Name, pkg.Version, pkg.Arch)])
	url := repoURLs[repo]

	// gpg-pubkey entries are the keys rpm imported, not packages anyone
	// installed. A key is the operating system's when it is one of the keys
	// the distribution ships.
	if pkg.Name == "gpg-pubkey" {
		if !keysKnown {
			return unknownSource()
		}
		if osKeys.hasKeyID(strings.SplitN(pkg.Version, "-", 2)[0]) {
			return Source{OSProvided: osProvided(true), Channel: ChannelOS}
		}
		return Source{OSProvided: osProvided(false), Channel: ChannelDirect}
	}

	if h == nil || !keysKnown {
		// Without the package's record or the distribution's keys, nothing
		// says whether it is the operating system's; the repository dnf
		// recorded is still reported.
		return Source{Channel: ChannelUnknown, Name: repo, URL: url}
	}
	if osKeys.signedBy(h.issuers) {
		return Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: repo, URL: url}
	}
	if repo == "" {
		// installed from a file, or by a tool that left no history
		return Source{OSProvided: osProvided(false), Channel: ChannelDirect}
	}
	return Source{OSProvided: osProvided(false), Channel: ChannelVendorRepository, Name: repo, URL: url}
}

// reportedRepoID turns what the history recorded into a repository name, or ""
// when it names none: a file installed from the command line, the installed
// system itself, or the throwaway repository an image build used. Image
// builders (kiwi for Fedora and Rocky) give that repository a random 32-digit
// hex id that names nothing anyone could look up.
func reportedRepoID(repo string) string {
	switch {
	case repo == rpmHistoryLocal, repo == "@System", repo == zyppLocalRepo:
		return ""
	case strings.HasPrefix(repo, "/"):
		// yum records a local file as the path it was installed from
		return ""
	case len(repo) == 32 && strings.Trim(repo, "0123456789abcdef") == "":
		return ""
	}
	return repo
}

// rpmKey identifies a package the way the package list prints it: name,
// [epoch:]version-release and architecture.
func rpmKey(name, version, arch string) string {
	return name + "\x00" + version + "\x00" + arch
}

// rpmHeader is what Sources reads from one package's header in the rpm
// database.
type rpmHeader struct {
	name, version, release, arch string
	epoch                        *int32
	// issuers are the key IDs and fingerprints of the package's signatures.
	issuers []string
	// files are the paths the package installed.
	files []string
}

func (h *rpmHeader) key() string {
	v := h.version
	if h.epoch != nil {
		if e := normalizeRpmEpoch(strconv.Itoa(int(*h.epoch))); e != "" {
			v = e + ":" + v
		}
	}
	if h.release != "" {
		v += "-" + h.release
	}
	return rpmKey(h.name, v, h.arch)
}

// rpm header tags Sources reads. The signature tags are copied into the
// installed header when the package is installed.
const (
	rpmTagSigPGP     = 259
	rpmTagSigGPG     = 262
	rpmTagDSAHeader  = 267
	rpmTagRSAHeader  = 268
	rpmTagName       = 1000
	rpmTagVersion    = 1001
	rpmTagRelease    = 1002
	rpmTagEpoch      = 1003
	rpmTagArch       = 1022
	rpmTagDirIndexes = 1116
	rpmTagBaseNames  = 1117
	rpmTagDirNames   = 1118
)

const (
	rpmTypeInt32       = 4
	rpmTypeString      = 6
	rpmTypeBin         = 7
	rpmTypeStringArray = 8
	rpmTypeI18NString  = 9
)

// parseRpmHeader reads the tags Sources needs from a header blob as the rpm
// database stores it: two big-endian counts (index entries, data bytes), the
// index entries of 16 bytes each (tag, type, offset, count), then the data.
func parseRpmHeader(blob []byte) (rpmHeader, error) {
	var h rpmHeader
	if len(blob) < 8 {
		return h, errors.New("rpm header too short")
	}
	il := int(binary.BigEndian.Uint32(blob[0:4]))
	dl := int(binary.BigEndian.Uint32(blob[4:8]))
	if il <= 0 || il > 0xffff || dl < 0 || 8+il*16+dl > len(blob) {
		return h, errors.New("rpm header counts out of range")
	}
	data := blob[8+il*16 : 8+il*16+dl]

	var baseNames, dirNames []string
	var dirIndexes []int32
	for i := 0; i < il; i++ {
		e := blob[8+i*16 : 8+(i+1)*16]
		tag := int32(binary.BigEndian.Uint32(e[0:4]))
		typ := binary.BigEndian.Uint32(e[4:8])
		off := int(int32(binary.BigEndian.Uint32(e[8:12])))
		count := int(binary.BigEndian.Uint32(e[12:16]))
		if off < 0 || off > len(data) {
			continue
		}
		switch tag {
		case rpmTagName, rpmTagVersion, rpmTagRelease, rpmTagArch:
			if typ != rpmTypeString && typ != rpmTypeI18NString {
				continue
			}
			s := rpmString(data[off:])
			switch tag {
			case rpmTagName:
				h.name = s
			case rpmTagVersion:
				h.version = s
			case rpmTagRelease:
				h.release = s
			case rpmTagArch:
				h.arch = s
			}
		case rpmTagEpoch:
			if typ == rpmTypeInt32 && off+4 <= len(data) {
				ep := int32(binary.BigEndian.Uint32(data[off : off+4]))
				h.epoch = &ep
			}
		case rpmTagRSAHeader, rpmTagDSAHeader, rpmTagSigPGP, rpmTagSigGPG:
			if typ != rpmTypeBin || count > len(data) || off+count > len(data) {
				continue
			}
			h.issuers = append(h.issuers, signatureIssuers(data[off:off+count])...)
		case rpmTagBaseNames, rpmTagDirNames:
			if typ != rpmTypeStringArray {
				continue
			}
			list := rpmStrings(data[off:], count)
			if tag == rpmTagBaseNames {
				baseNames = list
			} else {
				dirNames = list
			}
		case rpmTagDirIndexes:
			if typ != rpmTypeInt32 || count > len(data)/4 || off+4*count > len(data) {
				continue
			}
			dirIndexes = make([]int32, count)
			for j := range dirIndexes {
				dirIndexes[j] = int32(binary.BigEndian.Uint32(data[off+4*j : off+4*j+4]))
			}
		}
	}
	if len(baseNames) == len(dirIndexes) {
		for i, base := range baseNames {
			d := int(dirIndexes[i])
			if d >= 0 && d < len(dirNames) {
				h.files = append(h.files, dirNames[d]+base)
			}
		}
	}
	return h, nil
}

func rpmString(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// rpmStrings reads count NUL-terminated strings. count comes from the header
// and is not trusted: a string takes at least one byte, so there can be no
// more than there are bytes left.
func rpmStrings(b []byte, count int) []string {
	out := make([]string, 0, min(count, len(b)))
	for len(out) < count && len(b) > 0 {
		i := indexByte(b, 0)
		if i < 0 {
			out = append(out, string(b))
			break
		}
		out = append(out, string(b[:i]))
		b = b[i+1:]
	}
	return out
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// rpmDBFiles are the rpm database locations staticList probes, with the
// format each is in.
var rpmDBFiles = []struct{ path, format string }{
	{"/usr/lib/sysimage/rpm/rpmdb.sqlite", "sqlite"},
	{"/var/lib/rpm/rpmdb.sqlite", "sqlite"},
	{"/usr/share/rpm/rpmdb.sqlite", "sqlite"},
	{"/usr/lib/sysimage/rpm/Packages.db", "ndb"},
	{"/var/lib/rpm/Packages.db", "ndb"},
	{"/usr/lib/sysimage/rpm/Packages", "bdb"},
	{"/var/lib/rpm/Packages", "bdb"},
}

// readRpmHeaders reads every package header from the rpm database. It reads
// the database file rather than asking rpm, so it answers the same way on a
// running host and on an image: the rpm query format prints a signature only
// as text, and only the newer tags.
func readRpmHeaders(conn shared.Connection) ([]rpmHeader, error) {
	fs := conn.FileSystem()
	for _, db := range rpmDBFiles {
		if _, err := fs.Stat(db.path); err != nil {
			continue
		}
		dir, err := os.MkdirTemp("", "mondoo-rpmsrc")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		local := filepath.Join(dir, path.Base(db.path))
		// a sqlite database in WAL mode keeps recent writes beside it
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if err := copyToLocal(fs, db.path+suffix, local+suffix); err != nil && suffix == "" {
				return nil, err
			}
		}
		return readRpmHeaderBlobs(local, db.format)
	}
	return nil, errors.New("no rpm database found")
}

func copyToLocal(fs afero.Fs, src, dst string) error {
	f, err := fs.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, f)
	return err
}

func readRpmHeaderBlobs(local, format string) ([]rpmHeader, error) {
	var headers []rpmHeader
	add := func(blob []byte) {
		h, err := parseRpmHeader(blob)
		if err != nil || h.name == "" {
			return
		}
		headers = append(headers, h)
	}
	switch format {
	case "sqlite":
		db, err := rpmdbsqlite.Open(local)
		if err != nil {
			return nil, err
		}
		defer db.Close()
		for e := range db.Read() {
			if e.Err != nil {
				return headers, e.Err
			}
			add(e.Value)
		}
	case "ndb":
		db, err := rpmdbndb.Open(local)
		if err != nil {
			return nil, err
		}
		defer db.Close()
		for e := range db.Read() {
			if e.Err != nil {
				return headers, e.Err
			}
			add(e.Value)
		}
	case "bdb":
		db, err := rpmdbbdb.Open(local)
		if err != nil {
			return nil, err
		}
		defer db.Close()
		for e := range db.Read() {
			if e.Err != nil {
				return headers, e.Err
			}
			add(e.Value)
		}
	}
	return headers, nil
}

// rpmOSKeys collects the keys in every file the distribution's key packages
// installed. The second result is false when the distribution is not known,
// or none of its key packages is installed.
func rpmOSKeys(files *sourceFiles, headers []rpmHeader, keyPackages []string) (openPGPKeys, bool) {
	keys := openPGPKeys{}
	wanted := map[string]bool{}
	for _, n := range keyPackages {
		wanted[n] = true
	}
	var keyFiles []string
	for i := range headers {
		if !wanted[headers[i].name] {
			continue
		}
		for _, f := range headers[i].files {
			if strings.Contains(f, "RPM-GPG-KEY") || isKeyFile(f) || strings.HasPrefix(f, "/etc/pki/rpm-gpg/") {
				keyFiles = append(keyFiles, f)
			}
		}
	}
	files.prefetch(keyFiles)
	for _, f := range keyFiles {
		keys.addFile(files, f)
	}
	return keys, len(keys) > 0
}

// rpmRemoteQuery prints each package's identity and signatures, one per line,
// tab-separated. %{EPOCH} rather than %{EPOCHNUM}, which rpm 4.11 (Amazon
// Linux 2, RHEL 7) does not know; it prints "(none)" for no epoch.
const rpmRemoteQuery = `rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{RSAHEADER:pgpsig}\t%{DSAHEADER:pgpsig}\t%{SIGPGP:pgpsig}\t%{SIGGPG:pgpsig}\n'`

// rpmRemoteHeaders reads the packages' signatures with rpm itself, and the
// files of the key packages with rpm -q.
func rpmRemoteHeaders(conn shared.Connection, keyPackages []string) ([]rpmHeader, error) {
	cmd, err := conn.RunCommand(rpmRemoteQuery)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, errors.New("rpm -qa failed")
	}
	headers := parseRpmRemoteHeaders(readCommandOutput(cmd.Stdout))
	if len(keyPackages) == 0 {
		return headers, nil
	}
	quoted := make([]string, len(keyPackages))
	for i, p := range keyPackages {
		quoted[i] = shellQuote(p)
	}
	// rpm -q prints "package <name> is not installed" for a missing one and
	// exits non-zero; the files of the others are still listed
	list, err := conn.RunCommand("rpm -q --qf '#%{NAME}\\n[%{FILENAMES}\\n]' " + strings.Join(quoted, " "))
	if err != nil {
		return headers, nil
	}
	owned := parseRpmFileLists(readCommandOutput(list.Stdout))
	for i := range headers {
		if f, ok := owned[headers[i].name]; ok {
			headers[i].files = f
		}
	}
	return headers, nil
}

func parseRpmRemoteHeaders(out string) []rpmHeader {
	var headers []rpmHeader
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 9 || f[0] == "" {
			continue
		}
		h := rpmHeader{name: f[0], version: f[2], release: f[3], arch: f[4]}
		if e, err := strconv.ParseInt(f[1], 10, 32); err == nil {
			ep := int32(e)
			h.epoch = &ep
		}
		for _, sig := range f[5:9] {
			if id := pgpsigKeyID(sig); id != "" {
				h.issuers = append(h.issuers, id)
			}
		}
		headers = append(headers, h)
	}
	return headers
}

// pgpsigKeyID reads the key ID out of rpm's :pgpsig rendering of a signature,
// "RSA/SHA256, Mon 14 Mar 2022 11:20:00 AM UTC, Key ID d36cb86cb86b3716", or
// "" for "(none)".
func pgpsigKeyID(sig string) string {
	_, id, ok := strings.Cut(sig, "Key ID ")
	if !ok {
		return ""
	}
	id = strings.ToUpper(strings.TrimSpace(id))
	if strings.Trim(id, "0123456789ABCDEF") != "" {
		return ""
	}
	return id
}

// parseRpmFileLists reads "#<name>" lines followed by that package's files.
func parseRpmFileLists(out string) map[string][]string {
	owned := map[string][]string{}
	current := ""
	for _, line := range strings.Split(out, "\n") {
		if n, ok := strings.CutPrefix(line, "#"); ok {
			current = n
			continue
		}
		if current != "" && strings.HasPrefix(line, "/") {
			owned[current] = append(owned[current], line)
		}
	}
	return owned
}

// readRpmInstallHistory maps each installed package to the repository its
// current version was installed from, as the package manager's history
// recorded it: dnf's transaction history, zypper's history log, or yum's
// per-package database. tdnf (Photon, Azure Linux) records no repository.
func readRpmInstallHistory(fs afero.Fs) map[string]string {
	if h := readDnfHistory(fs); len(h) > 0 {
		return h
	}
	if h := readZyppHistory(fs); len(h) > 0 {
		return h
	}
	return readYumDB(fs)
}

// rpmHistoryRemoteCmd reads the install history on the scanned system and
// prints one tab-separated line per install (name, epoch, version, release,
// arch, repository), oldest first. dnf's history database grows with every
// transaction and keeps a write-ahead log beside it: tens of megabytes on a
// long-lived server, too much to copy over SSH on every scan. The Python that
// dnf itself runs on queries it in place. zypper's log is filtered to its
// install lines, and yum's per-package database is read in one pass.
const rpmHistoryRemoteCmd = `for db in /usr/lib/sysimage/libdnf5/transaction_history.sqlite /var/lib/dnf/history.sqlite; do
[ -r "$db" ] || continue
for py in /usr/libexec/platform-python python3; do
command -v "$py" >/dev/null 2>&1 || continue
exec "$py" -c '
import sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
dnf5 = db.execute("SELECT count(*) FROM sqlite_master WHERE type=? AND name=?", ("table", "pkg_name")).fetchone()[0]
if dnf5:
    q = ("SELECT n.name, r.epoch, r.version, r.release, a.name, rp.repoid FROM trans_item ti JOIN rpm r ON r.item_id = ti.item_id "
         "JOIN pkg_name n ON n.id = r.name_id JOIN arch a ON a.id = r.arch_id JOIN repo rp ON rp.id = ti.repo_id "
         "JOIN trans_item_action act ON act.id = ti.action_id WHERE act.name IN (?, ?, ?, ?, ?) ORDER BY ti.trans_id")
    args = ("Install", "Downgrade", "Obsolete", "Upgrade", "Reinstall")
else:
    q = ("SELECT r.name, r.epoch, r.version, r.release, r.arch, rp.repoid FROM trans_item ti JOIN rpm r ON r.item_id = ti.item_id "
         "JOIN repo rp ON rp.id = ti.repo_id WHERE ti.action IN (1, 2, 4, 6, 9) ORDER BY ti.trans_id")
    args = ()
for row in db.execute(q, args):
    sys.stdout.write("\t".join("" if v is None else str(v) for v in row) + "\n")
' "$db"
done
exit 3
done
if [ -r /var/log/zypp/history ]; then
grep "|install|" /var/log/zypp/history | awk -F"|" "{print \$3 \"\t\t\" \$4 \"\t\t\" \$5 \"\t\" \$7}"
exit 0
fi
if [ -d /var/lib/yum/yumdb ]; then
for d in /var/lib/yum/yumdb/*/*; do [ -r "$d/from_repo" ] && printf "#%s\t%s\n" "${d##*/}" "$(cat "$d/from_repo")"; done
exit 0
fi
exit 3`

// readRpmInstallHistoryRemote runs rpmHistoryRemoteCmd. It returns nil when the
// command could not answer, so the caller reads the files instead.
func readRpmInstallHistoryRemote(conn shared.Connection) map[string]string {
	cmd, err := conn.RunCommand(rpmHistoryRemoteCmd)
	if err != nil || cmd.ExitStatus != 0 {
		return nil
	}
	return parseRpmHistoryRemote(readCommandOutput(cmd.Stdout))
}

// parseRpmHistoryRemote reads rpmHistoryRemoteCmd's output. dnf and zypper
// lines are name, epoch, version, release, arch, repository; zypper's edition
// is printed whole as the version with no release. A yumdb line is the
// package's directory name behind a "#", then its repository.
func parseRpmHistoryRemote(out string) map[string]string {
	hist := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if dir, ok := strings.CutPrefix(line, "#"); ok {
			name, repo, ok := strings.Cut(dir, "\t")
			if !ok {
				continue
			}
			if key, ok := yumDBEntryKey(name); ok {
				hist[key] = strings.TrimSpace(repo)
			}
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 6 || f[0] == "" {
			continue
		}
		v := f[2]
		if e := normalizeRpmEpoch(f[1]); e != "" {
			v = e + ":" + v
		}
		if f[3] != "" {
			v += "-" + f[3]
		}
		hist[rpmKey(f[0], v, f[4])] = f[5]
	}
	return hist
}

// zyppHistoryLog is zypper's install log: one "|"-separated line per action.
const zyppHistoryLog = "/var/log/zypp/history"

// zyppLocalRepo is the alias zypper records for a package installed from a
// file.
const zyppLocalRepo = "_tmpRPMcache_"

// readZyppHistory reads install lines of zypper's history log:
//
//	2026-10-05 20:41:13|install|fish|3.7.1-150600.1.2|aarch64|root@host|shells_fish|<checksum>|
//
// The seventh field is the repository alias. Later lines win, so the line of
// the version installed now is the one kept.
func readZyppHistory(fs afero.Fs) map[string]string {
	data, err := afero.ReadFile(fs, zyppHistoryLog)
	if err != nil {
		return nil
	}
	return parseZyppHistory(data)
}

func parseZyppHistory(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "|")
		if len(f) < 7 || f[1] != "install" {
			continue
		}
		out[rpmKey(f[2], f[3], f[4])] = f[6]
	}
	return out
}

// yumDBDir is where yum (Amazon Linux 2, RHEL 7) keeps per-package metadata:
// one directory per package named "<checksum>-<name>-<version>-<release>-<arch>",
// holding a from_repo file.
const yumDBDir = "/var/lib/yum/yumdb"

func readYumDB(fs afero.Fs) map[string]string {
	out := map[string]string{}
	shards, err := afero.ReadDir(fs, yumDBDir)
	if err != nil {
		return nil
	}
	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}
		entries, err := afero.ReadDir(fs, path.Join(yumDBDir, shard.Name()))
		if err != nil {
			continue
		}
		for _, e := range entries {
			key, ok := yumDBEntryKey(e.Name())
			if !ok {
				continue
			}
			repo, err := afero.ReadFile(fs, path.Join(yumDBDir, shard.Name(), e.Name(), "from_repo"))
			if err != nil {
				continue
			}
			out[key] = strings.TrimSpace(string(repo))
		}
	}
	return out
}

// yumDBEntryKey parses a yumdb directory name. The name can contain dashes, so
// the fields are split off from the right: arch, release, version, and the
// checksum before the first dash.
func yumDBEntryKey(dir string) (string, bool) {
	_, rest, ok := strings.Cut(dir, "-")
	if !ok {
		return "", false
	}
	parts := strings.Split(rest, "-")
	if len(parts) < 4 {
		return "", false
	}
	n := len(parts)
	name := strings.Join(parts[:n-3], "-")
	return rpmKey(name, parts[n-3]+"-"+parts[n-2], parts[n-1]), true
}

// dnfHistoryDBs are dnf's transaction history databases: dnf5 first, then dnf4.
var dnfHistoryDBs = []string{
	"/usr/lib/sysimage/libdnf5/transaction_history.sqlite",
	"/var/lib/dnf/history.sqlite",
}

// readDnfHistory maps each installed package to the repository id of the
// transaction that installed its current version.
func readDnfHistory(fs afero.Fs) map[string]string {
	for _, p := range dnfHistoryDBs {
		if _, err := fs.Stat(p); err != nil {
			continue
		}
		dir, err := os.MkdirTemp("", "mondoo-dnfhist")
		if err != nil {
			return nil
		}
		defer os.RemoveAll(dir)
		local := filepath.Join(dir, "history.sqlite")
		// the write-ahead log holds whatever dnf has not checkpointed yet;
		// on an image it can hold the whole image build
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if err := copyToLocal(fs, p+suffix, local+suffix); err != nil && suffix == "" {
				return nil
			}
		}
		hist, err := queryDnfHistory(local)
		if err != nil {
			log.Debug().Err(err).Str("path", p).Msg("could not read dnf history")
			return nil
		}
		return hist
	}
	return nil
}

// dnf4 stores the package name, epoch and arch in the rpm table; dnf5 moves
// name and arch into lookup tables and the action into an enum table. Both
// list the install of the current version as the newest install-type item.
const dnf4HistoryQuery = `
SELECT r.name, r.epoch, r.version, r.release, r.arch, rp.repoid, ti.trans_id
FROM trans_item ti
JOIN rpm r ON r.item_id = ti.item_id
JOIN repo rp ON rp.id = ti.repo_id
WHERE ti.action IN (1, 2, 4, 6, 9)
ORDER BY ti.trans_id`

const dnf5HistoryQuery = `
SELECT n.name, r.epoch, r.version, r.release, a.name, rp.repoid, ti.trans_id
FROM trans_item ti
JOIN rpm r ON r.item_id = ti.item_id
JOIN pkg_name n ON n.id = r.name_id
JOIN arch a ON a.id = r.arch_id
JOIN repo rp ON rp.id = ti.repo_id
JOIN trans_item_action act ON act.id = ti.action_id
WHERE act.name IN ('Install', 'Downgrade', 'Obsolete', 'Upgrade', 'Reinstall')
ORDER BY ti.trans_id`

func queryDnfHistory(local string) (map[string]string, error) {
	db, err := sql.Open("sqlite", "file:"+local+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	q := dnf4HistoryQuery
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='pkg_name'`).Scan(&n); err == nil && n > 0 {
		q = dnf5HistoryQuery
	}
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var name, version, release, arch, repo string
		var epoch sql.NullInt64
		var trans int64
		if err := rows.Scan(&name, &epoch, &version, &release, &arch, &repo, &trans); err != nil {
			return nil, err
		}
		v := version
		if epoch.Valid {
			if e := normalizeRpmEpoch(strconv.FormatInt(epoch.Int64, 10)); e != "" {
				v = e + ":" + v
			}
		}
		if release != "" {
			v += "-" + release
		}
		// rows come oldest first, so the newest install wins
		out[rpmKey(name, v, arch)] = repo
	}
	return out, rows.Err()
}

// readRepoURLs maps each repository id in the dnf and zypper repository
// files to its address: baseurl, else metalink, else mirrorlist, without
// credentials.
func readRepoURLs(fs afero.Fs) map[string]string {
	out := map[string]string{}
	for _, dir := range []string{"/etc/yum.repos.d", "/etc/zypp/repos.d", "/etc/distro.repos.d"} {
		entries, err := afero.ReadDir(fs, dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".repo") {
				continue
			}
			data, err := afero.ReadFile(fs, path.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			for id, u := range parseRepoFile(data) {
				if _, ok := out[id]; !ok {
					out[id] = u
				}
			}
		}
	}
	return out
}

// parseRepoFile reads an INI-style .repo file into repository id -> address.
func parseRepoFile(data []byte) map[string]string {
	out := map[string]string{}
	type urls struct{ base, meta, mirror string }
	sections := map[string]*urls{}
	var cur *urls
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			id := strings.TrimSpace(line[1 : len(line)-1])
			cur = &urls{}
			sections[id] = cur
			continue
		}
		if cur == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		// baseurl can list several addresses; the first is the repository's
		value = strings.TrimSpace(value)
		if fields := strings.Fields(value); len(fields) > 0 {
			value = fields[0]
		}
		switch key {
		case "baseurl":
			if cur.base == "" {
				cur.base = value
			}
		case "metalink":
			cur.meta = value
		case "mirrorlist":
			cur.mirror = value
		}
	}
	for id, u := range sections {
		for _, candidate := range []string{u.base, u.meta, u.mirror} {
			if clean := sanitizeRepoURL(candidate); clean != "" {
				out[id] = clean
				break
			}
		}
	}
	return out
}
