// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/java"
)

type mqlJavaKeystoreInternal struct {
	lock     sync.Mutex
	parsed   *java.Keystore
	parseErr error
	// readable and unreadable cache the X.509 pass over the store's
	// certificates. A policy that asks for both certificates and
	// unreadableCertificates would otherwise parse every certificate twice.
	readable   [][]byte
	unreadable int
	splitDone  bool
}

type mqlJavaKeystoreEntryInternal struct {
	// certs holds the entry's DER-encoded certificates, carried over from the
	// parse so the entry does not have to re-read the store.
	certs [][]byte
}

func initJavaKeystore(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		p, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in java.keystore initialization, it must be a string")
		}
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(p),
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")
	}
	return args, nil, nil
}

func (s *mqlJavaKeystore) id() (string, error) {
	return "java.keystore/" + s.Path.Data, nil
}

func (s *mqlJavaKeystore) file() (*mqlFile, error) {
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(s.Path.Data),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// read parses the store once and caches it on the resource. Every field goes
// through here so a store is read a single time however many are asked for.
func (s *mqlJavaKeystore) read() (*java.Keystore, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.parsed != nil {
		return s.parsed, nil
	}
	if s.parseErr != nil {
		return nil, s.parseErr
	}

	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	f, err := afs.Open(s.Path.Data)
	if err != nil {
		s.parseErr = err
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		s.parseErr = err
		return nil, err
	}

	// The password is only consulted for PKCS#12; a JKS store does not need one.
	ks, err := java.Parse(data, "")
	if err != nil {
		s.parseErr = err
		return nil, err
	}

	s.parsed = ks
	return ks, nil
}

func (s *mqlJavaKeystore) format() (string, error) {
	ks, err := s.read()
	if err != nil {
		return "", err
	}
	return ks.Format, nil
}

func (s *mqlJavaKeystore) entries() ([]any, error) {
	ks, err := s.read()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(ks.Entries))
	for i := range ks.Entries {
		entry := ks.Entries[i]

		createdAt := llx.NilData
		if !entry.CreatedAt.IsZero() {
			at := entry.CreatedAt
			createdAt = llx.TimeData(at)
		}

		raw, err := CreateResource(s.MqlRuntime, "java.keystore.entry", map[string]*llx.RawData{
			// The index is part of the id, not decoration. Two entries can carry
			// the same alias — a PKCS#12 store may repeat a friendlyName or omit
			// it entirely, leaving several entries aliased "" — and an id that
			// collided would hand back the cached first entry, whose certificates
			// the second would then overwrite. One entry would be reported where
			// there are two, with the wrong contents.
			"__id":                 llx.StringData(fmt.Sprintf("%s/%s#%d", s.Path.Data, entry.Alias, i)),
			"alias":                llx.StringData(entry.Alias),
			"isTrustedCertificate": llx.BoolData(entry.Trusted),
			"createdAt":            createdAt,
		})
		if err != nil {
			return nil, err
		}
		mqlEntry := raw.(*mqlJavaKeystoreEntry)
		mqlEntry.certs = entry.Certs
		res = append(res, mqlEntry)
	}
	return res, nil
}

// split runs the X.509 pass over the whole store once and caches the result.
func (s *mqlJavaKeystore) split() ([][]byte, int, error) {
	ks, err := s.read()
	if err != nil {
		return nil, 0, err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	if !s.splitDone {
		var der [][]byte
		for i := range ks.Entries {
			der = append(der, ks.Entries[i].Certs...)
		}
		s.readable, s.unreadable = readableDER(der)
		s.splitDone = true
	}
	return s.readable, s.unreadable, nil
}

func (s *mqlJavaKeystore) certificates() ([]any, error) {
	readable, _, err := s.split()
	if err != nil {
		return nil, err
	}
	return certificatesToMql(s.MqlRuntime, readable)
}

// unreadableCertificates counts what certificates() had to skip.
func (s *mqlJavaKeystore) unreadableCertificates() (int64, error) {
	_, unreadable, err := s.split()
	if err != nil {
		return 0, err
	}
	return int64(unreadable), nil
}

func (s *mqlJavaKeystoreEntry) id() (string, error) {
	return s.__id, nil
}

func (s *mqlJavaKeystoreEntry) certificates() ([]any, error) {
	return certificatesFromDER(s.MqlRuntime, s.certs)
}

// readableDER splits certificates into those the X.509 parser accepts and a
// count of those it does not.
//
// A trust store assembled over years holds certificates that no longer parse —
// a negative serial number is the common one, legal when the certificate was
// issued and rejected by Go today. RHEL 7's store has exactly one such
// certificate out of 133. Handing the whole batch downstream fails on the first
// of them and the store reports nothing at all, so one twenty-year-old CA
// blinds every check. Skipping them keeps the other 132 assertable; the count is
// what stops that being a silent loss.
func readableDER(der [][]byte) ([][]byte, int) {
	out := make([][]byte, 0, len(der))
	unreadable := 0
	for i := range der {
		if _, err := x509.ParseCertificate(der[i]); err != nil {
			unreadable++
			continue
		}
		out = append(out, der[i])
	}
	return out, unreadable
}

// certificatesFromDER hands DER-encoded certificates to the shared
// `certificates` resource, which is what produces `network.certificate`. The
// bytes are PEM-wrapped first because that is the interface it takes.
func certificatesFromDER(runtime *plugin.Runtime, der [][]byte) ([]any, error) {
	readable, _ := readableDER(der)
	return certificatesToMql(runtime, readable)
}

// certificatesToMql wraps already-validated DER as network.certificate.
func certificatesToMql(runtime *plugin.Runtime, der [][]byte) ([]any, error) {
	if len(der) == 0 {
		return []any{}, nil
	}

	var buf strings.Builder
	for i := range der {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der[i]}); err != nil {
			return nil, err
		}
	}

	certs, err := runtime.CreateSharedResource("certificates", map[string]*llx.RawData{
		"pem": llx.StringData(buf.String()),
	})
	if err != nil {
		return nil, err
	}

	list, err := runtime.GetSharedData("certificates", certs.MqlID(), "list")
	if err != nil {
		return nil, err
	}
	return list.Value.([]any), nil
}

// javaTruststoreDirs are the directories a JDK or JRE keeps its trust store in,
// relative to the runtime's own root. JDK 9 moved it up out of `jre/`.
var javaTruststoreDirs = []string{
	"lib/security",
	"jre/lib/security",
}

// javaHomeRoots are the directories JVMs get installed under. Each is scanned
// one level deep, since a machine commonly has several runtimes side by side.
var javaHomeRoots = []string{
	"/usr/lib/jvm",
	// SUSE installs its JVMs under lib64.
	"/usr/lib64/jvm",
	"/usr/java",
	"/opt/java",
	"/opt/jdk",
	"/Library/Java/JavaVirtualMachines",
}

// javaTruststoreFiles are absolute paths that hold a trust store in their own
// right: a distribution-managed store, or a JVM installed at a fixed location.
var javaTruststoreFiles = []string{
	"/etc/ssl/certs/java/cacerts",
	"/etc/pki/java/cacerts",
	// SUSE's store, maintained by update-ca-certificates. It exists even with
	// no JVM installed, and every SUSE JVM's cacerts links to it.
	"/var/lib/ca-certificates/java-cacerts",
	"/opt/java/openjdk/lib/security/cacerts",
}

func (s *mqlJavaTruststores) id() (string, error) {
	return "java.truststores", nil
}

func (s *mqlJavaTruststores) paths() ([]any, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	found := map[string]struct{}{}

	add := func(p string) {
		if ok, _ := afs.Exists(p); ok {
			found[p] = struct{}{}
		}
	}

	for _, p := range javaTruststoreFiles {
		add(p)
	}

	// A machine usually has more than one runtime installed, and they do not
	// have to agree about what they trust, so every one of them is reported
	// rather than the first that turns up.
	for _, root := range javaHomeRoots {
		entries, err := afs.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			// macOS nests the runtime one level further, under Contents/Home.
			for _, home := range []string{
				path.Join(root, entry.Name()),
				path.Join(root, entry.Name(), "Contents", "Home"),
			} {
				for _, dir := range javaTruststoreDirs {
					add(path.Join(home, dir, "cacerts"))
				}
			}
		}
	}

	candidates := make([]string, 0, len(found))
	for p := range found {
		candidates = append(candidates, p)
	}

	// Distributions point every JVM's cacerts at one shared store (RHEL links
	// all of them to /etc/pki/ca-trust/extracted/java/cacerts, Debian to
	// /etc/ssl/certs/java/cacerts), and version aliases such as
	// /usr/lib/jvm/java-21 link to a JDK directory that is listed as well.
	// Reporting each name would audit one file many times over.
	out := dedupeByRealPath(candidates, resolveTruststorePaths(conn, candidates))

	res := make([]any, 0, len(out))
	for _, p := range out {
		res = append(res, p)
	}
	return res, nil
}

// maxSymlinkHops bounds symlink resolution, as the kernel's own limit does, so
// that a link loop ends in an error instead of spinning forever.
const maxSymlinkHops = 40

// resolveTruststorePaths maps each candidate to the file it names once every
// symlink along the way is followed. A filesystem that can read links is
// walked directly; otherwise (SSH, sudo through cat) one shell loop asks
// readlink -f for all of them. A candidate that cannot be resolved is left out
// of the map and keeps its own name.
func resolveTruststorePaths(conn shared.Connection, candidates []string) map[string]string {
	real := make(map[string]string, len(candidates))
	if len(candidates) == 0 {
		return real
	}

	if lr, ok := conn.FileSystem().(afero.LinkReader); ok {
		for _, p := range candidates {
			if r, err := resolveSymlinks(lr, p); err == nil {
				real[p] = r
			}
		}
		return real
	}

	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return real
	}
	// Candidate names include directory entries read from the target (the
	// JVM directories under each javaHomeRoots entry), so every name is
	// shell-quoted rather than trusted.
	var script strings.Builder
	script.WriteString("for p in")
	for _, p := range candidates {
		script.WriteString(" " + shellQuote(p))
	}
	script.WriteString(`; do printf '%s\t%s\n' "$p" "$(readlink -f "$p" 2>/dev/null)"; done`)
	// Run through sh -c so that --sudo elevates the loop as one command rather
	// than prefixing only its first word.
	cmd, err := conn.RunCommand("sh -c " + shellQuote(script.String()))
	if err != nil || cmd.ExitStatus != 0 {
		return real
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return real
	}
	return parseReadlinkOutput(string(data))
}

// parseReadlinkOutput reads the "<path>\t<resolved>" lines the readlink loop
// prints. An empty resolution (a dangling link, or no readlink -f) is skipped.
func parseReadlinkOutput(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		p, r, ok := strings.Cut(line, "\t")
		if !ok || p == "" || !strings.HasPrefix(r, "/") {
			continue
		}
		res[p] = r
	}
	return res
}

// resolveSymlinks is filepath.EvalSymlinks over a connection's filesystem: it
// follows links in every path component, not just the last, resolving a
// relative target against the directory that holds the link.
func resolveSymlinks(lr afero.LinkReader, p string) (string, error) {
	resolved := "/"
	rest := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
	hops := 0
	for len(rest) > 0 {
		elem := rest[0]
		rest = rest[1:]
		if elem == "" || elem == "." {
			continue
		}
		if elem == ".." {
			resolved = path.Dir(resolved)
			continue
		}
		next := path.Join(resolved, elem)
		target, err := lr.ReadlinkIfPossible(next)
		if err != nil {
			// Not a link (or not readable as one): keep it as it is.
			resolved = next
			continue
		}
		hops++
		if hops > maxSymlinkHops {
			return "", fmt.Errorf("too many levels of symbolic links resolving %s", p)
		}
		if strings.HasPrefix(target, "/") {
			resolved = "/"
		}
		rest = append(strings.Split(strings.TrimPrefix(target, "/"), "/"), rest...)
	}
	return resolved, nil
}

// dedupeByRealPath keeps one name per file. Of the names that resolve to the
// same file, a fixed store location (javaTruststoreFiles) wins over a name
// reached through a JVM directory, so a shared store is reported under the
// distribution's own name (/etc/pki/java/cacerts, /etc/ssl/certs/java/cacerts,
// /var/lib/ca-certificates/java-cacerts). Among equals the lexicographically
// smallest is kept, which is stable across scans. The result is sorted so a
// check's output does not shuffle between scans of the same host.
func dedupeByRealPath(candidates []string, real map[string]string) []string {
	keep := map[string]string{}
	for _, p := range candidates {
		key, ok := real[p]
		if !ok {
			key = p
		}
		if cur, ok := keep[key]; !ok || preferTruststoreName(p, cur) {
			keep[key] = p
		}
	}
	out := make([]string, 0, len(keep))
	for _, p := range keep {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// preferTruststoreName reports whether a is the better name than b for the
// same store.
func preferTruststoreName(a, b string) bool {
	aFixed := slices.Contains(javaTruststoreFiles, a)
	bFixed := slices.Contains(javaTruststoreFiles, b)
	if aFixed != bFixed {
		return aFixed
	}
	return a < b
}

func (s *mqlJavaTruststores) list(paths []any) ([]any, error) {
	res := make([]any, 0, len(paths))
	for i := range paths {
		p, ok := paths[i].(string)
		if !ok {
			continue
		}
		raw, err := CreateResource(s.MqlRuntime, "java.keystore", map[string]*llx.RawData{
			"path": llx.StringData(p),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, raw)
	}
	return res, nil
}
