// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// Channels a package can arrive through (ADR 049). ChannelOS is the channel of
// every package the operating system vendor provides; the rest are third-party
// channels.
const (
	ChannelOS               = "os"
	ChannelVendorRepository = "vendor-repository"
	ChannelAppStore         = "app-store"
	ChannelHomebrew         = "homebrew"
	ChannelInstaller        = "installer"
	ChannelDirect           = "direct"
	ChannelSnap             = "snap"
	ChannelFlatpak          = "flatpak"
	ChannelChocolatey       = "chocolatey"
	ChannelUnknown          = "unknown"
)

// Source is where an installed package came from: whether the operating system
// vendor provides it, and the channel, repository and address it arrived
// through.
type Source struct {
	// OSProvided is nil when nothing on the system answers. It is never
	// guessed: a nil value means the records needed to decide are missing.
	OSProvided *bool
	Channel    string
	Name       string
	URL        string
}

// SourceResolver is implemented by package managers that can tell where their
// packages came from.
//
// Sources is called at most once per package list, and only when a query reads
// osProvided or source, because answering can mean reading the repository
// indexes or the transaction history. pkgs is the list List returned; the
// result holds one Source per package, in the same order.
type SourceResolver interface {
	Sources(pkgs []Package) ([]Source, error)
}

func osProvided(v bool) *bool { return &v }

// unknownSource is the answer when no record on the system says anything.
func unknownSource() Source { return Source{Channel: ChannelUnknown} }

// DefaultSource is the source of a package whose manager has no SourceResolver,
// or whose resolver could not answer. It covers what the format alone decides:
// a snap, a flatpak and a Chocolatey package each have one channel, and a
// Windows hotfix is an operating system update by definition.
func DefaultSource(pkg Package) Source {
	if pkg.source != nil {
		return *pkg.source
	}
	switch pkg.Format {
	case SnapPkgFormat:
		return Source{Channel: ChannelSnap, Name: pkg.Name}
	case FlatpakPkgFormat:
		// origin is the remote the flatpak was installed from, e.g. "flathub"
		return Source{Channel: ChannelFlatpak, Name: pkg.Origin}
	case ChocolateyPkgFormat:
		return Source{OSProvided: osProvided(false), Channel: ChannelChocolatey, Name: pkg.Name}
	case HomebrewPkgFormat:
		return Source{OSProvided: osProvided(false), Channel: ChannelHomebrew, Name: pkg.Name}
	case WindowsHotfixPkgFormat:
		return Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "Windows Update"}
	}
	return unknownSource()
}

// sanitizeRepoURL keeps only the scheme, host and path of a repository address.
// Private repositories put credentials in the address, as user information
// ("https://user:token@repo.example/") or in the query string
// ("?token=..."); neither may leave the system. A value that does not parse as
// a URL with a host is dropped rather than reported half-cleaned.
func sanitizeRepoURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	clean := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return strings.TrimSuffix(clean.String(), "/")
}

// isNetworkConnection reports a connection where every file read is a round
// trip to another machine and running one command is cheaper than reading many
// files: SSH, and Vagrant, which connects over SSH.
func isNetworkConnection(conn shared.Connection) bool {
	if conn == nil || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return false
	}
	t := conn.Type()
	return t == shared.Type_SSH || t == shared.Type_Vagrant
}

// sourceFiles reads the small files source resolution needs: release files, key
// files, sources lists. Over SSH every file is a round trip, and a Debian
// host's archive keyring alone is twenty files, so prefetch reads a set of
// them with one command. Everywhere else, and for whatever prefetch did not
// return, it reads the file system.
type sourceFiles struct {
	fs     afero.Fs
	conn   shared.Connection
	remote bool
	cache  map[string][]byte
}

func newSourceFiles(conn shared.Connection) *sourceFiles {
	return &sourceFiles{fs: conn.FileSystem(), conn: conn, remote: isNetworkConnection(conn), cache: map[string][]byte{}}
}

// newLocalSourceFiles reads only the file system.
func newLocalSourceFiles(fs afero.Fs) *sourceFiles {
	return &sourceFiles{fs: fs, cache: map[string][]byte{}}
}

// sourceFilesMaxBatch caps how many paths one prefetch command names, to stay
// well inside the command-line limits of the shells it runs in.
const sourceFilesMaxBatch = 200

// prefetch reads the paths in one command per batch on a network connection,
// and does nothing elsewhere. Each file is printed behind a "#" line as
// base64, so binary keyrings survive the trip.
func (f *sourceFiles) prefetch(paths []string) {
	if !f.remote {
		return
	}
	var todo []string
	for _, p := range paths {
		if _, ok := f.cache[p]; !ok {
			todo = append(todo, p)
		}
	}
	for len(todo) > 0 {
		n := min(len(todo), sourceFilesMaxBatch)
		f.prefetchBatch(todo[:n])
		todo = todo[n:]
	}
}

func (f *sourceFiles) prefetchBatch(paths []string) {
	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = shellQuote(p)
	}
	cmd, err := f.conn.RunCommand(`for f in ` + strings.Join(quoted, " ") +
		`; do [ -f "$f" ] && [ -r "$f" ] || continue; printf '#%s\n' "$f"; base64 < "$f" | tr -d '\n'; printf '\n'; done`)
	if err != nil || cmd.ExitStatus != 0 {
		return
	}
	scanner := bufio.NewScanner(cmd.Stdout)
	// a key file is a few kilobytes and a release file a few hundred; the
	// largest Ubuntu release files are under 300 KB before encoding
	scanner.Buffer(nil, 16*1024*1024)
	current := ""
	for scanner.Scan() {
		line := scanner.Text()
		if p, ok := strings.CutPrefix(line, "#"); ok {
			current = p
			continue
		}
		if current == "" {
			continue
		}
		if data, err := base64.StdEncoding.DecodeString(line); err == nil {
			f.cache[current] = data
		}
		current = ""
	}
}

// read returns a file's content, from what prefetch fetched or from the file
// system.
func (f *sourceFiles) read(p string) ([]byte, error) {
	if data, ok := f.cache[p]; ok {
		return data, nil
	}
	return afero.ReadFile(f.fs, p)
}
