// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/utils/syncx"
)

// freebsdConfLatest is usr.sbin/pkg/FreeBSD.conf.latest from freebsd-src,
// installed as /etc/pkg/FreeBSD.conf. The comment header is part of the
// fixture on purpose: it spells out two repository blocks inside shell
// examples, so a parser that does not strip comments finds five
// repositories where pkg finds three.
const freebsdConfLatest = `#
# To disable a repository, instead of modifying or removing this file,
# create or edit /usr/local/etc/pkg/repos/FreeBSD.conf, e.g.:
#
#   mkdir -p /usr/local/etc/pkg/repos
#   echo "FreeBSD-ports: { enabled: no }" >> /usr/local/etc/pkg/repos/FreeBSD.conf
#   echo "FreeBSD-ports-kmods: { enabled: no }" >> /usr/local/etc/pkg/repos/FreeBSD.conf
#
# Note that the FreeBSD-base repository is disabled by default.
#

FreeBSD-ports: {
  url: "pkg+https://pkg.FreeBSD.org/${ABI}/latest",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
FreeBSD-ports-kmods: {
  url: "pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
FreeBSD-base: {
  url: "pkg+https://pkg.FreeBSD.org/${ABI}/base_latest",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: no
}
`

// mergePkgFiles parses and merges a sequence of configuration file
// contents in the order pkg would read them.
func mergePkgFiles(contents ...string) (map[string]*pkgRepo, []string) {
	repos := map[string]*pkgRepo{}
	order := []string{}
	for _, c := range contents {
		for _, block := range parsePkgRepoBlocks(c) {
			mergePkgRepoBlock(repos, &order, block, nil)
		}
	}
	return repos, order
}

func TestParsePkgRepoBlocks_FreeBSDDefault(t *testing.T) {
	blocks := parsePkgRepoBlocks(freebsdConfLatest)
	require.Len(t, blocks, 3)

	assert.Equal(t, "FreeBSD-ports", blocks[0].Name)
	assert.Equal(t, "FreeBSD-ports-kmods", blocks[1].Name)
	assert.Equal(t, "FreeBSD-base", blocks[2].Name)

	assert.Equal(t, "pkg+https://pkg.FreeBSD.org/${ABI}/latest", blocks[0].Keys["url"].Raw)
	assert.Equal(t, "srv", blocks[0].Keys["mirror_type"].Raw)
	assert.Equal(t, "fingerprints", blocks[0].Keys["signature_type"].Raw)
	assert.Equal(t, "/usr/share/keys/pkg", blocks[0].Keys["fingerprints"].Raw)
	assert.Equal(t, "yes", blocks[0].Keys["enabled"].Raw)
	assert.Equal(t, "no", blocks[2].Keys["enabled"].Raw)
}

func TestMergePkgRepos_FreeBSDDefault(t *testing.T) {
	repos, order := mergePkgFiles(freebsdConfLatest)
	require.Equal(t, []string{"FreeBSD-ports", "FreeBSD-ports-kmods", "FreeBSD-base"}, order)

	ports := repos["FreeBSD-ports"]
	require.NotNil(t, ports)
	assert.True(t, ports.Enabled)
	assert.Equal(t, "fingerprints", ports.SignatureType)
	assert.Equal(t, "srv", ports.MirrorType)
	assert.Equal(t, "/usr/share/keys/pkg", ports.Fingerprints)
	assert.Empty(t, ports.Pubkey)

	// FreeBSD ships the base repository turned off
	assert.False(t, repos["FreeBSD-base"].Enabled)
}

func TestMergePkgRepos_EnabledOverrideKeepsTrust(t *testing.T) {
	// the override FreeBSD.conf's own header tells operators to write
	override := `FreeBSD-ports: { enabled: no }`

	repos, order := mergePkgFiles(freebsdConfLatest, override)
	require.Len(t, order, 3)

	ports := repos["FreeBSD-ports"]
	require.NotNil(t, ports)
	assert.False(t, ports.Enabled)

	// every key the override leaves out is inherited from the base
	// definition rather than reset
	assert.Equal(t, "pkg+https://pkg.FreeBSD.org/${ABI}/latest", ports.URL)
	assert.Equal(t, "fingerprints", ports.SignatureType)
	assert.Equal(t, "/usr/share/keys/pkg", ports.Fingerprints)
	assert.Equal(t, "srv", ports.MirrorType)
}

func TestMergePkgRepos_PriorityResetsOnOverride(t *testing.T) {
	base := `Custom: { url: "https://example.com/pkg", priority: 10 }`

	repos, _ := mergePkgFiles(base)
	require.Equal(t, int64(10), repos["Custom"].Priority)

	// priority is the one key libpkg does not inherit: add_repo starts every
	// block at zero and assigns it unconditionally, so an override that does
	// not restate priority drops the repository back to 0 while leaving the
	// other keys alone
	repos, _ = mergePkgFiles(base, `Custom: { enabled: yes }`)
	assert.Equal(t, int64(0), repos["Custom"].Priority)
	assert.Equal(t, "https://example.com/pkg", repos["Custom"].URL)
}

func TestMergePkgRepos_OverrideWithoutUrlOrBaseIsDiscarded(t *testing.T) {
	// nothing declared this repository with a url first, so pkg drops the
	// block rather than creating a repository it cannot fetch from
	repos, order := mergePkgFiles(`Typo-ports: { enabled: no }`)
	assert.Empty(t, order)
	assert.Empty(t, repos)
}

func TestMergePkgRepos_InvalidSignatureTypeDropsBlock(t *testing.T) {
	// `fingerprint` for `fingerprints`: libpkg rejects the whole block
	repos, order := mergePkgFiles(`Custom: { url: "https://example.com/pkg", signature_type: "fingerprint" }`)
	assert.Empty(t, order)
	assert.Empty(t, repos)

	// and where the repository already exists it keeps the definition it had
	base := `Custom: { url: "https://example.com/pkg", signature_type: "pubkey", pubkey: "/k.pem" }`
	repos, _ = mergePkgFiles(base, `Custom: { signature_type: "fingerprint" }`)
	assert.Equal(t, "pubkey", repos["Custom"].SignatureType)
	assert.Equal(t, "/k.pem", repos["Custom"].Pubkey)
}

func TestMergePkgRepos_Defaults(t *testing.T) {
	// a repository that sets nothing but a url is unverified: pkg defaults
	// signature_type to none, which is exactly the case an audit looks for
	repos, _ := mergePkgFiles(`Custom: { url: "https://example.com/pkg" }`)

	r := repos["Custom"]
	require.NotNil(t, r)
	assert.Equal(t, "none", r.SignatureType)
	assert.Equal(t, "none", r.MirrorType)
	assert.True(t, r.Enabled)
	assert.Equal(t, int64(0), r.Priority)
	assert.Empty(t, r.Fingerprints)
	assert.Empty(t, r.Pubkey)
}

func TestMergePkgRepos_UnverifiedEnabledRepository(t *testing.T) {
	// the shape the audit turns on: a disabled unverified repository must
	// not condemn a host, an enabled one must
	local := `
Internal: { url: "http://pkg.internal/${ABI}/latest" }
Retired: { url: "http://old.internal/${ABI}/latest", signature_type: none, enabled: no }
`

	repos, order := mergePkgFiles(freebsdConfLatest, local)
	require.Len(t, order, 5)

	unverified := []string{}
	for _, name := range order {
		if r := repos[name]; r.Enabled && r.SignatureType == "none" {
			unverified = append(unverified, name)
		}
	}
	assert.Equal(t, []string{"Internal"}, unverified)
}

func TestParsePkgRepoBlocks_SyntaxVariants(t *testing.T) {
	content := `
# a leading comment
"Quoted-Name" = {
  url = "https://example.com/pkg";  // a trailing comment
  env: { http_proxy: "http://proxy:3128" }   /* a nested object */
  signature_type: pubkey,
  pubkey: /usr/local/etc/ssl/pkg.pem
}
Second: { url: "https://second.example.com/pkg#notacomment", enabled: off }
`

	blocks := parsePkgRepoBlocks(content)
	require.Len(t, blocks, 2)

	assert.Equal(t, "Quoted-Name", blocks[0].Name)
	assert.Equal(t, "https://example.com/pkg", blocks[0].Keys["url"].Raw)
	assert.Equal(t, "pubkey", blocks[0].Keys["signature_type"].Raw)
	assert.Equal(t, "/usr/local/etc/ssl/pkg.pem", blocks[0].Keys["pubkey"].Raw)

	// the nested object is not a scalar and neither it nor its contents may
	// land as one
	_, ok := blocks[0].Keys["env"]
	assert.False(t, ok)
	_, ok = blocks[0].Keys["http_proxy"]
	assert.False(t, ok)

	// a `#` inside a quoted url is part of the url, not the start of a comment
	assert.Equal(t, "https://second.example.com/pkg#notacomment", blocks[1].Keys["url"].Raw)
	assert.Equal(t, "off", blocks[1].Keys["enabled"].Raw)
}

func TestParsePkgBlockKeys_Quoting(t *testing.T) {
	keys := parsePkgBlockKeys(`priority: 10, mirror_type: "srv"`)

	// pkg rejects a quoted priority because UCL reads it as a string
	assert.False(t, keys["priority"].Quoted)
	assert.Equal(t, "10", keys["priority"].Raw)

	assert.True(t, keys["mirror_type"].Quoted)
	assert.Equal(t, "srv", keys["mirror_type"].Raw)
}

func TestStripPkgComments_BlockComments(t *testing.T) {
	// a block comment becomes one space, so it separates the tokens it sat
	// between rather than joining them. The character right after `*/` must
	// survive and the one before `/*` must not be swallowed: an off-by-one
	// either way leaks a stray `/` into a value or welds two tokens together,
	// and both parse into something plausible
	assert.Equal(t, "a   b", stripPkgComments("a /* x */ b"))
	assert.Equal(t, "a b c", stripPkgComments("a b/**/c"))

	// an unterminated block comment runs to the end of the file
	assert.Equal(t, "a  ", stripPkgComments("a /* x"))

	// `/*` inside a quoted string is part of the value
	assert.Equal(t, `url: "http://x/*/y"`, stripPkgComments(`url: "http://x/*/y"`))

	// a block comment ending the file leaves nothing dangling
	assert.Equal(t, "a  ", stripPkgComments("a /* x */"))
}

func TestParsePkgBlockKeys_CaseInsensitiveKeys(t *testing.T) {
	// libpkg compares keys case-insensitively, so a repeated key is one key
	// and the later spelling wins
	keys := parsePkgBlockKeys(`mirror_type: "srv", MIRROR_TYPE: http`)
	require.Len(t, keys, 1)
	assert.Equal(t, "http", keys["mirror_type"].Raw)
}

func TestMergePkgRepos_QuotedPriorityDropsBlock(t *testing.T) {
	repos, order := mergePkgFiles(`Custom: { url: "https://example.com/pkg", priority: "10" }`)
	assert.Empty(t, order)
	assert.Empty(t, repos)
}

// TestPkgRepos_IgnoresSubdirectories pins the REPOS_DIR walk to the
// directories themselves. files.find counts depth differently per
// connection: the command backend hands it to `find -maxdepth`, where 1 is
// the directory's own entries, and the filesystem backend counts 1 as one
// level below those, so a filesystem scan sees files in subdirectories that
// pkg never opens. A repository defined there is not a repository on the
// host.
func TestPkgRepos_IgnoresSubdirectories(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}

	write("etc/pkg/FreeBSD.conf", freebsdConfLatest)
	write("usr/local/etc/pkg/repos/internal.conf",
		`internal: { url: "https://pkg.example.internal/${ABI}", signature_type: "pubkey", pubkey: "/k.pub" }`)
	write("usr/local/etc/pkg/repos/extra/nested.conf",
		`nested: { url: "https://pkg.example.internal/nested" }`)

	conn, err := fs.NewFileSystemConnectionWithClose(0, &inventory.Config{
		Options: map[string]string{"path": root},
	}, &inventory.Asset{
		Platform: &inventory.Platform{Name: "freebsd", Family: []string{"unix", "bsd"}},
	}, nil)
	require.NoError(t, err)

	pkg := &mqlPkg{MqlRuntime: &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}}

	repos, err := pkg.repos()
	require.NoError(t, err)

	names := []string{}
	for _, r := range repos {
		names = append(names, r.(*mqlPkgRepo).Name.Data)
	}
	assert.Equal(t, []string{"FreeBSD-ports", "FreeBSD-ports-kmods", "FreeBSD-base", "internal"}, names)
}

func TestIsPkgConfigFile(t *testing.T) {
	assert.True(t, isPkgConfigFile("/etc/pkg/FreeBSD.conf", "/etc/pkg"))
	assert.True(t, isPkgConfigFile("/usr/local/etc/pkg/repos/custom.conf", "/usr/local/etc/pkg/repos"))
	assert.True(t, isPkgConfigFile("/etc/pkg/FreeBSD.conf", "/etc/pkg/"))

	// pkg reads each REPOS_DIR entry with scandir and never descends
	assert.False(t, isPkgConfigFile("/usr/local/etc/pkg/repos/extra/nested.conf", "/usr/local/etc/pkg/repos"))
	assert.False(t, isPkgConfigFile("/etc/pkg/disabled/FreeBSD.conf", "/etc/pkg"))

	// pkg requires a name longer than ".conf" itself
	assert.False(t, isPkgConfigFile("/etc/pkg/.conf", "/etc/pkg"))
	// dotfiles are skipped, so an editor's backup never becomes a repository
	assert.False(t, isPkgConfigFile("/usr/local/etc/pkg/repos/.FreeBSD.conf", "/usr/local/etc/pkg/repos"))
	assert.False(t, isPkgConfigFile("/etc/pkg/FreeBSD.conf.bak", "/etc/pkg"))
	assert.False(t, isPkgConfigFile("/etc/pkg/README", "/etc/pkg"))
}

func TestPkgBool(t *testing.T) {
	for _, v := range []string{"yes", "true", "on", "1", "YES", "True"} {
		assert.True(t, pkgBool(v), v)
	}
	for _, v := range []string{"no", "false", "off", "0", "NO", "False", ""} {
		assert.False(t, pkgBool(v), v)
	}
}

func TestParsePkgRepoBlocks_Malformed(t *testing.T) {
	// an unterminated block takes the rest of the file with it, but must not
	// hang or panic
	blocks := parsePkgRepoBlocks(`Good: { url: "https://a.example.com/pkg" }
Bad: { url: "https://b.example.com/pkg"
`)
	require.Len(t, blocks, 1)
	assert.Equal(t, "Good", blocks[0].Name)

	assert.Empty(t, parsePkgRepoBlocks(""))
	assert.Empty(t, parsePkgRepoBlocks("# only a comment\n"))
	assert.Empty(t, parsePkgRepoBlocks("}}}{{{"))
}
