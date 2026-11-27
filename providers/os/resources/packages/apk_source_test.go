// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

var (
	apkTestKeyOnce sync.Once
	apkTestKeys    []*rsa.PrivateKey
)

// apkTestKey returns one of a few RSA keys generated once for the whole test
// run.
func apkTestKey(t testing.TB, i int) *rsa.PrivateKey {
	t.Helper()
	apkTestKeyOnce.Do(func() {
		for range 3 {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			apkTestKeys = append(apkTestKeys, k)
		}
	})
	return apkTestKeys[i]
}

func apkPublicPEM(t testing.TB, k *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// gzipTar writes files as a gzip stream of a tar archive. The signature stream
// of an index, as abuild-sign writes it, has no end-of-archive marker; end
// adds it.
func gzipTar(t testing.TB, files map[string][]byte, order []string, end bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range order {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name])), Typeflag: tar.TypeReg}))
		_, err := tw.Write(files[name])
		require.NoError(t, err)
	}
	if end {
		require.NoError(t, tw.Close())
	} else {
		require.NoError(t, tw.Flush())
	}
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// buildApkIndex writes an APKINDEX.tar.gz the way abuild-sign does: a gzip
// stream with the signature file, then a gzip stream with DESCRIPTION and
// APKINDEX. The signature covers the second stream. keyName "" writes an
// unsigned index.
func buildApkIndex(t testing.TB, text string, signer *rsa.PrivateKey, keyName, alg string) []byte {
	t.Helper()
	first, second := apkIndexStreams(t, text, signer, keyName, alg)
	return append(first, second...)
}

// apkIndexStreams returns the two gzip streams of buildApkIndex; the first is
// nil for an unsigned index.
func apkIndexStreams(t testing.TB, text string, signer *rsa.PrivateKey, keyName, alg string) (first, second []byte) {
	t.Helper()
	second = gzipTar(t, map[string][]byte{"DESCRIPTION": []byte("test"), "APKINDEX": []byte(text)}, []string{"DESCRIPTION", "APKINDEX"}, true)
	if signer == nil {
		return nil, second
	}
	var sig []byte
	var err error
	switch alg {
	case "RSA":
		sum := sha1.Sum(second)
		sig, err = rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA1, sum[:])
	case "RSA256":
		sum := sha256.Sum256(second)
		sig, err = rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, sum[:])
	default:
		t.Fatalf("unknown algorithm %s", alg)
	}
	require.NoError(t, err)
	name := ".SIGN." + alg + "." + keyName
	first = gzipTar(t, map[string][]byte{name: sig}, []string{name}, false)
	return first, second
}

func testdataBytes(t testing.TB, p string) []byte {
	t.Helper()
	data, err := os.ReadFile(path.Join("testdata", p))
	require.NoError(t, err)
	return data
}

// Measured: nginx.org's alpine v3.21 index for aarch64, 2026-11-27, with the
// installed record of nginx 1.30.8-r1 from the alpine:3.21 container that ran
// `apk add nginx` against it. The index is signed with RSA-SHA256 by
// nginx_signing.rsa.pub, a key no package owns.
func TestParseApkIndexMeasuredNginx(t *testing.T) {
	index := testdataBytes(t, "apk/APKINDEX.nginx-alpine-v3.21-aarch64.tar.gz")
	nginxKey := parseApkPublicKey(testdataBytes(t, "apk/nginx_signing.rsa.pub"))
	alpineKey := parseApkPublicKey(testdataBytes(t, "apk/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub"))
	require.NotNil(t, nginxKey)
	require.NotNil(t, alpineKey)
	installed := map[string]struct{}{"nginx": {}}

	db := parseApkDB(bytes.NewReader(testdataBytes(t, "apk/installed-alpine321-sample.txt")), nil)
	var installedSum string
	for _, p := range db.pkgs {
		if p.name == "nginx" {
			installedSum = p.checksum
			assert.Equal(t, "1.30.8-r1", p.version)
		}
	}
	require.NotEmpty(t, installedSum)

	t.Run("verifies against the key the signature names", func(t *testing.T) {
		idx, err := parseApkIndex(index, apkOSKeys{"nginx_signing.rsa.pub": nginxKey}, installed)
		require.NoError(t, err)
		assert.True(t, idx.osSigned, "the RSA-SHA256 signature of the real index verifies")
		var found bool
		for _, e := range idx.byName["nginx"] {
			if e.version == "1.30.8-r1" {
				found = true
				assert.Equal(t, installedSum, e.checksum, "the index lists the build apk installed")
			}
		}
		assert.True(t, found)
	})

	t.Run("a key that is not in the set does not verify", func(t *testing.T) {
		idx, err := parseApkIndex(index, apkOSKeys{"alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub": alpineKey}, installed)
		require.NoError(t, err)
		assert.False(t, idx.osSigned)
	})

	t.Run("the name alone is not enough, the signature must verify", func(t *testing.T) {
		idx, err := parseApkIndex(index, apkOSKeys{"nginx_signing.rsa.pub": alpineKey}, installed)
		require.NoError(t, err)
		assert.False(t, idx.osSigned)
	})

}

// Synthetic: no target served an index whose content was swapped under a valid
// signature. The signature stream of one index in front of the content of
// another must not verify, whichever algorithm signed it.
func TestParseApkIndexSwappedContent(t *testing.T) {
	key := apkTestKey(t, 0)
	installed := map[string]struct{}{"busybox": {}}
	for _, alg := range []string{"RSA", "RSA256"} {
		sigStream, genuine := apkIndexStreams(t, "C:Q1a=\nP:busybox\nV:1\nA:x86_64\n\n", key, "k.rsa.pub", alg)
		_, forged := apkIndexStreams(t, "C:Q1b=\nP:busybox\nV:1\nA:x86_64\n\n", key, "k.rsa.pub", alg)
		keys := apkOSKeys{"k.rsa.pub": &key.PublicKey}

		idx, err := parseApkIndex(append(append([]byte{}, sigStream...), genuine...), keys, installed)
		require.NoError(t, err)
		assert.True(t, idx.osSigned, alg)

		idx, err = parseApkIndex(append(append([]byte{}, sigStream...), forged...), keys, installed)
		require.NoError(t, err)
		assert.False(t, idx.osSigned, alg)
		assert.Equal(t, "Q1b=", idx.byName["busybox"][0].checksum)
	}
}

// Measured: the installed database of alpine:3.21 (apk-tools 2.14.13), the
// records of alpine-keys, busybox and nginx, 2026-11-27.
func TestParseApkDBMeasured(t *testing.T) {
	db := parseApkDB(bytes.NewReader(testdataBytes(t, "apk/installed-alpine321-sample.txt")), map[string]bool{"alpine-keys": true})
	sums := map[string]string{}
	for _, p := range db.pkgs {
		sums[p.name+" "+p.version] = p.checksum
	}
	assert.Equal(t, "Q1sFUVM6x0MU3Jgfd3WBNOFoeX2Rs=", sums["busybox 1.37.0-r14"])
	assert.Equal(t, "Q1xaY9zKtYBN0RTG5cB5u2CAw1auQ=", sums["nginx 1.30.8-r1"])
	assert.Equal(t, "Q1jXcq7km6pzhujtGqKPqvA3lfsd4=", sums["hello-direct 2.0-r0"])

	keys := db.keyFiles["alpine-keys"]
	assert.Contains(t, keys, "/etc/apk/keys/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub")
	assert.Contains(t, keys, "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub")
	assert.NotContains(t, db.keyFiles, "busybox", "only the named packages' files are kept")
}

// Synthetic: records with a missing version, a field with no value and the
// file lines of an unwanted package; no target showed these.
func TestParseApkDBEdgeCases(t *testing.T) {
	text := "P:nover\nC:Q1aaa=\n\n" +
		"C:Q1bbb=\nP:wolfi-keys\nV:1-r15\nA:aarch64\nF:etc/apk/keys\nR:wolfi-signing.rsa.pub\n\n" +
		"P:other\nV:1\nF:etc/apk/keys\nR:evil.pub\n"
	db := parseApkDB(strings.NewReader(text), map[string]bool{"wolfi-keys": true})
	require.Len(t, db.pkgs, 2, "a record without a version is not a package")
	assert.Equal(t, "Q1bbb=", db.pkgs[0].checksum, "the checksum before the name is read")
	assert.Equal(t, []string{"/etc/apk/keys/wolfi-signing.rsa.pub"}, db.keyFiles["wolfi-keys"])
	assert.NotContains(t, db.keyFiles, "other")
}

// Measured: the cached index file names of the alpine, nginx.org, Chainguard
// and BellSoft indexes on aarch64 containers, 2026-11-27. apk-tools 2.14.13 and
// 3.0.x name them APKINDEX.<first four bytes of SHA-1(<url>/<arch>/APKINDEX.tar.gz)>.tar.gz.
func TestApkRepoIndexPathsMeasured(t *testing.T) {
	cases := []struct {
		repo apkRepo
		want string
	}{
		{apkRepo{location: "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"}, "3983ad5a"},
		{apkRepo{location: "https://dl-cdn.alpinelinux.org/alpine/v3.21/community"}, "76499195"},
		{apkRepo{tag: "testing", location: "https://dl-cdn.alpinelinux.org/alpine/edge/testing"}, "9b60f87e"},
		{apkRepo{location: "https://nginx.org/packages/alpine/v3.21/main"}, "83315d16"},
		{apkRepo{location: "https://apk.cgr.dev/chainguard"}, "629d04f5"},
		{apkRepo{location: "https://packages.bell-sw.com/alpaquita/glibc/stream/core"}, "39cde0f7"},
		{apkRepo{location: "https://packages.bell-sw.com/alpaquita/glibc/stream/universe"}, "b17428a3"},
		{apkRepo{location: "https://cdn.alpinelinux.org/edge/community/"}, "978fde86"},
	}
	for _, c := range cases {
		paths := c.repo.indexPaths("aarch64")
		assert.Equal(t, "/var/cache/apk/APKINDEX."+c.want+".tar.gz", paths[0], c.repo.location)
		assert.Equal(t, "/etc/apk/cache/APKINDEX."+c.want+".tar.gz", paths[1], c.repo.location)
	}
}

// Synthetic: a repository that is a directory is read in place, as apk reads
// it; no target used one.
func TestApkRepoIndexPathsLocal(t *testing.T) {
	assert.Equal(t, []string{"/srv/repo/x86_64/APKINDEX.tar.gz"}, apkRepo{location: "/srv/repo"}.indexPaths("x86_64"))
	assert.Equal(t, []string{"/srv/repo/x86_64/APKINDEX.tar.gz"}, apkRepo{location: "file:///srv/repo/"}.indexPaths("x86_64"))
}

// Measured: /etc/apk/repositories of the alpine:3.21 container after adding
// edge/testing with a tag and nginx.org, 2026-11-27. The comment and the
// malformed lines are Synthetic.
func TestParseApkRepositories(t *testing.T) {
	repos := parseApkRepositories([]byte("https://dl-cdn.alpinelinux.org/alpine/v3.21/main\n" +
		"# https://dl-cdn.alpinelinux.org/alpine/v3.21/community\n" +
		"@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing\n" +
		"https://nginx.org/packages/alpine/v3.21/main  # vendor\n" +
		"\n@lonely\nthree fields here\n"))
	assert.Equal(t, []apkRepo{
		{location: "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"},
		{tag: "testing", location: "https://dl-cdn.alpinelinux.org/alpine/edge/testing"},
		{location: "https://nginx.org/packages/alpine/v3.21/main"},
	}, repos)
}

func TestApkRepoName(t *testing.T) {
	assert.Equal(t, "testing", apkRepo{tag: "testing", location: "https://dl-cdn.alpinelinux.org/alpine/edge/testing"}.name())
	assert.Equal(t, "dl-cdn.alpinelinux.org/alpine/v3.21/main", apkRepo{location: "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"}.name())
	assert.Equal(t, "nginx.org/packages/alpine/v3.21/main", apkRepo{location: "https://nginx.org/packages/alpine/v3.21/main/"}.name())
	// Synthetic: credentials in the address are not part of the name
	assert.Equal(t, "repo.example/apk", apkRepo{location: "https://user:secret@repo.example/apk"}.name())
	assert.Equal(t, "/srv/repo", apkRepo{location: "/srv/repo"}.name())
}

func TestApkRepoURL(t *testing.T) {
	assert.Equal(t, "https://nginx.org/packages/alpine/v3.21/main", apkRepoURL(apkRepo{location: "https://nginx.org/packages/alpine/v3.21/main"}))
	// Synthetic: credentials never leave the system
	assert.Equal(t, "https://repo.example/apk", apkRepoURL(apkRepo{location: "https://user:secret@repo.example/apk?token=x"}))
	assert.Empty(t, apkRepoURL(apkRepo{location: "/srv/repo"}), "a directory is not an address")
}

func apkTestPkg(name, version, arch string) Package {
	return Package{Name: name, Version: version, Arch: arch, Format: AlpinePkgFormat}
}

func TestApkSource(t *testing.T) {
	osIdx := &apkIndex{repo: apkRepo{location: "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"}, osSigned: true}
	vendorIdx := &apkIndex{repo: apkRepo{location: "https://nginx.org/packages/alpine/v3.21/main"}}
	e := func(version, sum string, idx *apkIndex) apkIndexEntry {
		return apkIndexEntry{version: version, arch: "aarch64", checksum: sum, index: idx}
	}
	pkg := apkTestPkg("curl", "8.14.1-r3", "aarch64")

	tests := []struct {
		name     string
		entries  []apkIndexEntry
		complete bool
		wantOS   *bool
		wantChan string
	}{
		{"exact build in an OS index", []apkIndexEntry{e("8.14.1-r3", "Q1x", osIdx)}, true, osProvided(true), ChannelOS},
		{"exact build only in a vendor index", []apkIndexEntry{e("8.14.1-r3", "Q1x", vendorIdx)}, true, osProvided(false), ChannelVendorRepository},
		{"the OS index wins over a vendor index that lists the same build", []apkIndexEntry{e("8.14.1-r3", "Q1x", vendorIdx), e("8.14.1-r3", "Q1x", osIdx)}, true, osProvided(true), ChannelOS},
		{"a vendor build with the same version but another checksum is not the OS's", []apkIndexEntry{e("8.14.1-r3", "Q1other", osIdx)}, true, nil, ChannelUnknown},
		{"missed update, name only in OS indexes", []apkIndexEntry{e("8.14.1-r4", "Q1y", osIdx)}, true, osProvided(true), ChannelOS},
		{"missed update, name also in a vendor index", []apkIndexEntry{e("8.14.1-r4", "Q1y", osIdx), e("8.15.0-r0", "Q1z", vendorIdx)}, true, nil, ChannelUnknown},
		{"missed update, name only in a vendor index", []apkIndexEntry{e("8.15.0-r0", "Q1z", vendorIdx)}, true, nil, ChannelUnknown},
		{"in no index with every index read: installed from a file", nil, true, osProvided(false), ChannelDirect},
		{"in no index but a repository has no index: unknown", nil, false, nil, ChannelUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Synthetic: the cases combine records no single target showed together.
			got := apkSource(&pkg, "Q1x", tt.entries, tt.complete)
			assert.Equal(t, tt.wantOS, got.OSProvided)
			assert.Equal(t, tt.wantChan, got.Channel)
		})
	}

	t.Run("repository name and address", func(t *testing.T) {
		got := apkSource(&pkg, "Q1x", []apkIndexEntry{e("8.14.1-r3", "Q1x", vendorIdx)}, true)
		assert.Equal(t, "nginx.org/packages/alpine/v3.21/main", got.Name)
		assert.Equal(t, "https://nginx.org/packages/alpine/v3.21/main", got.URL)
	})

	t.Run("no checksum on either side matches on the version", func(t *testing.T) {
		got := apkSource(&pkg, "", []apkIndexEntry{e("8.14.1-r3", "", osIdx)}, true)
		assert.Equal(t, osProvided(true), got.OSProvided)
	})
}

func apkTestFS(t *testing.T, files map[string][]byte) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	for p, data := range files {
		require.NoError(t, afero.WriteFile(fs, p, data, 0o644))
	}
	return fs
}

func apkIndexName(t *testing.T, location string) string {
	t.Helper()
	return apkRepo{location: location}.indexPaths("aarch64")[0]
}

const apkAlpineKeyName = "alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub"

// The alpine:3.21 image with a vendor repository and a tagged OS repository,
// read through the file system. The installed database and the nginx index are
// Measured (2026-11-27); the OS indexes are built here and signed with a
// generated key placed under a name alpine-keys owns, because Alpine's private
// keys are not available, so the end-to-end result is Synthetic in that part.
func TestApkSourcesEndToEnd(t *testing.T) {
	osKey := apkTestKey(t, 0)
	db := testdataBytes(t, "apk/installed-alpine321-sample.txt")
	mainIndex := buildApkIndex(t, "C:Q1sFUVM6x0MU3Jgfd3WBNOFoeX2Rs=\nP:busybox\nV:1.37.0-r14\nA:aarch64\n\n", osKey, apkAlpineKeyName, "RSA")
	testingIndex := buildApkIndex(t, "C:Q1fFZPvT0BQ9JR4n39djviX4/Ex9A=\nP:neofetch\nV:7.1.0-r3\nA:aarch64\n\n", osKey, apkAlpineKeyName, "RSA")

	files := map[string][]byte{
		"/lib/apk/db/installed":               db,
		"/etc/apk/arch":                       []byte("aarch64\n"),
		apkKeysDir + "/" + apkAlpineKeyName:   apkPublicPEM(t, osKey),
		apkKeysDir + "/nginx_signing.rsa.pub": testdataBytes(t, "apk/nginx_signing.rsa.pub"),
		"/etc/apk/repositories": []byte("https://dl-cdn.alpinelinux.org/alpine/v3.21/main\n" +
			"@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing\n" +
			"https://nginx.org/packages/alpine/v3.21/main\n"),
		apkIndexName(t, "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"):   mainIndex,
		apkIndexName(t, "https://dl-cdn.alpinelinux.org/alpine/edge/testing"): testingIndex,
		apkIndexName(t, "https://nginx.org/packages/alpine/v3.21/main"):       testdataBytes(t, "apk/APKINDEX.nginx-alpine-v3.21-aarch64.tar.gz"),
	}
	pf := &inventory.Platform{Name: "alpine", Arch: "arm64"}
	pkgs := ParseApkDbPackages(pf, bytes.NewReader(db))
	byName := func(srcs []Source) map[string]Source {
		m := map[string]Source{}
		for i := range pkgs {
			m[pkgs[i].Name] = srcs[i]
		}
		return m
	}

	t.Run("every repository has an index", func(t *testing.T) {
		in := readApkIndexes(newLocalSourceFiles(apkTestFS(t, files)), "alpine")
		require.True(t, in.indexes.complete)
		got := byName(apkSources(pkgs, in))

		assert.Equal(t, Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "dl-cdn.alpinelinux.org/alpine/v3.21/main", URL: "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"}, got["busybox"])
		assert.Equal(t, Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "testing", URL: "https://dl-cdn.alpinelinux.org/alpine/edge/testing"}, got["neofetch"])
		assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelVendorRepository, Name: "nginx.org/packages/alpine/v3.21/main", URL: "https://nginx.org/packages/alpine/v3.21/main"}, got["nginx"])
		assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelDirect}, got["hello-direct"], "apk add --allow-untrusted ./hello-direct.apk")
	})

	t.Run("a repository without an index leaves what only it could list unknown", func(t *testing.T) {
		// Measured: an image that never ran apk update has no APKINDEX files.
		cut := map[string][]byte{}
		for p, data := range files {
			if p != apkIndexName(t, "https://dl-cdn.alpinelinux.org/alpine/edge/testing") {
				cut[p] = data
			}
		}
		in := readApkIndexes(newLocalSourceFiles(apkTestFS(t, cut)), "alpine")
		require.False(t, in.indexes.complete)
		got := byName(apkSources(pkgs, in))
		assert.Equal(t, ChannelUnknown, got["neofetch"].Channel, "the testing index is missing")
		assert.Nil(t, got["hello-direct"].OSProvided, "a missing index could list it")
		assert.Equal(t, ChannelOS, got["busybox"].Channel, "the OS index still answers")
	})

	t.Run("no index at all", func(t *testing.T) {
		// Measured: alpine:3.21 and cgr.dev/chainguard/wolfi-base ship without an index.
		bare := map[string][]byte{}
		for p, data := range files {
			if !strings.Contains(p, "APKINDEX") {
				bare[p] = data
			}
		}
		in := readApkIndexes(newLocalSourceFiles(apkTestFS(t, bare)), "alpine")
		for _, s := range apkSources(pkgs, in) {
			assert.Nil(t, s.OSProvided)
			assert.Equal(t, ChannelUnknown, s.Channel)
		}
	})

	t.Run("a platform without a key package is unknown", func(t *testing.T) {
		// Synthetic: postmarketOS and the rest have no entry; none was read off an image.
		in := readApkIndexes(newLocalSourceFiles(apkTestFS(t, files)), "postmarketos")
		for _, s := range apkSources(pkgs, in) {
			assert.Nil(t, s.OSProvided)
		}
	})

	t.Run("an index signed by a key alpine-keys does not own is the vendor's", func(t *testing.T) {
		// Synthetic: an administrator re-signs a mirror of Alpine's main repository
		// with their own key and adds it to /etc/apk/keys.
		own := map[string][]byte{}
		for p, data := range files {
			own[p] = data
		}
		mine := apkTestKey(t, 1)
		own[apkKeysDir+"/corp-mirror.rsa.pub"] = apkPublicPEM(t, mine)
		own[apkIndexName(t, "https://dl-cdn.alpinelinux.org/alpine/v3.21/main")] = buildApkIndex(t, "C:Q1sFUVM6x0MU3Jgfd3WBNOFoeX2Rs=\nP:busybox\nV:1.37.0-r14\nA:aarch64\n\n", mine, "corp-mirror.rsa.pub", "RSA256")
		in := readApkIndexes(newLocalSourceFiles(apkTestFS(t, own)), "alpine")
		got := byName(apkSources(pkgs, in))
		assert.Equal(t, osProvided(false), got["busybox"].OSProvided)
		assert.Equal(t, ChannelVendorRepository, got["busybox"].Channel)
	})
}

// Measured: cgr.dev/chainguard/wolfi-base (2026-11-27) carries the three
// chainguard-<64 hex>.rsa.pub keys, which no package owns, and wolfi-keys owns
// wolfi-signing.rsa.pub, which does not sign the index of apk.cgr.dev. The key
// material is Synthetic.
func TestApkSourcesWolfiKeyFiles(t *testing.T) {
	key := apkTestKey(t, 0)
	keyName := "chainguard-717fef45988854d7bfe4378796221d1a777fd1cc2f2ff515a84f4668c987c65c.rsa.pub"
	db := "C:Q1aaa=\nP:wolfi-baselayout\nV:20230201-r31\nA:aarch64\n\n" +
		"C:Q1bbb=\nP:wolfi-keys\nV:1-r15\nA:aarch64\nF:etc/apk/keys\nR:wolfi-signing.rsa.pub\n\n"
	index := buildApkIndex(t, "C:Q1aaa=\nP:wolfi-baselayout\nV:20230201-r31\nA:aarch64\n\nC:Q1bbb=\nP:wolfi-keys\nV:1-r15\nA:aarch64\n\n", key, keyName, "RSA256")
	files := map[string][]byte{
		"/usr/lib/apk/db/installed":                       []byte(db),
		"/etc/apk/arch":                                   []byte("aarch64"),
		"/etc/apk/repositories":                           []byte("https://apk.cgr.dev/chainguard\n"),
		apkKeysDir + "/" + keyName:                        apkPublicPEM(t, key),
		apkKeysDir + "/wolfi-signing.rsa.pub":             apkPublicPEM(t, apkTestKey(t, 2)),
		apkIndexName(t, "https://apk.cgr.dev/chainguard"): index,
	}
	pkgs := ParseApkDbPackages(&inventory.Platform{Name: "wolfi", Arch: "arm64"}, strings.NewReader(db))
	require.Len(t, pkgs, 2)

	for _, platform := range []string{"wolfi", "chainguard"} {
		in := readApkIndexes(newLocalSourceFiles(apkTestFS(t, files)), platform)
		for _, s := range apkSources(pkgs, in) {
			assert.Equal(t, osProvided(true), s.OSProvided, platform)
			assert.Equal(t, "apk.cgr.dev/chainguard", s.Name)
		}
	}

	t.Run("a key named like a vendor key but not on a distribution that places them is not trusted", func(t *testing.T) {
		in := readApkIndexes(newLocalSourceFiles(apkTestFS(t, files)), "alpine")
		for _, s := range apkSources(pkgs, in) {
			assert.Nil(t, s.OSProvided, "alpine has no key package installed here, so no key is the OS's")
		}
	})
}

func TestApkChainguardKeyPattern(t *testing.T) {
	// Measured: the key files of wolfi-base, 2026-11-27
	assert.True(t, apkChainguardKey.MatchString("chainguard-717fef45988854d7bfe4378796221d1a777fd1cc2f2ff515a84f4668c987c65c.rsa.pub"))
	// Synthetic: names that are not that scheme
	assert.False(t, apkChainguardKey.MatchString("chainguard.rsa.pub"))
	assert.False(t, apkChainguardKey.MatchString("evil-717fef45988854d7bfe4378796221d1a777fd1cc2f2ff515a84f4668c987c65c.rsa.pub"))
	assert.False(t, apkChainguardKey.MatchString("nginx_signing.rsa.pub"))
}

// Synthetic: the sizes and shapes no target served.
func TestParseApkIndexRejects(t *testing.T) {
	_, err := parseApkIndex([]byte("not gzip"), nil, nil)
	assert.Error(t, err)

	// a signature stream followed by an archive with no APKINDEX
	noIndex := gzipTar(t, map[string][]byte{"DESCRIPTION": []byte("x")}, []string{"DESCRIPTION"}, true)
	_, err = parseApkIndex(noIndex, nil, nil)
	assert.Error(t, err)

	// an unsigned index parses and is not the operating system's
	idx, err := parseApkIndex(buildApkIndex(t, "C:Q1a=\nP:foo\nV:1\nA:x86_64\n\n", nil, "", ""), apkOSKeys{}, map[string]struct{}{"foo": {}})
	require.NoError(t, err)
	assert.False(t, idx.osSigned)
	require.Len(t, idx.byName["foo"], 1)

	// only installed names are kept
	idx, err = parseApkIndex(buildApkIndex(t, "P:foo\nV:1\n\nP:bar\nV:2\n", nil, "", ""), apkOSKeys{}, map[string]struct{}{"foo": {}})
	require.NoError(t, err)
	assert.Len(t, idx.byName, 1)
}
