// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/klauspost/compress/zstd"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// Measured: the mirror list of archlinux:latest, 2026-11-27 (linux/amd64)
	archMirrorlist = "# Arch Linux repository mirrorlist\n\nServer = https://fastly.mirror.pkgbuild.com/$repo/os/$arch\nServer = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n"
	// Measured: the head of manjarolinux/base's mirror list, 2026-11-27
	manjaroMirrorlist = "Server = https://mirrors.ocf.berkeley.edu/manjaro/stable/$repo/$arch\nServer = https://nocix.mm.fcix.net/manjaro/stable/$repo/$arch\n"
)

func readPacmanTestdata(t testing.TB, name string) []byte {
	t.Helper()
	return testdataBytes(t, "pacman/"+name)
}

func TestParsePacmanConfMeasured(t *testing.T) {
	read := func(mirrorlist string) func(string) []byte {
		return func(p string) []byte {
			if p == "/etc/pacman.d/mirrorlist" {
				return []byte(mirrorlist)
			}
			return nil
		}
	}

	t.Run("archlinux:latest", func(t *testing.T) {
		cfg := parsePacmanConf(readPacmanTestdata(t, "pacman.conf-archlinux-latest.txt"), read(archMirrorlist))
		assert.Equal(t, pacmanDefaultDBPath, cfg.dbPath)
		require.Len(t, cfg.repos, 2, "core and extra; the commented multilib and testing repositories are not read")
		assert.Equal(t, "core", cfg.repos[0].name)
		assert.Equal(t, "extra", cfg.repos[1].name)
		assert.Equal(t, "https://fastly.mirror.pkgbuild.com/$repo/os/$arch", cfg.repos[0].server, "the first Server of the included mirror list")
		assert.Equal(t, "https://fastly.mirror.pkgbuild.com/core/os/x86_64", cfg.repos[0].url("x86_64"))
	})

	t.Run("manjarolinux/base", func(t *testing.T) {
		cfg := parsePacmanConf(readPacmanTestdata(t, "pacman.conf-manjaro-base.txt"), read(manjaroMirrorlist))
		require.Len(t, cfg.repos, 2)
		assert.Equal(t, "https://mirrors.ocf.berkeley.edu/manjaro/stable/extra/x86_64", cfg.repos[1].url("x86_64"))
	})
}

// Synthetic: configurations no target showed.
func TestParsePacmanConfEdgeCases(t *testing.T) {
	conf := `# comment
[options]
DBPath = /srv/pacman
SigLevel = Required

[vendor]
SigLevel = Optional TrustAll
Server = https://user:secret@repo.example/$repo/$arch?token=abc
Server = https://mirror2.example/$repo

[outside]
Include = /home/someone/mirrors

[custom]
Include = /etc/pacman.d/custom.list # trailing comment

[nothing]
`
	read := func(p string) []byte {
		switch p {
		case "/etc/pacman.d/custom.list":
			return []byte("# header\nServer = https://custom.example/pkgs/$repo\n")
		case "/home/someone/mirrors":
			t.Errorf("a mirror list outside /etc must not be read")
		}
		return nil
	}
	cfg := parsePacmanConf([]byte(conf), read)
	assert.Equal(t, "/srv/pacman/", cfg.dbPath)
	require.Len(t, cfg.repos, 4)
	assert.Equal(t, "vendor", cfg.repos[0].name)
	assert.Equal(t, "https://repo.example/vendor/x86_64", cfg.repos[0].url("x86_64"), "credentials and the query are removed")
	assert.Empty(t, cfg.repos[1].server, "outside /etc")
	assert.Equal(t, "https://custom.example/pkgs/custom", cfg.repos[2].url("x86_64"))
	assert.Equal(t, "nothing", cfg.repos[3].name)
	assert.Empty(t, cfg.repos[3].url("x86_64"))
}

// Measured: the file list of archlinux-keyring 20260909-1 from archlinux:latest.
func TestPacmanOwnedFilesMeasured(t *testing.T) {
	files := pacmanOwnedFiles(readPacmanTestdata(t, "local-files-archlinux-keyring-20260909-1.txt"))
	assert.Contains(t, files, "usr/share/pacman/keyrings/archlinux.gpg")
	assert.Contains(t, files, "usr/share/pacman/keyrings/archlinux-trusted")
	assert.NotContains(t, files, "%FILES%")
}

func pacmanDescField(t testing.TB, desc []byte, key string) string {
	t.Helper()
	return parsePacmanDescSections(bytes.NewReader(desc))[key]
}

// Measured: the PGPSIG of acl 2.4.0-1 from the core database of archlinux:latest
// (signed by an Arch packager's subkey, 6D42BDD116E0068F) and of amd-ucode
// 20260110-1 from the core database of manjarolinux/base (signed by a Manjaro
// packager's key, 150C200743ED46D8), both 2026-11-27. The keyrings hold only these
// two keys, exported from archlinux.gpg and manjaro.gpg with their own
// self-signatures.
func TestPacmanSignedByMeasured(t *testing.T) {
	archKeys, manjaroKeys := openPGPKeys{}, openPGPKeys{}
	archKeys.addKeyring(readPacmanTestdata(t, "archlinux-keyring-packager-key.gpg"))
	manjaroKeys.addKeyring(readPacmanTestdata(t, "manjaro-keyring-packager-key.gpg"))
	require.NotEmpty(t, archKeys)
	require.NotEmpty(t, manjaroKeys)

	aclSig := pacmanDescField(t, readPacmanTestdata(t, "sync-desc-core-acl-2.4.0-1.txt"), "%PGPSIG%")
	ucodeSig := pacmanDescField(t, readPacmanTestdata(t, "sync-desc-manjaro-core-amd-ucode-20260110-1.txt"), "%PGPSIG%")
	require.NotEmpty(t, aclSig)
	require.NotEmpty(t, ucodeSig)

	assert.True(t, pacmanSignedBy(aclSig, archKeys))
	assert.False(t, pacmanSignedBy(aclSig, manjaroKeys), "Arch's packager is not a Manjaro key")
	assert.True(t, pacmanSignedBy(ucodeSig, manjaroKeys))
	assert.False(t, pacmanSignedBy(ucodeSig, archKeys))

	// Synthetic: a record with no signature, damaged base64, and a keyring with no keys
	assert.False(t, pacmanSignedBy("", archKeys))
	assert.False(t, pacmanSignedBy("!!!not base64!!!", archKeys))
	assert.False(t, pacmanSignedBy(base64.StdEncoding.EncodeToString([]byte("garbage")), archKeys))
	assert.False(t, pacmanSignedBy(aclSig, openPGPKeys{}))
}

// Measured: the local database records of acl 2.4.0-1 from archlinux:latest
// (installed from core, %VALIDATION% pgp) and of hello-direct 2.0-1 installed
// with `pacman -U` from an unsigned file (%VALIDATION% none), 2026-11-27.
func TestPacmanValidationMeasured(t *testing.T) {
	pf := &inventory.Platform{Name: "arch", Arch: "x86_64"}
	acl := packageFromPacmanFields(pf, parsePacmanDescSections(bytes.NewReader(readPacmanTestdata(t, "local-desc-acl-2.4.0-1.txt"))))
	require.NotNil(t, acl)
	assert.Equal(t, "pgp", acl.pacmanValidation)
	assert.Equal(t, "1782738989", acl.pacmanBuildDate)
	assert.Equal(t, acl.pacmanBuildDate, pacmanDescField(t, readPacmanTestdata(t, "sync-desc-core-acl-2.4.0-1.txt"), "%BUILDDATE%"),
		"the sync database lists the same build date as the installed record")
	direct := packageFromPacmanFields(pf, parsePacmanDescSections(bytes.NewReader(readPacmanTestdata(t, "local-desc-hello-direct-2.0-1.txt"))))
	require.NotNil(t, direct)
	assert.Equal(t, "none", direct.pacmanValidation)
	assert.Equal(t, "any", direct.Arch)
}

// syncDB writes a sync database: a tar archive with one "<name>-<version>/desc"
// record per package, compressed by compress.
func syncDB(t testing.TB, descs map[string]string, compress string) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for dir, desc := range descs {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: dir + "/", Typeflag: tar.TypeDir, Mode: 0o755}))
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: dir + "/desc", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(desc))}))
		_, err := tw.Write([]byte(desc))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	switch compress {
	case "gz":
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		_, err := gz.Write(raw.Bytes())
		require.NoError(t, err)
		require.NoError(t, gz.Close())
		return out.Bytes()
	case "zst":
		var out bytes.Buffer
		zw, err := zstd.NewWriter(&out)
		require.NoError(t, err)
		_, err = zw.Write(raw.Bytes())
		require.NoError(t, err)
		require.NoError(t, zw.Close())
		return out.Bytes()
	}
	return raw.Bytes()
}

func syntheticDesc(name, version, arch, pgpsig string) string {
	d := "%NAME%\n" + name + "\n\n%VERSION%\n" + version + "\n\n%ARCH%\n" + arch + "\n\n"
	if pgpsig != "" {
		d += "%PGPSIG%\n" + pgpsig + "\n\n"
	}
	return d
}

func TestReadPacmanSyncDB(t *testing.T) {
	archKeys := openPGPKeys{}
	archKeys.addKeyring(readPacmanTestdata(t, "archlinux-keyring-packager-key.gpg"))
	acl := string(readPacmanTestdata(t, "sync-desc-core-acl-2.4.0-1.txt"))
	// Synthetic: an unsigned record and one for a package that is not installed
	descs := map[string]string{
		"acl-2.4.0-1":        acl,
		"hello-vendor-1.0-1": syntheticDesc("hello-vendor", "1.0-1", "any", ""),
		"zzz-1-1":            syntheticDesc("zzz", "1-1", "any", ""),
	}
	installed := map[string]struct{}{"acl": {}, "hello-vendor": {}}
	db := &pacmanRepoDB{pacmanRepo: pacmanRepo{name: "core"}, url: "https://m.example/core"}

	for _, compress := range []string{"gz", "zst", ""} {
		t.Run("compression "+compress, func(t *testing.T) {
			got, err := readPacmanSyncDB(syncDB(t, descs, compress), installed, archKeys, db)
			require.NoError(t, err)
			require.Len(t, got, 2, "only installed names are kept")
			require.Len(t, got["acl"], 1)
			assert.Equal(t, "2.4.0-1", got["acl"][0].version)
			assert.Equal(t, "x86_64", got["acl"][0].arch)
			assert.True(t, got["acl"][0].osSigned, "Measured: acl's real signature is from the Arch keyring")
			assert.False(t, got["hello-vendor"][0].osSigned, "no signature is not the operating system's")
			assert.Same(t, db, got["acl"][0].repo)
		})
	}

	t.Run("a database that is not an archive", func(t *testing.T) {
		_, err := readPacmanSyncDB([]byte{0x1f, 0x8b, 0x00}, installed, archKeys, db)
		assert.Error(t, err)
	})

	t.Run("a format that is not known is not an empty database", func(t *testing.T) {
		// Synthetic: repo-add also writes .lz4, .lz, .lrz, .lzo and .Z; no image used one.
		_, err := readPacmanSyncDB(append([]byte{0x04, 0x22, 0x4d, 0x18}, bytes.Repeat([]byte{1}, 600)...), installed, archKeys, db)
		assert.Error(t, err)
	})

	t.Run("an archive cut short", func(t *testing.T) {
		// Synthetic: a download that stopped early
		data := syncDB(t, descs, "")
		_, err := readPacmanSyncDB(data[:len(data)/2+3], installed, archKeys, db)
		assert.Error(t, err)
		data = syncDB(t, descs, "gz")
		_, err = readPacmanSyncDB(data[:len(data)-12], installed, archKeys, db)
		assert.Error(t, err)
	})
}

func pacmanTestPkg(name, version, arch, validation string) Package {
	return Package{Name: name, Version: version, Arch: arch, Format: PacmanPkgFormat, pacmanValidation: validation}
}

func TestPacmanSource(t *testing.T) {
	core := &pacmanRepoDB{pacmanRepo: pacmanRepo{name: "core"}, url: "https://m.example/core/os/x86_64"}
	vendor := &pacmanRepoDB{pacmanRepo: pacmanRepo{name: "vendor"}, url: "https://vendor.example/arch"}
	e := func(version string, signed bool, repo *pacmanRepoDB) pacmanSyncEntry {
		return pacmanSyncEntry{version: version, arch: "x86_64", osSigned: signed, repo: repo}
	}
	tests := []struct {
		name       string
		pkg        Package
		entries    []pacmanSyncEntry
		complete   bool
		wantOS     *bool
		wantChan   string
		wantSource string
	}{
		{"installed version in an OS-signed repository", pacmanTestPkg("acl", "2.4.0-1", "x86_64", "pgp"), []pacmanSyncEntry{e("2.4.0-1", true, core)}, true, osProvided(true), ChannelOS, "core"},
		{"installed version in a repository with another key", pacmanTestPkg("hello", "1.0-1", "x86_64", "sha256"), []pacmanSyncEntry{e("1.0-1", false, vendor)}, true, osProvided(false), ChannelVendorRepository, "vendor"},
		{"the OS repository wins when both list the version", pacmanTestPkg("acl", "2.4.0-1", "x86_64", "pgp"), []pacmanSyncEntry{e("2.4.0-1", false, vendor), e("2.4.0-1", true, core)}, true, osProvided(true), ChannelOS, "core"},
		{"in no sync database, every database read: pacman -Qm", pacmanTestPkg("hello-direct", "2.0-1", "any", "none"), nil, true, osProvided(false), ChannelDirect, ""},
		{"in no sync database, one repository has no database", pacmanTestPkg("hello-direct", "2.0-1", "any", "none"), nil, false, nil, ChannelUnknown, ""},
		{"missed update, name only in OS-signed repositories", pacmanTestPkg("acl", "2.3.0-1", "x86_64", "pgp"), []pacmanSyncEntry{e("2.4.0-1", true, core)}, true, osProvided(true), ChannelOS, ""},
		{"missed update, a third-party repository lists the name too", pacmanTestPkg("acl", "2.3.0-1", "x86_64", "pgp"), []pacmanSyncEntry{e("2.4.0-1", true, core), e("9.9-1", false, vendor)}, true, nil, ChannelUnknown, ""},
		{"missed update, name only in a third-party repository", pacmanTestPkg("hello", "0.9-1", "x86_64", "sha256"), []pacmanSyncEntry{e("1.0-1", false, vendor)}, true, nil, ChannelUnknown, ""},
		{"OS version listed but installed without a signature check", pacmanTestPkg("acl", "2.4.0-1", "x86_64", "none"), []pacmanSyncEntry{e("2.4.0-1", true, core)}, true, nil, ChannelUnknown, ""},
		{"OS version missed an update and installed without a signature check", pacmanTestPkg("acl", "2.3.0-1", "x86_64", "sha256"), []pacmanSyncEntry{e("2.4.0-1", true, core)}, true, nil, ChannelUnknown, ""},
		{"architecture independent package", pacmanTestPkg("base", "3-3", "any", "pgp"), []pacmanSyncEntry{{version: "3-3", arch: "any", osSigned: true, repo: core}}, true, osProvided(true), ChannelOS, "core"},
		{"another architecture is another package", pacmanTestPkg("acl", "2.4.0-1", "x86_64", "pgp"), []pacmanSyncEntry{{version: "2.4.0-1", arch: "aarch64", osSigned: true, repo: core}}, true, osProvided(true), ChannelOS, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Synthetic, except where the name quotes a measured install: the
			// combinations of records were not each shown by a target.
			pkg := tt.pkg
			got := pacmanSource(&pkg, tt.entries, tt.complete)
			assert.Equal(t, tt.wantOS, got.OSProvided)
			assert.Equal(t, tt.wantChan, got.Channel)
			assert.Equal(t, tt.wantSource, got.Name)
		})
	}

	t.Run("the same version built another time is not the listed package", func(t *testing.T) {
		// Synthetic: a repository ahead of core rebuilds acl 2.4.0-1 and signs it with its own key
		pkg := pacmanTestPkg("acl", "2.4.0-1", "x86_64", "pgp")
		pkg.pacmanBuildDate = "1782738989"
		coreEntry := e("2.4.0-1", true, core)
		coreEntry.buildDate = "1700000000"
		got := pacmanSource(&pkg, []pacmanSyncEntry{coreEntry}, true)
		assert.Nil(t, got.OSProvided)
		assert.Equal(t, ChannelUnknown, got.Channel)

		// listed by the rebuilding repository too: that listing is the match
		rebuild := e("2.4.0-1", false, vendor)
		rebuild.buildDate = "1782738989"
		got = pacmanSource(&pkg, []pacmanSyncEntry{coreEntry, rebuild}, true)
		assert.Equal(t, osProvided(false), got.OSProvided)
		assert.Equal(t, "vendor", got.Name)

		// the same build date is the same build
		coreEntry.buildDate = "1782738989"
		got = pacmanSource(&pkg, []pacmanSyncEntry{coreEntry}, true)
		assert.Equal(t, osProvided(true), got.OSProvided)
	})

	t.Run("address", func(t *testing.T) {
		pkg := pacmanTestPkg("acl", "2.4.0-1", "x86_64", "pgp")
		got := pacmanSource(&pkg, []pacmanSyncEntry{e("2.4.0-1", true, core)}, true)
		assert.Equal(t, "https://m.example/core/os/x86_64", got.URL)
	})
}

// pacmanTestFS lays out a host: the sync databases, the keyring package's
// record and keyring file, and pacman.conf.
func pacmanTestFS(t *testing.T, conf string, keyringPkgs map[string]string, dbs map[string][]byte, keyrings map[string][]byte) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	write := func(p string, data []byte) { require.NoError(t, afero.WriteFile(fs, p, data, 0o644)) }
	write("/etc/pacman.conf", []byte(conf))
	write("/etc/pacman.d/mirrorlist", []byte(archMirrorlist))
	for repo, data := range dbs {
		write("/var/lib/pacman/sync/"+repo+".db", data)
	}
	for name, version := range keyringPkgs {
		write("/var/lib/pacman/local/"+name+"-"+version+"/files", []byte("%FILES%\nusr/share/pacman/keyrings/"+name[:strings.Index(name, "-")]+".gpg\nusr/share/pacman/keyrings/"+name[:strings.Index(name, "-")]+"-trusted\nusr/share/pacman/keyrings/"+name[:strings.Index(name, "-")]+"-revoked\n"))
	}
	for p, data := range keyrings {
		write(p, data)
	}
	return fs
}

// End to end on archlinux:latest's layout. The configuration, the signature of
// acl and the keyring's key are Measured (2026-11-27); the vendor repository,
// its packages and the keyring file (reduced to one key) are Synthetic.
func TestPacmanSourcesEndToEnd(t *testing.T) {
	conf := string(readPacmanTestdata(t, "pacman.conf-archlinux-latest.txt")) + "\n[vendor]\nSigLevel = Required\nServer = file:///srv/repo\n"
	core := syncDB(t, map[string]string{"acl-2.4.0-1": string(readPacmanTestdata(t, "sync-desc-core-acl-2.4.0-1.txt"))}, "gz")
	extra := syncDB(t, map[string]string{"zzz-1-1": syntheticDesc("zzz", "1-1", "x86_64", "")}, "gz")
	vendor := syncDB(t, map[string]string{"hello-vendor-1.0-1": syntheticDesc("hello-vendor", "1.0-1", "any", "")}, "gz")
	keyringFile := map[string][]byte{"/usr/share/pacman/keyrings/archlinux.gpg": readPacmanTestdata(t, "archlinux-keyring-packager-key.gpg")}

	pkgs := []Package{
		pacmanTestPkg("archlinux-keyring", "20260909-1", "any", "pgp"),
		pacmanTestPkg("acl", "2.4.0-1", "x86_64", "pgp"),
		pacmanTestPkg("hello-vendor", "1.0-1", "any", "sha256"),
		pacmanTestPkg("hello-direct", "2.0-1", "any", "none"),
	}
	byName := func(srcs []Source) map[string]Source {
		m := map[string]Source{}
		for i := range pkgs {
			m[pkgs[i].Name] = srcs[i]
		}
		return m
	}
	keyringPkgs := map[string]string{"archlinux-keyring": "20260909-1"}

	t.Run("every repository has a database", func(t *testing.T) {
		fs := pacmanTestFS(t, conf, keyringPkgs, map[string][]byte{"core": core, "extra": extra, "vendor": vendor}, keyringFile)
		dbs := readPacmanSyncDBs(newLocalSourceFiles(fs), "arch", pkgs)
		require.True(t, dbs.complete)
		got := byName(pacmanSources(pkgs, dbs))
		assert.Equal(t, Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "core", URL: "https://fastly.mirror.pkgbuild.com/core/os/x86_64"}, got["acl"])
		assert.Equal(t, osProvided(false), got["hello-vendor"].OSProvided)
		assert.Equal(t, ChannelVendorRepository, got["hello-vendor"].Channel)
		assert.Equal(t, "vendor", got["hello-vendor"].Name)
		assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelDirect}, got["hello-direct"])
		// archlinux-keyring itself is in no database of this host
		assert.Equal(t, ChannelDirect, got["archlinux-keyring"].Channel)
	})

	t.Run("a repository without a database", func(t *testing.T) {
		// Measured: archlinux:latest ships no sync database until pacman -Sy
		fs := pacmanTestFS(t, conf, keyringPkgs, map[string][]byte{"core": core, "vendor": vendor}, keyringFile)
		dbs := readPacmanSyncDBs(newLocalSourceFiles(fs), "arch", pkgs)
		require.False(t, dbs.complete)
		got := byName(pacmanSources(pkgs, dbs))
		assert.Equal(t, ChannelOS, got["acl"].Channel, "listed by a database that was read")
		assert.Nil(t, got["hello-direct"].OSProvided, "the missing extra database could list it")
	})

	t.Run("a sync database no repository names", func(t *testing.T) {
		// Synthetic: a repository removed from pacman.conf after its first sync.
		// Measured: manjarolinux/base ships a stale community.db that no
		// repository of its pacman.conf names.
		fs := pacmanTestFS(t, conf, keyringPkgs, map[string][]byte{"core": core, "extra": extra, "vendor": vendor, "removed": vendor}, keyringFile)
		dbs := readPacmanSyncDBs(newLocalSourceFiles(fs), "arch", pkgs)
		require.False(t, dbs.complete)
		got := byName(pacmanSources(pkgs, dbs))
		assert.Nil(t, got["hello-direct"].OSProvided, "it may come from the removed repository")
		assert.Equal(t, ChannelOS, got["acl"].Channel)
	})

	t.Run("a repository added through an Include outside a repository section", func(t *testing.T) {
		// Synthetic
		fs := pacmanTestFS(t, "Include = /etc/pacman.d/extra-repos.conf\n"+conf, keyringPkgs, map[string][]byte{"core": core, "extra": extra, "vendor": vendor}, keyringFile)
		dbs := readPacmanSyncDBs(newLocalSourceFiles(fs), "arch", pkgs)
		assert.False(t, dbs.complete)
	})

	t.Run("a revoked key is not the operating system's", func(t *testing.T) {
		// Measured: archlinux-keyring ships archlinux-revoked, one fingerprint per
		// line. Synthetic: the keyring here holds one key, and the file names it.
		list, err := openpgp.ReadKeyRing(bytes.NewReader(readPacmanTestdata(t, "archlinux-keyring-packager-key.gpg")))
		require.NoError(t, err)
		fp := hexString(list[0].PrimaryKey.Fingerprint)
		kr := map[string][]byte{
			"/usr/share/pacman/keyrings/archlinux.gpg":     readPacmanTestdata(t, "archlinux-keyring-packager-key.gpg"),
			"/usr/share/pacman/keyrings/archlinux-revoked": []byte("0A9DDABB64B993D82AD45E4F32EAB0A976938292\n" + fp + "\n"),
		}
		fs := pacmanTestFS(t, conf, keyringPkgs, map[string][]byte{"core": core, "extra": extra, "vendor": vendor}, kr)
		for _, s := range pacmanSources(pkgs, readPacmanSyncDBs(newLocalSourceFiles(fs), "arch", pkgs)) {
			assert.Nil(t, s.OSProvided, "no key is left to attribute a package to the operating system")
		}

		// a revoked list that names other keys leaves this one trusted
		kr["/usr/share/pacman/keyrings/archlinux-revoked"] = []byte("0A9DDABB64B993D82AD45E4F32EAB0A976938292\n")
		fs = pacmanTestFS(t, conf, keyringPkgs, map[string][]byte{"core": core, "extra": extra, "vendor": vendor}, kr)
		got := byName(pacmanSources(pkgs, readPacmanSyncDBs(newLocalSourceFiles(fs), "arch", pkgs)))
		assert.Equal(t, osProvided(true), got["acl"].OSProvided)
	})

	t.Run("no sync database at all", func(t *testing.T) {
		fs := pacmanTestFS(t, conf, keyringPkgs, nil, keyringFile)
		got := pacmanSources(pkgs, readPacmanSyncDBs(newLocalSourceFiles(fs), "arch", pkgs))
		for _, s := range got {
			assert.Nil(t, s.OSProvided)
			assert.Equal(t, ChannelUnknown, s.Channel)
		}
	})

	t.Run("no keyring package installed", func(t *testing.T) {
		// Synthetic: the keyring package was removed
		fs := pacmanTestFS(t, conf, nil, map[string][]byte{"core": core, "extra": extra, "vendor": vendor}, keyringFile)
		for _, s := range pacmanSources(pkgs, readPacmanSyncDBs(newLocalSourceFiles(fs), "arch", pkgs)) {
			assert.Nil(t, s.OSProvided)
		}
	})

	t.Run("a distribution with no entry", func(t *testing.T) {
		// Synthetic: no image of it was read
		fs := pacmanTestFS(t, conf, keyringPkgs, map[string][]byte{"core": core, "extra": extra, "vendor": vendor}, keyringFile)
		for _, s := range pacmanSources(pkgs, readPacmanSyncDBs(newLocalSourceFiles(fs), "endeavouros", pkgs)) {
			assert.Nil(t, s.OSProvided)
		}
	})

	t.Run("manjaro trusts both keyrings", func(t *testing.T) {
		// Measured: manjarolinux/base installs manjaro-keyring and archlinux-keyring
		// and its core database is signed with keys of both.
		ucode := syncDB(t, map[string]string{"amd-ucode-20260110-1": string(readPacmanTestdata(t, "sync-desc-manjaro-core-amd-ucode-20260110-1.txt"))}, "gz")
		fs := pacmanTestFS(t, string(readPacmanTestdata(t, "pacman.conf-manjaro-base.txt")),
			map[string]string{"archlinux-keyring": "20260206-1", "manjaro-keyring": "20251003-1"},
			map[string][]byte{"core": syncDB(t, map[string]string{"acl-2.4.0-1": string(readPacmanTestdata(t, "sync-desc-core-acl-2.4.0-1.txt"))}, "gz"), "extra": ucode},
			map[string][]byte{
				"/usr/share/pacman/keyrings/archlinux.gpg": readPacmanTestdata(t, "archlinux-keyring-packager-key.gpg"),
				"/usr/share/pacman/keyrings/manjaro.gpg":   readPacmanTestdata(t, "manjaro-keyring-packager-key.gpg"),
			})
		mp := []Package{
			pacmanTestPkg("archlinux-keyring", "20260206-1", "any", "pgp"),
			pacmanTestPkg("manjaro-keyring", "20251003-1", "any", "pgp"),
			pacmanTestPkg("acl", "2.4.0-1", "x86_64", "pgp"),
			pacmanTestPkg("amd-ucode", "20260110-1", "any", "pgp"),
		}
		got := pacmanSources(mp, readPacmanSyncDBs(newLocalSourceFiles(fs), "manjaro", mp))
		assert.Equal(t, osProvided(true), got[2].OSProvided, "signed by an Arch key")
		assert.Equal(t, osProvided(true), got[3].OSProvided, "signed by a Manjaro key")
	})
}

// Synthetic: a %VALIDATION% record with several methods; the measured records
// each had one.
func TestPacmanValidationMethods(t *testing.T) {
	fields := parsePacmanDescSections(strings.NewReader("%NAME%\nx\n\n%VALIDATION%\nsha256\npgp\n\n%ARCH%\nany\n"))
	assert.Equal(t, "sha256\npgp", fields["%VALIDATION%"])
	assert.True(t, pacmanChecked(fields["%VALIDATION%"]), "pgp among the methods is a checked signature")
	assert.True(t, pacmanChecked("pgp"))
	assert.True(t, pacmanChecked(""), "no record says nothing against it")
	assert.False(t, pacmanChecked("none"))
	assert.False(t, pacmanChecked("sha256\nmd5"))
}

// Synthetic: configurations that name repositories the reader did not place.
func TestParsePacmanConfIncomplete(t *testing.T) {
	cfg := parsePacmanConf([]byte("[options]\nInclude = /etc/pacman.d/more.conf\n[core]\nServer = https://m.example/$repo\n"), nil)
	assert.True(t, cfg.incomplete, "an included file can define repositories")

	cfg = parsePacmanConf([]byte("Include = /etc/pacman.d/more.conf\n[core]\nServer = https://m.example/$repo\n"), nil)
	assert.True(t, cfg.incomplete)

	cfg = parsePacmanConf([]byte("[core]\nInclude = /etc/pacman.d/mirrorlist\n"), func(string) []byte { return []byte("Server = https://m.example/$repo\n") })
	assert.False(t, cfg.incomplete, "a mirror list in a repository section is the usual form")

	var conf strings.Builder
	for i := range pacmanMaxRepos + 2 {
		conf.WriteString("[r" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "]\nServer = https://m.example/x\n")
	}
	cfg = parsePacmanConf([]byte(conf.String()), nil)
	assert.True(t, cfg.incomplete)
	assert.Len(t, cfg.repos, pacmanMaxRepos)
}

func TestPacmanArch(t *testing.T) {
	// Synthetic: package lists; the architecture counts are made up
	assert.Equal(t, "x86_64", pacmanArch([]Package{{Arch: "any"}, {Arch: "x86_64"}, {Arch: "x86_64"}, {Arch: "aarch64"}, {}}))
	assert.Empty(t, pacmanArch([]Package{{Arch: "any"}}))
}
