// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures under testdata/source/rpm are taken from real systems:
//
//   - */*.hdr are single package headers as the rpm database stores them,
//     cut out of: an almalinux:9 container with EPEL and Docker's repository
//     added (sqlite), almalinux:8 and amazonlinux:2 as pulled (Berkeley DB),
//     registry.suse.com/bci/bci-base:15.6 (NDB) and photon:5.0 (sqlite).
//   - keys/ are the key files each distribution's key package installs,
//     prefixed with the distribution.
//   - history/ holds dnf4's history from the almalinux:9 container and
//     dnf5's from fedora:44, trimmed to a few packages, and zypper's log
//     from opensuse/leap:15.6.
//   - yumdb/ holds amazonlinux:2 yumdb entries, repos/ .repo files as the
//     repositories' setup instructions wrote them.
const rpmFixtures = "testdata/source/rpm"

func readHeader(t *testing.T, name string) rpmHeader {
	t.Helper()
	data, err := os.ReadFile(path.Join(rpmFixtures, name))
	require.NoError(t, err)
	h, err := parseRpmHeader(data)
	require.NoError(t, err)
	return h
}

// keyFS places a distribution's key files where its key package's header says
// they belong.
func keyFS(t *testing.T, keyPkg rpmHeader, distro string) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	entries, err := os.ReadDir(path.Join(rpmFixtures, "keys"))
	require.NoError(t, err)
	placed := 0
	for _, e := range entries {
		base, ok := strings.CutPrefix(e.Name(), distro+"-")
		if !ok {
			continue
		}
		for _, f := range keyPkg.files {
			if filepath.Base(f) == base {
				data, err := os.ReadFile(path.Join(rpmFixtures, "keys", e.Name()))
				require.NoError(t, err)
				require.NoError(t, afero.WriteFile(fs, f, data, 0o644))
				placed++
			}
		}
	}
	require.NotZero(t, placed, "a key file of %s must be among the files %s installed", distro, keyPkg.name)
	return fs
}

func TestParseRpmHeader(t *testing.T) {
	tree := readHeader(t, "alma9/tree.hdr")
	assert.Equal(t, "tree", tree.name)
	assert.Equal(t, "1.8.0", tree.version)
	assert.Equal(t, "10.el9", tree.release)
	assert.Equal(t, "aarch64", tree.arch)
	assert.Nil(t, tree.epoch, "tree carries no epoch")
	assert.Contains(t, tree.issuers, "D36CB86CB86B3716", "signed by the AlmaLinux 9 key")
	assert.Contains(t, tree.files, "/usr/bin/tree")
	assert.Equal(t, rpmKey("tree", "1.8.0-10.el9", "aarch64"), tree.key())

	docker := readHeader(t, "alma9/docker-ce-cli.hdr")
	require.NotNil(t, docker.epoch)
	assert.Equal(t, rpmKey("docker-ce-cli", "1:29.8.2-1.el9", "aarch64"), docker.key(), "the epoch is part of the version")
	assert.Contains(t, docker.issuers, "C52FEB6B621E9F35", "signed by Docker's key")

	local := readHeader(t, "alma9/acme-agent.hdr")
	assert.Empty(t, local.issuers, "a locally built package is unsigned")

	_, err := parseRpmHeader([]byte{0, 0, 0, 9, 0, 0, 0, 1})
	assert.Error(t, err, "counts that run past the blob")

	// a string array whose count claims four billion entries in a few bytes
	// must not allocate for them
	blob := []byte{
		0, 0, 0, 1, 0, 0, 0, 4, // one entry, four data bytes
		0, 0, 0x04, 0x5d, 0, 0, 0, 8, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, // BASENAMES, STRING_ARRAY, offset 0, count 2^32-1
		'a', 0, 'b', 0,
	}
	h, err := parseRpmHeader(blob)
	require.NoError(t, err)
	assert.Empty(t, h.files)
	_, err = parseRpmHeader(nil)
	assert.Error(t, err)
}

func TestRpmOSKeys(t *testing.T) {
	tests := []struct {
		name, distro, keyPkg string
		signed, other        []string
	}{
		{"almalinux 9", "alma9", "alma9/almalinux-gpg-keys.hdr", []string{"alma9/tree.hdr", "alma9/epel-release.hdr"}, []string{"alma9/docker-ce-cli.hdr", "alma9/acme-agent.hdr"}},
		// 61 of AlmaLinux 8's base packages are signed with a subkey
		{"almalinux 8, signed by a subkey", "alma8", "", []string{"alma8/basesystem.hdr"}, nil},
		{"amazon linux 2, Berkeley DB", "al2", "al2/system-release.hdr", []string{"al2/basesystem.hdr"}, nil},
		{"sles 15.6, NDB", "sles156", "sles156/suse-build-key.hdr", []string{"sles156/libz1.hdr"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var fs afero.Fs
			var headers []rpmHeader
			var pkgs []string
			if tc.keyPkg != "" {
				kp := readHeader(t, tc.keyPkg)
				fs = keyFS(t, kp, tc.distro)
				headers = append(headers, kp)
				pkgs = []string{kp.name}
			} else {
				// almalinux:8 keeps its key in almalinux-release, whose header
				// is not a fixture; place the file the package installs
				fs = afero.NewMemMapFs()
				data, err := os.ReadFile(path.Join(rpmFixtures, "keys", "alma8-RPM-GPG-KEY-AlmaLinux"))
				require.NoError(t, err)
				require.NoError(t, afero.WriteFile(fs, "/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux", data, 0o644))
				headers = append(headers, rpmHeader{name: "almalinux-release", files: []string{"/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux"}})
				pkgs = []string{"almalinux-release"}
			}
			keys, known := rpmOSKeys(newLocalSourceFiles(fs), headers, pkgs)
			require.True(t, known)
			for _, s := range tc.signed {
				assert.True(t, keys.signedBy(readHeader(t, s).issuers), s)
			}
			for _, o := range tc.other {
				assert.False(t, keys.signedBy(readHeader(t, o).issuers), o)
			}
		})
	}

	t.Run("a key package that is not on the list is not trusted", func(t *testing.T) {
		kp := readHeader(t, "alma9/almalinux-gpg-keys.hdr")
		fs := keyFS(t, kp, "alma9")
		_, known := rpmOSKeys(newLocalSourceFiles(fs), []rpmHeader{kp}, []string{"epel-release"})
		assert.False(t, known)
	})
}

func TestRpmSourceGpgPubkey(t *testing.T) {
	kp := readHeader(t, "photon5/photon-repos.hdr")
	fs := keyFS(t, kp, "photon5")
	keys, known := rpmOSKeys(newLocalSourceFiles(fs), []rpmHeader{kp}, []string{"photon-repos"})
	require.True(t, known)

	// Photon names its imported keys by their full fingerprint
	for _, f := range []string{"photon5/gpg-pubkey.hdr", "photon5/gpg-pubkey-2.hdr"} {
		h := readHeader(t, f)
		require.Equal(t, "gpg-pubkey", h.name)
		pkg := Package{Name: h.name, Version: h.version + "-" + h.release, Arch: h.arch, Format: RpmPkgFormat}
		got := rpmSource(&pkg, &h, keys, known, nil, nil)
		require.NotNil(t, got.OSProvided, f)
		assert.True(t, *got.OSProvided, "%s: version %s", f, h.version)
	}
	// AlmaLinux names them by short ID
	assert.True(t, openPGPKeys{"7FCC7D46ACCC4CF8": {}}.hasKeyID("accc4cf8"))
	assert.False(t, openPGPKeys{"7FCC7D46ACCC4CF8": {}}.hasKeyID("0000cf8"))
}

func TestRpmSourceDecisions(t *testing.T) {
	kp := readHeader(t, "alma9/almalinux-gpg-keys.hdr")
	fs := keyFS(t, kp, "alma9")
	keys, known := rpmOSKeys(newLocalSourceFiles(fs), []rpmHeader{kp}, []string{"almalinux-gpg-keys"})
	require.True(t, known)

	history := map[string]string{
		rpmKey("tree", "1.8.0-10.el9", "aarch64"):            "baseos",
		rpmKey("docker-ce-cli", "1:29.8.2-1.el9", "aarch64"): "docker-ce-stable",
		rpmKey("acme-agent", "1.2.3-1", "noarch"):            "@commandline",
	}
	urls := map[string]string{"docker-ce-stable": "https://download.docker.com/linux/rhel/$releasever/$basearch/stable"}

	pkg := func(h rpmHeader) Package {
		return Package{Name: h.name, Version: strings.TrimPrefix(strings.TrimPrefix(h.key(), h.name+"\x00"), ""), Arch: h.arch, Format: RpmPkgFormat}
	}
	run := func(file string, hist map[string]string) Source {
		h := readHeader(t, file)
		p := pkg(h)
		parts := strings.Split(h.key(), "\x00")
		p.Version = parts[1]
		return rpmSource(&p, &h, keys, known, hist, urls)
	}

	assert.Equal(t, Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "baseos"}, run("alma9/tree.hdr", history))
	// an OS package installed with rpm -i has no history, and is still the OS's
	assert.Equal(t, Source{OSProvided: osProvided(true), Channel: ChannelOS}, run("alma9/tree.hdr", nil))
	assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelVendorRepository, Name: "docker-ce-stable", URL: urls["docker-ce-stable"]}, run("alma9/docker-ce-cli.hdr", history))
	assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelDirect}, run("alma9/acme-agent.hdr", history))
	// a third-party package with no history at all came from a file
	assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelDirect}, run("alma9/docker-ce-cli.hdr", nil))

	// without the distribution's keys nothing is decided, the repository is
	// still reported
	h := readHeader(t, "alma9/docker-ce-cli.hdr")
	p := Package{Name: h.name, Version: "1:29.8.2-1.el9", Arch: h.arch, Format: RpmPkgFormat}
	got := rpmSource(&p, &h, openPGPKeys{}, false, history, urls)
	assert.Nil(t, got.OSProvided)
	assert.Equal(t, "docker-ce-stable", got.Name)
}

func TestReportedRepoID(t *testing.T) {
	assert.Equal(t, "baseos", reportedRepoID("baseos"))
	assert.Equal(t, "", reportedRepoID("@commandline"))
	assert.Equal(t, "", reportedRepoID("@System"))
	assert.Equal(t, "", reportedRepoID("_tmpRPMcache_"))
	assert.Equal(t, "", reportedRepoID("/evlocal-1.0-1.noarch"), "yum records a local file as its path")
	// fedora:44's image build repository
	assert.Equal(t, "", reportedRepoID("f6ae26d2709140ec8807dba8ce4e3091"))
	assert.Equal(t, "updates", reportedRepoID("updates"))
}

func TestQueryDnfHistory(t *testing.T) {
	t.Run("dnf4", func(t *testing.T) {
		got, err := queryDnfHistory(path.Join(rpmFixtures, "history", "dnf4-almalinux9-history.sqlite"))
		require.NoError(t, err)
		assert.Equal(t, "baseos", got[rpmKey("bash", "5.1.8-9.el9", "aarch64")])
		assert.Equal(t, "extras", got[rpmKey("epel-release", "9-9.el9", "noarch")])
		assert.Equal(t, "epel", got[rpmKey("htop", "3.3.0-1.el9", "aarch64")])
		assert.Equal(t, "docker-ce-stable", got[rpmKey("docker-ce-cli", "1:29.8.2-1.el9", "aarch64")])
		assert.Equal(t, "@commandline", got[rpmKey("evlocal", "1.0-1", "noarch")])
	})
	t.Run("dnf5", func(t *testing.T) {
		got, err := queryDnfHistory(path.Join(rpmFixtures, "history", "dnf5-fedora44-transaction_history.sqlite"))
		require.NoError(t, err)
		assert.Equal(t, "f6ae26d2709140ec8807dba8ce4e3091", got[rpmKey("bash", "5.3.9-3.fc44", "aarch64")])
		assert.Equal(t, "@commandline", got[rpmKey("evlocal", "1.0-1", "noarch")])
	})
}

func TestParseZyppHistory(t *testing.T) {
	data, err := os.ReadFile(path.Join(rpmFixtures, "history", "zypp-history-leap156"))
	require.NoError(t, err)
	got := parseZyppHistory(data)
	assert.Equal(t, "repo-oss", got[rpmKey("file", "5.32-7.14.1", "aarch64")])
	assert.Equal(t, "repo-sle-update", got[rpmKey("libexpat1", "2.7.1-150400.3.37.1", "aarch64")])
	for k, v := range got {
		assert.NotEmpty(t, v, k)
	}
}

func TestReadYumDB(t *testing.T) {
	fs := afero.NewMemMapFs()
	root := path.Join(rpmFixtures, "yumdb")
	require.NoError(t, filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		return afero.WriteFile(fs, path.Join(yumDBDir, filepath.ToSlash(rel)), data, 0o644)
	}))
	got := readYumDB(fs)
	assert.Equal(t, "amzn2extra-epel", got[rpmKey("epel-release", "7-11", "noarch")])
	assert.Equal(t, "nginx-stable", got[rpmKey("nginx", "1.30.3-1.amzn2.ngx", "aarch64")])
	assert.Equal(t, "/evlocal-1.0-1.noarch", got[rpmKey("evlocal", "1.0-1", "noarch")])

	_, ok := yumDBEntryKey("nodash")
	assert.False(t, ok)
}

func TestParseRepoFile(t *testing.T) {
	data, err := os.ReadFile(path.Join(rpmFixtures, "repos", "docker-ce.repo"))
	require.NoError(t, err)
	got := parseRepoFile(data)
	// the fixture is the repository file Docker publishes for CentOS
	assert.Equal(t, "https://download.docker.com/linux/centos/$releasever/$basearch/stable", got["docker-ce-stable"])

	data, err = os.ReadFile(path.Join(rpmFixtures, "repos", "epel.repo"))
	require.NoError(t, err)
	got = parseRepoFile(data)
	// EPEL ships a metalink, whose query string is dropped
	assert.Equal(t, "https://mirrors.fedoraproject.org/metalink", got["epel"])

	got = parseRepoFile([]byte("[private]\nbaseurl=https://user:secret@repo.example/el9/ https://mirror.example/el9/\n"))
	assert.Equal(t, "https://repo.example/el9", got["private"])
}

func TestParseRpmRemoteHeaders(t *testing.T) {
	// rpm -qa with rpmRemoteQuery on almalinux:9 and amazonlinux:2 (rpm 4.11)
	out := "tree\t(none)\t1.8.0\t10.el9\taarch64\tRSA/SHA256, Wed Mar  9 21:18:07 2022, Key ID d36cb86cb86b3716\t(none)\tRSA/SHA256, Wed Mar  9 21:18:07 2022, Key ID d36cb86cb86b3716\t(none)\n" +
		"docker-ce-cli\t1\t29.8.2\t1.el9\taarch64\tRSA/SHA512, Fri Oct  2 10:00:00 2026, Key ID c52feb6b621e9f35\t(none)\t(none)\t(none)\n" +
		"acme-agent\t(none)\t1.2.3\t1\tnoarch\t(none)\t(none)\t(none)\t(none)\n" +
		"broken line\n"
	got := parseRpmRemoteHeaders(out)
	require.Len(t, got, 3)
	assert.Equal(t, rpmKey("tree", "1.8.0-10.el9", "aarch64"), got[0].key())
	assert.Equal(t, []string{"D36CB86CB86B3716", "D36CB86CB86B3716"}, got[0].issuers)
	assert.Equal(t, rpmKey("docker-ce-cli", "1:29.8.2-1.el9", "aarch64"), got[1].key())
	assert.Empty(t, got[2].issuers)

	assert.Equal(t, "", pgpsigKeyID("(none)"))
	assert.Equal(t, "70AF9E8139DB7C82", pgpsigKeyID("RSA/SHA256, Fri Oct 20 08:56:52 2023, Key ID 70af9e8139db7c82"))
}

func TestParseRpmFileLists(t *testing.T) {
	out := "#almalinux-gpg-keys\n/etc/pki/rpm-gpg\n/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9\npackage almalinux-release is not installed\n"
	assert.Equal(t, map[string][]string{"almalinux-gpg-keys": {"/etc/pki/rpm-gpg", "/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9"}}, parseRpmFileLists(out))
}

func TestSignedByShortID(t *testing.T) {
	keys := openPGPKeys{"D36CB86CB86B3716": {}}
	assert.True(t, keys.signedBy([]string{"B86B3716"}), "older rpm prints the 8-digit ID")
	assert.False(t, keys.signedBy([]string{"0000AAAA"}))
}

func TestParseRpmHistoryRemote(t *testing.T) {
	// what rpmHistoryRemoteCmd printed on almalinux:9 (dnf4), opensuse/leap:15.6
	// (zypper) and amazonlinux:2 (yumdb)
	out := "bash\t0\t5.1.8\t9.el9\taarch64\tbaseos\n" +
		"docker-ce-cli\t1\t29.8.2\t1.el9\taarch64\tdocker-ce-stable\n" +
		"evlocal\t0\t1.0\t1\tnoarch\t@commandline\n" +
		"file\t\t5.32-7.14.1\t\taarch64\trepo-oss\n" +
		"#b2aa0c78f7066a3ab74c9529ef32ba685877fb9a-epel-release-7-11-noarch\tamzn2extra-epel\n" +
		"garbage\n"
	got := parseRpmHistoryRemote(out)
	assert.Equal(t, "baseos", got[rpmKey("bash", "5.1.8-9.el9", "aarch64")])
	assert.Equal(t, "docker-ce-stable", got[rpmKey("docker-ce-cli", "1:29.8.2-1.el9", "aarch64")])
	assert.Equal(t, "@commandline", got[rpmKey("evlocal", "1.0-1", "noarch")])
	assert.Equal(t, "repo-oss", got[rpmKey("file", "5.32-7.14.1", "aarch64")])
	assert.Equal(t, "amzn2extra-epel", got[rpmKey("epel-release", "7-11", "noarch")])
	assert.Len(t, got, 5)
}
